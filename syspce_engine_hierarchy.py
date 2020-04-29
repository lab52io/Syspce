import logging
import hashlib
from syspce_bucket import Bucket
from syspce_bucket import BucketSystem
from syspce_engine import Engine
from syspce_message import *
from syspce_output import Output_

log = logging.getLogger('sysmoncorrelator')

#----------------------------------------------------------------------------#
# Clase que implementa el engine de deteccion                                #
#----------------------------------------------------------------------------#


class HierarchyEngine(Engine):
	def __init__(self, data_buffer_in, data_condition_in,
				 processes_tree, src, detection_rules,
				 detection_macros):

		# Detection rules vector
		# Process search is based on  "contains" filter and case insensitive.
		# Example: cmd.exe matches Image:"c:\Windows\System32\CMD.exe"

		Engine.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		self.name = 'Hierarchy Engine'

		self.module_id = Module.HIERARCHY_ENGINE

		self.detection_rules = detection_rules
		
		self.detection_macros = detection_macros

		self.p_tree = processes_tree

		self.process_tree = self.p_tree.processes_tree

		self.p_tree.set_macros(self.detection_macros)

		self.alerts_notified = []
		
		self.buckets = BucketSystem()
		
		self.total_alerts = 0


	def do_action(self):
		out = Output_()
		for rule in self.detection_rules:
		
			# dictionary used for printing and output matched alerts
			
			
			with self.p_tree.tree_condition_in:
				log.debug("%s Running..." % (self.name))

				# processing each rule 
				anom_res = self._process_rule(rule)
				self.p_tree.tree_condition_in.notify_all()
			
			if anom_res:
				# presenting the results
				# logfile + eventlog
				out.process_result_hierarchy(anom_res) 

				#sending alerts as a string
				self.send_message(out.format_result_hierarchy(anom_res)) 

				# lets disable already notified actions
				for anomaly in anom_res:
					self.p_tree.setAlertToAction(anomaly['ProcessChain'], False)
					self.total_alerts += 1

			if not self._running:
				break

		self.terminate()
		log.debug("%s Terminated." % (self.name))

	def _process_rule(self, rule):

		res = []
	
		#recorremos cada una de las maquinas
		for machine in self.p_tree.processes_tree:
			ptree = self.p_tree.processes_tree[machine]

			#first element to process
			new_candidates = ptree.keys()
			
			ntimes_enabled = False
			'''
			"Content": [
					{ "1c": { "Image": "explorer.exe" } , "3c": { "Image": "explorer.exe" }},
					{ "8c": { "Image": "*" } }
					]
			'''
			process_list = []
			for i, filter_dicc in enumerate(rule['Content']):

				if filter_dicc.has_key("N") and filter_dicc.has_key("Seconds"):
				
					ntimes_enabled = True
	
					for process in process_list:
						pchain = self.get_process_chain(process, machine)
						bucket_name = self.get_anomaly_id(machine, rule['RuleID'],
														pchain)
				
						bucket = self.buckets.getBucket(bucket_name)
						
						if not bucket:
							log.debug("bucket created %s" % bucket_name)
							bucket = self.buckets.createBucket(bucket_name, 
												filter_dicc["N"],
												filter_dicc["Seconds"])

				else:
					# not first filter line
					if i:
						if 'c' in filter_dicc.keys()[0]:
							new_candidates = []
							self.p_tree.get_all_childs(ptree, process_list, new_candidates)
						else:
							new_candidates = self.p_tree.get_direct_childs(ptree, process_list)

					process_list = self.p_tree.get_candidates(ptree, new_candidates, filter_dicc)

			# process_list now has all nodes (processes) that mached 
			# filter criteria
			if process_list:

				for process in process_list:
					pchain = self.get_process_chain(process, machine)

					pnode =  ptree[process]

					# it has been notified yet?
					anom_id = self.get_anomaly_id(machine, rule['RuleID'], pchain)
					
					if anom_id not in self.alerts_notified:	
					
						result = True 
						if ntimes_enabled:
							# True - there are more than "n" actions in 
							#a time period	
							bucket = self.find_bucket(pnode, machine, 
													rule['RuleID'])
													
							if 	bucket.actionExists(
										pnode.acciones["1"][0]["UtcTime"]):	
								result = False	
	
							else:
								log.debug("Inserted %s in bucket %s" % 
													(rule['RuleID'], 
													bucket.bucket_name))
								result = bucket.insertAction(
											pnode.acciones["1"][0]["UtcTime"])
												

						if result:
							self.alerts_notified.append(anom_id)
							res.append({'Computer': machine,
										'ProcessChain': pchain,
										'Rulename': rule['Rulename'],
										'RuleID': rule['RuleID']})
										
							self.p_tree.setAlertToAction(pchain, True)
					else:
						log.debug("Alert already notified %s" % anom_id)
				
		return res	

	def get_process_chain(self, src_process_guid, machine):
		pchain = []

		while True:
			pnode = self.p_tree.processes_tree[machine][src_process_guid]
			pchain.append(pnode)

			if not self.p_tree.processes_tree[machine].has_key(pnode.ParentProcessGuid):
				break
			else:
				src_process_guid = pnode.ParentProcessGuid

		return pchain
	def get_anomaly_id(self, machine, ruleid, pchain):
		
		anomalyid = machine + str(ruleid)
		for process in pchain:
			anomalyid += process.guid
			
		anomalyid = hashlib.sha1(anomalyid).hexdigest()
		return anomalyid		
		
			
	def find_bucket(self, process, machine, RuleID):
		while True: # node root
		
			pchain = self.get_process_chain(process.guid, machine)
			bucket_name = self.get_anomaly_id(machine, RuleID, pchain)
			bucket = self.buckets.getBucket(bucket_name)
			
			if bucket:
				return bucket

			if not self.process_tree[machine].has_key(process.ParentProcessGuid):
				break 
				
			process = self.process_tree[machine][process.ParentProcessGuid]
			
		log.error("Bucket not found")
		return False
		
