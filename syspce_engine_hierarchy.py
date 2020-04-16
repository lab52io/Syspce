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
				 processes_tree, tree_condition_in, src,
				 detection_rules, detection_macros):

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

		self.processes_tree = processes_tree

		self.tree_condition_in = tree_condition_in
		
		self.alerts_notified = []
		
		self.buckets = BucketSystem()
		
		self.actions_matched = {}
		
		self.total_alerts = 0


	def do_action(self):
		out = Output_()
		for rule in self.detection_rules:
		
			# dictionary used for printing and output matched alerts
			self.actions_matched = {}
			
			with self.tree_condition_in:
				# processing each rule 
				anom_res = self.processRule(rule)
				self.tree_condition_in.notify_all()
			
			if anom_res:
				# presenting the results
				# logfile + eventlog
				out.process_result_hierarchy(anom_res) 

				#sending alerts as a string
				self.send_message(out.format_result_hierarchy(anom_res)) 

				# lets disable already notified actions
				for anomaly in anom_res:
					self.setAlertToAction(anomaly['ProcessChain'], False)
					self.total_alerts += 1

			if not self._running:
				break

		self.terminate()
		log.debug("%s Terminated." % (self.name))

		#return self.total_alerts
		
	def getAnomalyID(self, machine, ruleid, pchain):
		
		anomalyid = machine + str(ruleid)
		for process in pchain:
			anomalyid += process.guid
			
		anomalyid = hashlib.sha1(anomalyid).hexdigest()
		return anomalyid		
		
	def processRule(self, rule):

		res = []
	
		#recorremos cada una de las maquinas
		for machine in self.processes_tree:
		
			#first element to process
			process_list = [self.processes_tree[machine]['nodo_root']]
			
			ntimes_enabled = False
			for event in rule['Content']:
			
				if event.has_key("N") and event.has_key("Seconds"):
				
					ntimes_enabled = True
					for process in process_list:
						pchain = process.getProcessChain()
						bucket_name = self.getAnomalyID(machine, rule['RuleID'],
														pchain)
				
						bucket = self.buckets.getBucket(bucket_name)
						
						if not bucket:
							log.debug("bucket created %s" % bucket_name)
							bucket = self.buckets.createBucket(bucket_name, 
												event["N"],
												event["Seconds"])

				else:
					process_list_tmp = list(process_list)

					process_list = []
					for process in process_list_tmp:
						matchlist = []

						# "c" significa continua buscando en todo el hilo de 
						# procesos una accion de ese tipo. Si no tiene "c" 
						# entonces lo busca en el proceso actual (nodo).

						if 'c' in event.keys()[0]:

							self.search_all_childs_actions(process, 
															event,
															matchlist													
															)
						else:
							self.searchChildActions(process,
															event,
															matchlist)

						process_list += matchlist
					
			# process_list now has all nodes (processes) that mached 
			# filter criteria
			if process_list:

				for process in process_list:
					pchain = process.getProcessChain()
					
					# it has been notified yet?
					anom_id = self.getAnomalyID(machine, rule['RuleID'], pchain)
					
					if anom_id not in self.alerts_notified:	
					
						result = True 
						if ntimes_enabled:
							# True - there are more than "n" actions in 
							#a time period	
							bucket = self.findBucket(process, machine, 
													rule['RuleID'])
													
							if 	bucket.actionExists(
										process.acciones["1"][0]["UtcTime"]):	
								result = False	
	
							else:
								log.debug("Inserted %s in bucket %s" % 
													(rule['RuleID'], 
													bucket.bucket_name))
								result = bucket.insertAction(
											process.acciones["1"][0]["UtcTime"])
												

						if result:
							self.alerts_notified.append(anom_id)
							res.append({'Computer': machine,
										'ProcessChain': pchain,
										'Rulename': rule['Rulename'],
										'RuleID': rule['RuleID']})
										
							self.setAlertToAction(pchain, True)
					else:
						log.debug("Alert already notified %s" % anom_id)
				
		return res	
	
	'''Devuelve un vector con todas las acciones de un tipo (Ej.tipo 3)
	dado un nodo concreto (proceso). 
	'''
	def searchChildActions(self, obj, filter_list, matchlist):
		# Getting all childs from a process
		for child in obj.hijo:
			match = True

			for type_action in filter_list.keys():

				match =  self.checkAction(type_action, child, filter_list)
				if not match:
					break
					
			if match:		
				matchlist.append(child)
				
	def search_all_childs_actions(self, obj, filter_list, matchlist):
		# Getting all childs from a process
		for nodo in obj.hijo:
			match = True
			for type_action in filter_list.keys():  								

				match = self.checkAction(type_action, nodo, filter_list)
				if not match:
					break
					
			if match:
				matchlist.append(nodo)
				
			self.search_all_childs_actions(nodo,filter_list, matchlist)	

	'''Method that checks rule acctions (1,3...) against process acctions
	'''	
	def checkAction(self, type_action, nodo, filter_list): 
		
		#  Acction types could have "c" (continue) and "-" (reverse, not)
		# modifiers let's remove them, Example:
		# {"1c":{"Image":"winword"},"-3":{"Image":"winword"}}
		
		
		t_action = type_action.replace('c','')

		if "-" in type_action:
			t_action = t_action.replace('-','')
			acction_reverse = True
		else:
			acction_reverse = False
			
		if (nodo.acciones[t_action] != []):   

			# Checking all specific acctions from a process
			for acc in nodo.acciones[t_action]:
				# Getting all the filters from a rule
				
				result = True
				
				for filter in filter_list[type_action]:
				
					# Filter property could have "-" modifier as well
					acc_filter = filter.replace('-','')
					if "-" in filter:
						filter_reverse = True		
					else:
						filter_reverse = False
					
					final_reverse = acction_reverse^filter_reverse
					
					# Finally comparing if a rule filter match a process action
					if not (acc.has_key(acc_filter)) or \
								not self.checkFilterMatch( 
											filter_list[type_action][filter], 
											acc[acc_filter], final_reverse):
						
						result =  False
						break
						
				if result:
					if self.actions_matched.has_key(nodo.guid):
						self.actions_matched[nodo.guid].append(acc)
					else:
						self.actions_matched.update({nodo.guid:[acc]})
						
					return True
					
		# Process has no acctions of this type
		else:
			if acction_reverse:
				return True
		
		return False
		
	'''Method that compares if a rule filter match a process acction
	'''
	def checkFilterMatch(self, filter, acction, reverse):
		match = False
		
		if filter in self.detection_macros:
			filter_list =  self.detection_macros[filter]
		else:
			filter_list = [filter]

		for f in filter_list:			
			if f.lower() in acction.lower() or f == "*":
				match = True
				
		if reverse:
			return not match
		else:
			return match
			
	def findBucket(self, process, machine, RuleID):
		while True: # node root
		
			pchain = process.getProcessChain()
			bucket_name = self.getAnomalyID(machine, RuleID, pchain)
			bucket = self.buckets.getBucket(bucket_name)
			
			if bucket:
				return bucket

			if  process.guid == '0':
				break 
				
			process = process.padre
			
		log.error("Bucket not found")
		return False
		
	def setAlertToAction(self, pchain, enable):
		
		for process in pchain:
			if process.guid in self.actions_matched:
				for action in self.actions_matched[process.guid]:
					action['Alert'] = enable

