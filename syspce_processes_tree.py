import logging
import threading
import datetime
import hashlib
import re

from syspce_parser import get_image_fileName

log = logging.getLogger('sysmoncorrelator')


class ProcessesTree(object):

	def __init__(self):
		self.processes_tree = {}
		self.tree_condition_in = threading.Condition()
		self.detection_macros = []
		self.actions_matched = {}
		self.alerts_notified = []
		self.stats = {}

	def set_macros(self, detection_macros):
		self.detection_macros = detection_macros

	def get_syspce_id(self, guid, pid, Image):
		'''This method is used for calculate new correlation id, 
		providing volatility compatibility. Sysmon 11 adds 
		random generation for 8-12 bytes of ProcessGuid,
		token ID isn't used anymore :(.
		'''
		trunk_guid = re.match(r"\{(\w{8}-\w{4}-\w{4}-)", guid)
		trunk_guid = trunk_guid.group(1)

		return hashlib.md5(trunk_guid + pid + Image.lower()).hexdigest()

	def pre_process_events(self, events_list):
		'''Method for adding more info to Sysmon events'''

		i = 0
		while i < len(events_list):

			# Checking if correct information is provided
			if not 'idEvent' in events_list[i]:
				events_list.pop(i)

			# Adding new atribute alert to all actions, used later for presenting
			#results
			events_list[i]['Alert'] = False
			
			# Volatility input has 'Source': 'Memory' key
			# and processGUI is in md5 format
			
			if not events_list[i].has_key('Source'):

				#Changing ProcessGUID algorithm due to correlation with volatility
				if events_list[i].has_key('ProcessId'):
					events_list[i]['ProcessGuidOrig'] = \
									events_list[i]['ProcessGuid']

					events_list[i]['ProcessGuid'] = self.get_syspce_id(
													events_list[i]['ProcessGuid'],
													events_list[i]['ProcessId'],
													events_list[i]['Image'])

				# we do the same for event 100 with childProcessId
			
				if events_list[i].has_key('ChildProcessId'):
					events_list[i]['ChildProcessGuidOrig'] = \
									events_list[i]['ChildProcessGuid']

					events_list[i]['ChildProcessGuid'] = \
									self.get_syspce_id(
										 events_list[i]['ChildProcessGuid'],
										 events_list[i]['ChildProcessId'],
										 events_list[i]['ChildImage'])

				# we do the same for event 110 with childProcessId
			
				if events_list[i].has_key('SourceProcessId'):
					events_list[i]['SourceProcessGuidOrig'] = \
									events_list[i]['SourceProcessGuid']

					events_list[i]['SourceProcessGuid'] = \
									self.get_syspce_id(
										 events_list[i]['SourceProcessGuid'],
										 events_list[i]['SourceProcessId'],
										 events_list[i]['SourceImage'])	

				# we do the same for event 110 with childProcessId
			
				if events_list[i].has_key('TargetProcessId'):
					events_list[i]['TargetProcessGuidOrig'] = \
									events_list[i]['TargetProcessGuid']

					events_list[i]['TargetProcessGuid'] = \
									self.get_syspce_id(
										 events_list[i]['TargetProcessGuid'],
										 events_list[i]['TargetProcessId'],
										 events_list[i]['TargetImage'])

				# we do the same for parent process guid
				if events_list[i].has_key('ParentProcessId'):
					events_list[i]['ParentProcessGuidOrig'] = \
										 events_list[i]['ParentProcessGuid']

					events_list[i]['ParentProcessGuid'] = self.get_syspce_id(
										 events_list[i]['ParentProcessGuid'],
										 events_list[i]['ParentProcessId'],
										 events_list[i]['ParentImage'])


			#else:
			#	print "Image:" + events_list[i]['Image']
			#	print "Pid:" + events_list[i]['ProcessId']

			#Adding new attributes to EventID 1
			if events_list[i]['idEvent'] == 1: 

				ParentImage	= events_list[i]['ParentImage']		
				ParentProcessId	= events_list[i]['ParentProcessId']	

				# Adding 2 new attribites to Event id 1
				# CreationType: [RegularThread, InjectedThread] 
				# 	(see update_process_creation_origin) and
				# RealParent: real parent process which created current process
			
				parent = "(" + ParentProcessId + ") " + ParentImage
				c_origin = {"CreationType":"RegularThread", "RealParent":parent}	
				events_list[i].update(c_origin)	
			
				# Adding new attribute process TTL
				process_ttl = {"ProcessTTL": "Running"}	
				events_list[i].update(process_ttl)

				# Adding new attribute LogonTime
				lt = self.get_logontime(events_list[i]['LogonGuid'])
				LogonTime = {"LogonTime": str(lt)}	
				events_list[i].update(LogonTime)

			i += 1

		return events_list

	def get_logontime(self, processGuid):
		''' Returns user logontime from ProcessGUID'''
		try:
			aux = processGuid.split('-')
			hex_lt = '0x' + aux[2] + aux[1]
			logontime = datetime.datetime.fromtimestamp(int(hex_lt, 16))
		except:
			logontime = None

		return logontime

	def add_event_to_tree(self, req):
		''' Adds one event to processes tree'''	
		
		node = None
		host_name = req['computer']
		ProcessGuid = req['ProcessGuid']
		EventId = str(req['idEvent'])

		if not host_name in self.processes_tree:
			self.processes_tree[host_name] = {}
			self.stats[host_name] = {'Actions':{'1':0, '2':0, '3':0, '5':0,'7':0,
									 '8':0,'9':0,'10':0,'11':0,'12':0,
									 '13':0,'14':0,'15':0,'17':0,'18':0,
									 '22':0,'23':0,'100':0,'108':0,'110':0},
									 'MergedProcesses': 0,
									 'DroppedEvents': 0,
									 'TotalEvents': 0,
									 'TotalEnginesOn': 0,
									 'RulesExecTime':{}
									 }

		computer_ptree = self.processes_tree[host_name]
		
		#Updating Stats

		if self.stats[host_name]['Actions'].has_key(EventId):
			self.stats[host_name]['Actions'][EventId] += 1

		self.stats[host_name]['TotalEvents'] += 1

		# Now processin message type 1 or other type 3,5...
		# Message type 1 , used for building tree's skeleton 
		if req['idEvent'] == 1: 

			# Process node already in tree
			if computer_ptree.has_key(ProcessGuid):
				node = computer_ptree[ProcessGuid]
				#print "Original"
				#print node.acciones['1'][0]
				# node found , just update
				
				#print "Machacado"
				#print req
				
				# Volatility input has 'Source': 'Memory' key, 
				# evtx don't have it
				# Collision dont update
				if (not node.acciones['1'][0].has_key('Source') and \
				   not req.has_key('Source')) or \
				   (node.acciones['1'][0].has_key('Source') and \
				   req.has_key('Source')):

					self.stats[host_name]['DroppedEvents'] += 1
				else:
					self.stats[host_name]['MergedProcesses'] += 1

					#print "CUADRAN origin"
					#print node.acciones['1'][0]

					#print "CUADRAN memoria"
					#print req
					#print "\n"

					# Update only new atributes, not all of them, let's
					# keep untouched sysmon ones
					for attr in req:
						if not node.acciones['1'][0].has_key(attr):
							node.acciones['1'][0][attr] = req[attr]

			# new entry
			else:
				#if req.has_key('Source'):
				#	print "NOOOO CUADRA"
				#	print req
				#	print "\n"
				# Tree Node with process datails
				node = Node_(req)
				node.acciones['1'].append(req)

			#Adding node to tree
			computer_ptree[ProcessGuid] = node

		# Es otra accion diferente a la creacion de un proceso
		else:

			if (not host_name in self.processes_tree):
				return node
	
			# Adding now normal proccess action if exists
			if req['ProcessGuid'] in computer_ptree:				
				node = computer_ptree[req['ProcessGuid']]

				# Adding additional information regarding target 
				if req['idEvent'] == 8 or req['idEvent'] == 10:

					if computer_ptree.has_key(req['TargetProcessGuid']):
						tnode = computer_ptree[req['TargetProcessGuid']]

						req['TargetSession'] = tnode.acciones['1'][0]['TerminalSessionId']
						req['TargetIntegrityLevel'] = tnode.acciones['1'][0]['IntegrityLevel']
						req['TargetUser'] = tnode.acciones['1'][0]['User']
										
					# if tnode dosen't exists we don't include new attribites
						
				# Adding additional information regarding source 
				if req['idEvent'] == 108 or req['idEvent'] == 110:

					if computer_ptree.has_key(req['SourceProcessGuid']):
						snode = computer_ptree[req['SourceProcessGuid']]
						req['SourceSession'] = \
									snode.acciones['1'][0]['TerminalSessionId']
						req['SourceIntegrityLevel'] = \
									snode.acciones['1'][0]['IntegrityLevel']
						req['SourceUser'] = \
									snode.acciones['1'][0]['User']
										
					# if snode dosen't exists we don't include new attribites
				eventid = str(req['idEvent'])
				node.acciones[eventid].append(req)
										
				# 2 types: regular or by remote injected thread
				node.update_process_creation_origin(req, computer_ptree)					

				#If it's a Terminate proccess (5) event let's calculate TTL
				if req['idEvent'] == 5:
					process_ttl = {"ProcessTTL": str(node.getLiveTime())}	
					node.acciones['5'][0].update(process_ttl)	
					node.acciones['1'][0].update(process_ttl)


		return node

	def get_node_by_syspceid(self, computer_ptree, SyspceId):

		for pnode in computer_ptree:
			if pnode.acciones['1'][0]['SyspceId'] == SyspceId:
				return pnode
		return None


	def get_candidates(self, ptree, process_list, filter_dicc):
		''' Return a proccesses that match event criteria'''

		matchlist = []

		for process in process_list:
			match = True

			for type_action in filter_dicc.keys():
				match =  self._check_action(type_action, ptree[process], filter_dicc)
				if not match:
					break
					
			if match:		
				matchlist.append(process)

		return matchlist


	def get_direct_childs(self, ptree, process_list):
		''' Return a proccesses that match event criteria'''

		plist = []

		for process_guid in process_list:
			plist += self._get_childs(ptree, process_guid)

		return plist

	def _get_childs(self, ptree, process_guid):
		childs_list = []

		for child_reg in ptree[process_guid].childs:
			childs_list.append(child_reg['ChildProcessGuid'])

		return childs_list

	def get_all_childs(self, ptree, process_list, res_list):
		''' Return a proccesses that match event criteria'''

		for process_guid in process_list:
			process_list = self._get_childs(ptree, process_guid)
			res_list += process_list
			self.get_all_childs(ptree,process_list, res_list)
		

	def _check_action(self, type_action, nodo, filter_list): 

		'''Method that checks rule acctions (1,3...) against process acctions
		'''			
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
								not self._check_filter_match( 
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
	def _check_filter_match(self, filter, acction, reverse):
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

	def setAlertToAction(self, pchain, enable):
		
		for process in pchain:
			if process.guid in self.actions_matched:
				for action in self.actions_matched[process.guid]:
					action['Alert'] = enable

	def get_node_by_guid(self, computer, process_guid):
		if self.processes_tree[computer].has_key(process_guid):
			return self.processes_tree[computer][process_guid]
		else:
			return None



class Node_(object):
	def __init__(self, req):

		# pid de sysmon id 1
		self.pid = req['ProcessId']
		
		# command line de sysmon id 1
		self.cmd = req['CommandLine']
	
		# uniq process id
		self.guid = req['ProcessGuid']

		# uniq pprocess id
		self.ParentProcessGuid = req['ParentProcessGuid']

		# process image
		self.ImageFileName = get_image_fileName(req['Image'])
		

		#diccionario donde para cada accion (conexion , modificacion registro..)
		# se guarda un listado de las mismas
		self.acciones = {'1':[],'2':[], '3':[], '5':[],'7':[],
						'8':[],'9':[],'10':[],'11':[],
						'12':[],'13':[],'14':[],'15':[],
						'17':[],'18':[],'22':[],'23':[],'100':[],
						'101':[],'108':[],'110':[]}

		#key ChildProcessGuid
		self.childs = self.acciones['100']

		# BASELINE Engine Attributes
		# baseline process points
		self.points = 100
		
		# baseline result suspicious actions
		self.suspicious_actions = []
		
		# baseline already notified
		self.notified = False

	def __str__(self):
		return "[" + str(self.pid) +"] "  + self.cmd

	def getCreationTime(self):
		try:
			c_time = self.acciones["1"][0]["UtcTime"]
			
			#UtcTime: 2020-01-13 07:51:59.575
			c_time = datetime.datetime.strptime(c_time, '%Y-%m-%d %H:%M:%S.%f') 
		except:
			c_time = False
			
		return c_time
		
	def getTerminationTime(self):
		try:
			t_time = self.acciones["5"][0]["UtcTime"]
			t_time = datetime.datetime.strptime(t_time, '%Y-%m-%d %H:%M:%S.%f')
		except:
			t_time = False
			
		return t_time	
	
	def getLiveTime(self):
		
		c_time = self.getCreationTime()
		t_time = self.getTerminationTime()
		
		if c_time and t_time:
			l_time = t_time - c_time
			return l_time
		else:
			return False


	def update_process_creation_origin(self, req, computer_ptree):
		'''
			Method for detecting if a thread has been created by other process
			(not parent) using remote injection technics. "Realparent" records
			the injector process. We need 3 kinds of event id for detecting 
			real parent: CreateRemoteThread 8 (108), Openprocess 10 and
			processcreate 1 (100). When a process is created (1) normally we'll 
			find an OpenProcess (10) event with the souce thread registered.
			Would be greate to have it at ID 1 Mark!!
		'''
		# let's check if parent process has injected thread first
		if self.acciones['100'] != [] and self.acciones['108'] != [] \
										and req['idEvent'] == 10:
			for action108 in self.acciones['108']:
				if action108["NewThreadId"] == req["ThreadId"]:

					for child in self.acciones['100']:
						node = computer_ptree[child["ChildProcessGuid"]]

						if node.acciones["1"][0]["ProcessGuid"] == \
						   req["TargetProcessGuid"] and \
						   "unknown" in req["CallTrace"].lower() and \
						   req["GrantedAccess"].lower() == '0x1fffff':
						
							parent = "(" + action108["SourceProcessId"] + \
										") " + action108["SourceImage"]
										
							c_origin = {"CreationType":"InjectedThread",\
										"RealParent":parent}
											
							node.acciones["1"][0].update(c_origin)

	'''Baseline related methods
	'''
	def add_suspicious_action(self, s_action):
		for action in s_action:
			self.suspicious_actions.append(action)
	
	def subtract_points(self, s_points):
			self.points -= s_points
	
	def get_suspicious_actions(self):
		return self.suspicious_actions + [{'PointsLeft': self.points}]
		
	def setNotified(self):
		self.notified = True
