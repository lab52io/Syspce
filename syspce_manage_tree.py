import logging

from syspce_info_tree import InfoTree
from syspce_message import *
from syspce_parser import get_image_fileName

log = logging.getLogger('sysmoncorrelator')

class ManageTree(InfoTree):

	def __init__(self, data_buffer_in,
				 data_condition_in, 
				 processes_tree,
				 tree_condition_in,
				 src):

		InfoTree.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		self.processes_tree = processes_tree
		self.tree_condition_in = tree_condition_in

		self.name = 'Manage Tree'
		self.module_id = Module.MANAGE_TREE


	def add_events_to_tree(self, list_of_events):

		with self.tree_condition_in:
			log.debug("%s %s Running with %d events ..." % (self.name, self.ident, len(list_of_events)))
			i=0
			for event in list_of_events:
				node = self.add_event_to_tree(event)
				if node:
					i+=1
				if not self._running:
					break			
			self.tree_condition_in.notify_all()



		log.debug("Added %d all events to processes tree" % i)

		self.send_message("Added %d all events to processes tree" % i)
		#self.print_tree(self.processes_tree['localhost']['nodo_root'])
		log.debug("Added all events to processes tree")
		log.debug("%s %s terminated." % (self.name, self.ident))
		exit(0)
	
	####################NUEVOOOOOOOOOOOOOOOOO
	#Testing new algorithm
	def add_event_to_tree_(self, req):
		# Checking if correct information is provided
		if not 'idEvent' in req:
			return None
			
		node = None
		
		# Adding new atribute alert to all actions, used later for presenting
		#results
		req['Alert'] = False

		if not req['computer'] in self.processes_tree:
			self.processes_tree[req['computer']] = {}

		computer_ptree = self.processes_tree[req['computer']]
		ProcessGuid = req['ProcessGuid']

		# Now processin message type 1 or other type 3,5...
		# Message type 1 , used for building tree's skeleton 
		if req['idEvent'] == 1: 
			
			ParentImage	= req['ParentImage']		
			ParentProcessId	= req['ParentProcessId']	

			# Adding 2 new attribites to Event id 1
			# CreationType: [RegularThread, InjectedThread] 
			# 	(see update_process_creation_origin) and
			# RealParent: real parent process which created current process
			
			parent = "(" + ParentProcessId + ") " + ParentImage
			c_origin = {"CreationType":"RegularThread", "RealParent":parent}	
			req.update(c_origin)	
			
			# Adding new attribute process TTL
			process_ttl = {"ProcessTTL": "Running"}	
			req.update(process_ttl)

			# Tree Node with process datails
			node = Node_(req)

			#Lo asignamos a la root de ese equipo ya que no existia con 
			#anterioridad el host
			node.acciones['1'].append(req)
			computer_ptree[ProcessGuid] = node
	



		# Es otra accion diferente a la creacion de un proceso
		else:

			if (not req['computer'] in self.processes_tree):
				return node
	
			# Adding now normal proccess action if exists
			if req['ProcessGuid'] in computer_ptree:				

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
						snode = self.processes_tree[req['computer']][req['SourceProcessGuid']]
						req['SourceSession'] = \
									snode.acciones['1'][0]['TerminalSessionId']
						req['SourceIntegrityLevel'] = \
									snode.acciones['1'][0]['IntegrityLevel']
						req['SourceUser'] = \
									snode.acciones['1'][0]['User']
										
					# if snode dosen't exists we don't include new attribites
				eventid = str(req['idEvent'])
				computer_ptree[req['ProcessGuid']].acciones[eventid].append(req)
										
				# 2 types: regular or by remote injected thread POR IMPLEMENTAR!!!
				#node.update_process_creation_origin(req)					

				#If it's a Terminate proccess (5) event let's calculate TTL
				if req['idEvent'] == 5:
					process_ttl = {"ProcessTTL": str(node.getLiveTime())}	
					computer_ptree[ProcessGuid].acciones['5'][0].update(process_ttl)	
					computer_ptree[ProcessGuid].acciones['1'][0].update(process_ttl)

				return computer_ptree[ProcessGuid]

		return node

	def add_event_to_tree(self, req):

		# Checking if correct information is provided
		if not 'idEvent' in req:
			return None
			
		node = None
		
		# Adding new atribute alert to all actions, used later for presenting
		#results
		req['Alert'] = False
		
		# Now processin message type 1 or other type 3,5...
		# Message type 1 , used for building tree's skeleton 
		if req['idEvent'] == 1: 
		
			ParentProcessGuid = req['ParentProcessGuid']		
			ProcessGuid = req['ProcessGuid']
			processId = req['ProcessId']
			pprocessId = req['ParentProcessId']
			commandline = req['CommandLine']
			Image = req['Image']
						
			# Tree Node with process datails
			node = Node(processId, commandline, ProcessGuid, Image)
			'''
			log.debug("Adding new process to the processtree PID %s: %s" % \
						(node.pid, node.ImageFileName))
			'''
			#Lo asignamos a la root de ese equipo ya que no existia con 
			#anterioridad el host
			if not req['computer'] in self.processes_tree:
				#Creamos nodo root sin datos para esa maquina
				self.processes_tree[req['computer']] = {
									'nodo_root':Node(0, 'root', '0', 'c:\\root'),
									'process_list':[],
									'total_processes': 0,
									'total_connections': 0}
										
				#Anyadimos el primer hijo al nodo root de procesos
				self.processes_tree[req['computer']]['nodo_root'].add_child(node)
				
				#Incluimos en la lista de procesos el nuevo
				self.processes_tree[req['computer']]['process_list'].append(ProcessGuid)
				self.processes_tree[req['computer']]['total_processes'] += 1
			else:
				#Si el proceso padre existe le buscamos el padre para incluirlo
				#como su hijo
				if ParentProcessGuid in self.processes_tree[req['computer']]['process_list']:

					self.processes_tree[req['computer']]['nodo_root'].add_pid(node, 
															ParentProcessGuid)
					
					self.processes_tree[req['computer']]['process_list'].append(ProcessGuid)
					'''
					log.debug("Process added to parent: %s parent %s" %\
															(node.ImageFileName,
															node.padre.pid))
					'''
				#Si no existe entonces al nodo root
				else:
					self.processes_tree[req['computer']]['process_list'].append(ProcessGuid)
					self.processes_tree[req['computer']]['nodo_root'].add_child(node)
					'''
					log.debug("Process added to root node: %s parent %s" %\
															(node.ImageFileName,
															node.padre.pid))
					'''
				#finalmente incrementamos el contador de procesos	
				self.processes_tree[req['computer']]['total_processes'] += 1

			
			# Adding 2 new attribites to Event id 1
			# CreationType: [RegularThread, InjectedThread] 
			# 	(see update_process_creation_origin) and
			# RealParent: real parent process which created current process
			
			parent = "(" + str(node.padre.pid) + \
											") " + node.padre.ImageFileName
										
			c_origin = {"CreationType":"RegularThread",\
										"RealParent":parent}	
			req.update(c_origin)	
			
			# Adding new attribute process TTL
			process_ttl = {"ProcessTTL": "Running"}	
			req.update(process_ttl)
			
			
			#anydimos la propia creacion de proceso como accion asociada
			self.processes_tree[req['computer']]['nodo_root'].add_accion(
										self.processes_tree[req['computer']]['nodo_root'],
										req, str(req['idEvent'])
										)

		# Es otra accion diferente a la creacion de un proceso
		else:

			if (not req['computer'] in self.processes_tree):
				return node
	
			# Adding now normal proccess action if exists
			if req['ProcessGuid'] in self.processes_tree[req['computer']]['process_list']:				

				# Adding additional information regarding target 
				if req['idEvent'] == 8 or req['idEvent'] == 10:
					tnode = \
						self.processes_tree[req['computer']]['nodo_root'].get_node_by_guid(\
													req['TargetProcessGuid'])
						
					if tnode:
						req['TargetSession'] = \
									tnode.acciones['1'][0]['TerminalSessionId']
						req['TargetIntegrityLevel'] = \
									tnode.acciones['1'][0]['IntegrityLevel']
						req['TargetUser'] = \
									tnode.acciones['1'][0]['User']
										
					# if tnode dosen't exists we don't include new attribites
						
				# Adding additional information regarding source 
				if req['idEvent'] == 108 or req['idEvent'] == 110:
					snode = \
						self.processes_tree[req['computer']]['nodo_root'].get_node_by_guid(\
													req['SourceProcessGuid'])
					if snode:
						req['SourceSession'] = \
									snode.acciones['1'][0]['TerminalSessionId']
						req['SourceIntegrityLevel'] = \
									snode.acciones['1'][0]['IntegrityLevel']
						req['SourceUser'] = \
									snode.acciones['1'][0]['User']
										
					# if snode dosen't exists we don't include new attribites
								
				node = self.processes_tree[req['computer']]['nodo_root'].add_accion(
										self.processes_tree[req['computer']]['nodo_root'],
										req, str(req['idEvent'])
										)
										
				# 2 types: regular or by remote injected thread
				node.update_process_creation_origin(req)					

				#If it's a Terminate proccess (5) event let's calculate TTL
				if req['idEvent'] == 5:
					process_ttl = {"ProcessTTL": str(node.getLiveTime())}	
					node.acciones['5'][0].update(process_ttl)	
					node.acciones['1'][0].update(process_ttl)

			# Updating computer connexions counter
			if req['idEvent'] == 3:
				self.processes_tree[req['computer']]['total_connections'] += 1			
		return node

		
	def print_tree(self, init_node):
		try:
			print ("[PID %s] [PPID %s] %s") % (init_node.acciones['1'][0]['ProcessId'],
											   init_node.acciones['1'][0]['ParentProcessId'],
											   init_node.acciones['1'][0]['CommandLine'])
		except Exception, e:
			print str(e)

		for hijo in init_node.hijo:
			self.print_tree(hijo)



class Node(object):
	def __init__(self, pid, cmd, guid, image):
		# pid de sysmon id 1
		self.pid = pid
		
		# command line de sysmon id 1
		self.cmd = cmd
		
		# uniq process id
		self.guid = guid

		# process image
		self.ImageFileName = get_image_fileName(image)
		

		#vector de procesos hijo PIDs
		self.hijo = []
		
		#diccionario donde para cada accion (conexion , modificacion registro..)
		# se guarda un listado de las mismas
		self.acciones = {'1':[],'2':[], '3':[], '5':[],'7':[],
						'8':[],'9':[],'10':[],'11':[],
						'12':[],'13':[],'14':[],'15':[],
						'17':[],'18':[],'22':[],'100':[],'108':[],'110':[]}
		
		#el padre del nodo actual
		self.padre = None
		
		# BASELINE Engine Attributes
		# baseline process points
		self.points = 100
		
		# baseline result suspicious actions
		self.suspicious_actions = []
		
		# baseline already notified
		self.notified = False
		
	def __str__(self):
		return "[" + str(self.pid) +"] "  + self.cmd

	def add_child(self, obj):
		#anyado el hijo
		obj.padre = self
		self.hijo.append(obj)

	''' Metodo que dado un pid busca su proceso padree para anyadirlo al arbol
	como hijo
	'''
	def add_pid(self, node, pguid):
		if (self.guid == pguid):
			self.add_child(node)
		else:
			for child in self.hijo:
				child.add_pid(node, pguid)

	'''Metodo para anyadir  los detalles de una accion a un proceso.
	Se guarda en un diccionario donde cada clave es el tipode la accion y el
	valor es un vector con los detalles de cada accion (otro dicc)
	'''		
	def add_detalles_accion(self, det, tipo):
		self.acciones[tipo].append(det)
	
				
	''' Metodo que registra una accion en el proceso que la ha realizado. Se 
	basa en el pid.
	'''
	def add_accion(self, obj, accion_detalles, tipo_accion):
		if (accion_detalles['ProcessGuid'] == obj.guid):
			obj.add_detalles_accion(accion_detalles, tipo_accion)
			return obj
		else:
			for nodo in obj.hijo:
				pnode = self.add_accion(nodo, accion_detalles, tipo_accion)
				if pnode:
					return pnode

	''' Devuelve un nodo dado un GUID.
	'''
	def get_node_by_guid(self, guid):
		if (self.guid == guid):
			return self
		else:
			for nodo in self.hijo:
				pnode = nodo.get_node_by_guid(guid)
				if pnode:
					return pnode

	def getNumChilds(self):
		return len(self.hijo)
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
	
	'''
		Method for detecting if a thread has been created by other process
		(not parent) using remote injection technics. "Realparent" records
		the injector process. We need 3 kinds of event id for detecting 
		real parent: CreateRemoteThread 8 (108), Openprocess 10 and
		processcreate 1 (100). When a process is created (1) normally we'll 
		find an OpenProcess (10) event with the souce thread registered.
		Would be grate to have it at ID 1 Mark!!
	'''
	def update_process_creation_origin(self, req):

		# let's check if parent process has injected thread first
		if self.acciones['100'] != [] and self.acciones['108'] != [] \
										and req['idEvent'] == 10:
			for action108 in self.acciones['108']:
				if action108["NewThreadId"] == req["ThreadId"]:
					for child in self.hijo:
						if child.acciones["1"][0]["ProcessGuid"] == \
												req["TargetProcessGuid"]:
						
							parent = "(" + action108["SourceProcessId"] + \
										") " + action108["SourceImage"]
										
							c_origin = {"CreationType":"InjectedThread",\
										"RealParent":parent}
											
							child.acciones["1"][0].update(c_origin)
							
	def getProcessChain(self):
		pchain = []
		while self.guid != '0': # node root
			pchain.append(self)
			self = self.padre
		return pchain

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



####################NUEVOOOOOOOO
class Node_(object):
	def __init__(self, req):
		'''
		# pid de sysmon id 1
		self.pid = req['ProcessId']
		
		# command line de sysmon id 1
		self.cmd = req['CommandLine']
		
		# uniq process id
		self.guid = req['ProcessGuid']
		'''
		# uniq pprocess id
		self.ParentProcessGuid = req['ParentProcessGuid']

		# process image
		self.ImageFileName = get_image_fileName(req['Image'])
		

		#diccionario donde para cada accion (conexion , modificacion registro..)
		# se guarda un listado de las mismas
		self.acciones = {'1':[],'2':[], '3':[], '5':[],'7':[],
						'8':[],'9':[],'10':[],'11':[],
						'12':[],'13':[],'14':[],'15':[],
						'17':[],'18':[],'22':[],'100':[],'108':[],'110':[]}
		
		# BASELINE Engine Attributes
		# baseline process points
		self.points = 100
		
		# baseline result suspicious actions
		self.suspicious_actions = []
		
		# baseline already notified
		self.notified = False

