import logging
import datetime
from SysmonParser import getImageFileName
log = logging.getLogger('sysmoncorrelator')

#----------------------------------------------------------------------------#
# Estructura de datos que almacena un arbol n-ario de procesos de la maquina #
#----------------------------------------------------------------------------#
class Nodo(object):
	def __init__(self, pid, cmd, guid, image):
		# pid de sysmon id 1
		self.pid = pid
		
		# command line de sysmon id 1
		self.cmd = cmd
		
		# uniq process id
		self.guid = guid

		# process image
		self.ImageFileName = getImageFileName(image)
		

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
		
	'''Metodo para anyadir un proceso hijo a un padre.
	No devuelve nada
	'''
	def add_hijo(self, obj):
		#anyado el hijo
		obj.padre = self
		self.hijo.append(obj)
		
		#al hijo le asociamos el padre
		#ultimo = len(self.hijo) - 1 
		#self.hijo[ultimo].padre = self
		
	'''Metodo para anyadir  los detalles de una accion a un proceso.
	Se guarda en un diccionario donde cada clave es el tipode la accion y el
	valor es un vector con los detalles de cada accion (otro dicc)
	'''		
	def add_detalles_accion(self, det, tipo):
		self.acciones[tipo].append(det)
	
				
	''' Metodo que dado un pid busca su proceso padree para anyadirlo al arbol
	como hijo
	'''
	def add_pid(self, node, pguid):
		if (self.guid == pguid):
			self.add_hijo(node)
		else:
			for child in self.hijo:
				child.add_pid(node, pguid)
				
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

	'''
	def search_child_acctions(self, filter_list, matchlist):
		# Getting all childs from a process
		for child in self.hijo:
			match = True
			for type_action in filter_list.keys():

				match =  self.check_acction(type_action, child, filter_list)
				if not match:
					break
					
			if match:		
				matchlist.append(child)
				
	def search_all_childs_acctions(self, obj, filter_list, matchlist):
		# Getting all childs from a process
		for nodo in obj.hijo:
			match = True
			for type_action in filter_list.keys():  								

				match = self.check_acction(type_action, nodo, filter_list)
				if not match:
					break
					
			if match:
				matchlist.append(nodo)
				
			self.search_all_childs_acctions(nodo,filter_list, matchlist)	


	def check_acction(self, type_action, nodo, filter_list): 
		
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
				for filter in filter_list[type_action]:
				
					# Filter property could have "-" modifier as well
					acc_filter = filter.replace('-','')
					if "-" in filter:
						filter_reverse = True		
					else:
						filter_reverse = False
					
					final_reverse = acction_reverse^filter_reverse
					
					# Finally comparing if a rule filter match a process acction
					if not self.check_filter_if_match( 
						filter_list[type_action][filter].lower(), 
						acc[acc_filter].lower(), final_reverse):
						return False
						
		# Process has no acctions of this type
		else:
			if not acction_reverse:
				return False
			
		return True
		

	def check_filter_if_match(self, filters, acction, reverse):
		match = False
		
		for filter in filters.split(";"):
			if filter in acction:
				match = True
				
		if reverse:
			return not match
		else:
			return match
	
	'''
	def getNumChilds(self):
		return len(self.hijo)
	
	''' Encuentra una accion identificada numericamente por sysmon
	en todos los procesos por bajo de ese proceso padre,
	(Ej.tipo 3 conexion) a partir de un nodo y devuelve sus detalles. 
	Los detalles son un diccionario qeu depende del tipo de accion.
	'''
	def busca_primera_accion(self, obj, tipo, filter):
		if (obj.acciones[tipo] != []):
			for acc in obj.acciones[tipo]:
				if filter[filter.keys()[0]] in acc[filter.keys()[0]] or \
					filter[filter.keys()[0]] == '*':
					return obj
		else:	
			for nodo in obj.hijo:
				accion_det = self.busca_primera_accion(nodo, tipo, filter)
				if accion_det:
					return accion_det

	''' Encuentra el priemr proceso q cumple por nombre y devuelve un 
	objeto de tipo nodo.
	'''					
	def busca_primer_proceso(self, obj, nombre):
		#print "comparando " + nombre + " con \"" + obj.cmd + "\""
		#self != obj previene de que haga match con el mismo nodo en si
		if (nombre.lower() in obj.image.lower()) and (self != obj):
			#print "Encontrado " + nombre + " en PID: " + str(obj.pid)
			return obj
		else:
			for nodo in obj.hijo:
				proceso = self.busca_proceso(nodo, nombre)
				if proceso:
					return proceso

	''' Encuentra una proceso por nombre y devuelve su hijo si cumple.
	'''					
	def get_primer_proceso(self, obj, nombre):
		for hijo in self.hijo:
			if (nombre.lower() in hijo.image.lower()):
				return hijo
		return None
		
			
	def getProcessChain(self):
		pchain = []
		while self.guid != '0': # node root
			pchain.append(self)
			self = self.padre
		return pchain
		
	def printTree(self):
		try:
			print ("[PID %s] [PPID %s] %s") % (self.acciones['1'][0]['ProcessId'], self.acciones['1'][0]['ParentProcessId'], self.acciones['1'][0]['CommandLine'])
		except Exception, e:
			print str(e)
		for hijo in self.hijo:
			hijo.printTree()
			
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
	def updateProcessCreationOrigin(self, req):

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
	
			
			