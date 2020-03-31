# -*- coding: utf-8 -*-
'''                                                                                
  ___ _   _ ___ _ __ ___   ___  _ __                                                  
 / __| | | / __| '_ ` _ \ / _ \| '_ \                                                 
 \__ \ |_| \__ \ | | | | | (_) | | | |                                                
 |___/\__, |___/_| |_| |_|\___/|_| |_|_          _                 _                  
       __/ |                         | |        | |               (_)                 
  _ __|___/_ ___   ___ ___  ___ ___  | |__   ___| |__   __ ___   ___  ___  _   _ _ __ 
 | '_ \| '__/ _ \ / __/ _ \/ __/ __| | '_ \ / _ \ '_ \ / _` \ \ / / |/ _ \| | | | '__|
 | |_) | | | (_) | (_|  __/\__ \__ \ | |_) |  __/ | | | (_| |\ V /| | (_) | |_| | |   
 | .__/|_|  \___/ \___\___||___/___/ |_.__/ \___|_| |_|\__,_| \_/ |_|\___/ \__,_|_|   
 | |                     | |     | |                                                  
 |_|__ ___  _ __ _ __ ___| | __ _| |_ ___  _ __                                       
  / __/ _ \| '__| '__/ _ \ |/ _` | __/ _ \| '__|                                      
 | (_| (_) | |  | | |  __/ | (_| | || (_) | |                                         
  \___\___/|_|  |_|  \___|_|\__,_|\__\___/|_|                                         

 
 This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''


__version__ = '1.1'
__author__ = '@ramado78'

'''
- Date: 18/12/2019
- Bugs suggestions: ramado@s2grupo.es
- Web: https://lab52.io
'''


import re
import win32evtlog
import win32event
import pprint
import json
from time import sleep
import sys
import logging
import argparse

from SysmonParser import *
from TreeNodes import Nodo
from ProcessHierarchyEngine import ProcessHierarchyEngine
from BaselineEngine import BaselineEngine
from CorrelatorOutput import *



# Event ID from sysmon eventlog that correlator supports.
EVENTLOG_EVENTID = [1,2,3,5,7,8,9,10,11,12,13,14,15,17,18,22,100,108,110]

log = None	
SYSMON_SCHEMA = {}
num_alerts = 0

#----------------------------------------------------------------------------#
# Funciones auxiliares para la constrcuion del arbol de procesos			 #
#----------------------------------------------------------------------------#

 

''' Funcion dada cada entrada que nos devulve la BBDD va construyendo el arbol
de procesos. Como salida se tiene un arbol cuya root tiene como hijos todos 
los procesos que no tienen padre. Usando posteriormente la variable "root" se 
puede operar con el arbol de procesos de un equipo.
'''				
def addToProcessTree(req, root):
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
			node = Nodo(processId, commandline, ProcessGuid, Image)
			log.debug("Adding new process to the processtree PID %s: %s" % \
						(node.pid, node.ImageFileName))
			
			#Lo asignamos a la root de ese equipo ya que no existia con 
			#anterioridad el host
			if not req['computer'] in root:
				#Creamos nodo root sin datos para esa maquina
				root[req['computer']] = {
									'nodo_root':Nodo(0, 'root', '0', 'c:\\root'),
									'lista_procesos':[],
									'total_procesos': 0,
									'total_conexiones': 0}
										
				#Anyadimos el primer hijo al nodo root de procesos
				root[req['computer']]['nodo_root'].add_hijo(node)
				
				#Incluimos en la lista de procesos el nuevo
				root[req['computer']]['lista_procesos'].append(ProcessGuid)
				root[req['computer']]['total_procesos'] += 1
			else:
				#Si el proceso padre existe le buscamos el padre para incluirlo
				#como su hijo
				if ParentProcessGuid in root[req['computer']]['lista_procesos']:

					root[req['computer']]['nodo_root'].add_pid(node, 
															ParentProcessGuid)
					
					root[req['computer']]['lista_procesos'].append(ProcessGuid)
	
					log.debug("Process added to parent: %s parent %s" %\
															(node.ImageFileName,
															node.padre.pid))
				#Si no existe entonces al nodo root
				else:
					root[req['computer']]['lista_procesos'].append(ProcessGuid)
					root[req['computer']]['nodo_root'].add_hijo(node)
					log.debug("Process added to root node: %s parent %s" %\
															(node.ImageFileName,
															node.padre.pid))
				#finalmente incrementamos el contador de procesos	
				root[req['computer']]['total_procesos'] += 1

			
			# Adding 2 new attribites to Event id 1
			# CreationType: [RegularThread, InjectedThread] 
			# 	(see updateProcessCreationOrigin) and
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
			root[req['computer']]['nodo_root'].add_accion(
										root[req['computer']]['nodo_root'],
										req, str(req['idEvent'])
										)
			

		# Es otra accion diferente a la creacion de un proceso
		else:

			if (not req['computer'] in root):
				return node
	
			# Adding now normal proccess action if exists
			if req['ProcessGuid'] in root[req['computer']]['lista_procesos']:				

				# Adding additional information regarding target 
				if req['idEvent'] == 8 or req['idEvent'] == 10:
					tnode = \
						root[req['computer']]['nodo_root'].get_node_by_guid(\
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
						root[req['computer']]['nodo_root'].get_node_by_guid(\
													req['SourceProcessGuid'])
					if snode:
						req['SourceSession'] = \
									snode.acciones['1'][0]['TerminalSessionId']
						req['SourceIntegrityLevel'] = \
									snode.acciones['1'][0]['IntegrityLevel']
						req['SourceUser'] = \
									snode.acciones['1'][0]['User']
										
					# if snode dosen't exists we don't include new attribites
								
				node = root[req['computer']]['nodo_root'].add_accion(
										root[req['computer']]['nodo_root'],
										req, str(req['idEvent'])
										)
										
				# 2 types: regular or by remote injected thread
				node.updateProcessCreationOrigin(req)					

				#If it's a Terminate proccess (5) event let's calculate TTL
				if req['idEvent'] == 5:
					process_ttl = {"ProcessTTL": str(node.getLiveTime())}	
					node.acciones['5'][0].update(process_ttl)	
					node.acciones['1'][0].update(process_ttl)

			# Updating computer connexions counter
			if req['idEvent'] == 3:
				root[req['computer']]['total_conexiones'] += 1			
		return node


'''FUNC DESC: encargada de monitorizar el eventlog de forma continua
'''

def readFromEvtx(path_evtx, root, baseline):
    global num_alerts
	
    server = "localhost"
	
	# Reading from a file 
    if path_evtx:
		try:
			h_log = win32evtlog.OpenBackupEventLog(server, path_evtx)
		except Exception, e:
			log.error(str(e))
			exit(1)
			
	# Reading from evetnlog
    else:
		#Hack, we need to add this registry key if we want to use win32event lib
		#Equipo\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\
		#	Services\EventLog\Microsoft-Windows-Sysmon/Operational
		
		source_type = "Microsoft-Windows-Sysmon/Operational" 
		h_log = win32evtlog.OpenEventLog(server, source_type)
		
    total_events = win32evtlog.GetNumberOfEventLogRecords(h_log)
    log.info("Total events: %d" % total_events)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ|\
			win32evtlog.EVENTLOG_SEQUENTIAL_READ
	
    num_events = 0
    while num_events < total_events:
		events = win32evtlog.ReadEventLog(h_log, flags,0)
		num_events += len(events)
		print 'Progress: %d/%d \r' % (num_events, total_events),
		if events:
			for event in events:
				req_parsed = {}
				if event.EventID in EVENTLOG_EVENTID:
					req_parsed = parseEventlogIDx(SYSMON_SCHEMA, event, server)
					actions_list = getListOfActions(req_parsed)
					for action in actions_list:
						pnode = addToProcessTree(action, root)
						
						# Baseline engine actions
						if pnode:
							baseline.runActionCheck(pnode, action)
							if baseline.fireAlert(pnode):
								num_alerts += 1

'''FUNC DESC: encargada de buscar un eventid en un evtx
'''

def searchInEvtx(path_evtx, filter, attribute):
    server = "localhost"

    filter = eval(filter)
	
	# Reading from a file 
    if path_evtx:
		h_log = win32evtlog.OpenBackupEventLog(server, path_evtx)
		
	# Reading from evetnlog
    else:

		source_type = "Microsoft-Windows-Sysmon/Operational" 
		h_log = win32evtlog.OpenEventLog(server, source_type)
		
    total_events = win32evtlog.GetNumberOfEventLogRecords(h_log)
    log.info("Searching in total events: %d" % total_events)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ|\
			win32evtlog.EVENTLOG_SEQUENTIAL_READ

    num_events = 0
    while num_events < total_events:
		events = win32evtlog.ReadEventLog(h_log, flags,0)
		num_events += len(events)
		print 'Progress: %d/%d \r' % (num_events, total_events),
		if events:
			for event in events:
				req_parsed = {}
				if event.EventID in EVENTLOG_EVENTID:
					req_parsed = parseEventlogIDx(SYSMON_SCHEMA, event, server)

					try:
						match = True
						for filter_attribute in filter:
						
							#special case for filter attribute idEvent becouse
							# it's an int not string
							if filter_attribute == 'idEvent':
								if filter[filter_attribute] != \
									req_parsed[filter_attribute]:
									match = False
									break 
							else:
								if filter[filter_attribute].lower() not in \
									req_parsed[filter_attribute].lower():
									match = False
									break 								
									
						if match:
							if attribute:
								try:
									print req_parsed[attribute]
								except:
									log.error('Filter attribute not found')
							
							else:
								pprint.pprint(req_parsed)
								print "\n"
							
					except Exception, e:
						pass
						
def monitEventlog(root, args, engine, baseline):
	server = "localhost"
	source_type = "Microsoft-Windows-Sysmon/Operational"
	num_events = 0
	
	h_log = win32evtlog.OpenEventLog(server, source_type)
	flags = win32evtlog.EVENTLOG_FORWARDS_READ|\
			win32evtlog.EVENTLOG_SEQUENTIAL_READ
						
	total_events = win32evtlog.GetNumberOfEventLogRecords(h_log)
	h_evt = win32event.CreateEvent(None, 1, 0, "evt0")
	win32evtlog.NotifyChangeEventLog(h_log, h_evt)
	
	while True:
		events_read = []
		
		while True:
			aux = win32evtlog.ReadEventLog(h_log, flags, 0)
			if not aux:
				break
			events_read += aux

		if events_read:

			num_events += len(events_read)
			log.debug("Read from eventlog: %d  - Total readed: %d \r" %\
					(len(events_read), num_events))
					
			for event in events_read:
				req_parsed = {}
				if event.EventID in EVENTLOG_EVENTID:
					req_parsed = parseEventlogIDx(SYSMON_SCHEMA, event, server)
					actions_list = getListOfActions(req_parsed)
					for action in actions_list:
						pnode = addToProcessTree(action, root)
						# Baseline engine actions
						if pnode:
							baseline.runActionCheck(pnode, action)
							baseline.fireAlert(pnode)
		
			# Wait for proccess all the tree
			if (num_events >= total_events):
				engine.run(root)
				
				log.debug("Waiting for events on eventlog")
				wait_result = win32event.WaitForSingleObject(h_evt, -1)

def init():
    """Initialization Function"""
    global log
    global SYSMON_SCHEMA
	
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                    help="Verbose debug",action="store_true")
    parser.add_argument("-d", "--daemon", 
                    help="Live detection",action="store_true")
    parser.add_argument("-b", "--baseline", 
                    help="Baseline detection engine",action="store_true")
    parser.add_argument("-r", "--rules", nargs=1, metavar='FileName',
                    help="Rules definition file")
    parser.add_argument("-f", "--file", nargs=1, metavar='FileName',
                    help="File .evtx to process")
    parser.add_argument("-e", "--eventid", nargs=1, metavar='Dictionary',
					help="Search for EventIDs or attributes as JSON filter")
    parser.add_argument("-a", "--attribute", nargs=1, metavar='Attribute',
					help="Show only an specific attribute when using -e option")
    parser.add_argument("-s", "--schema", nargs=1, metavar='FileName',
					help="Sysmon schema xml file")
    parser.add_argument("-l", "--full_log", 
                    help="Full actions details of process chain",
						action="store_true")
    parser.add_argument("-o", "--output",  metavar='Output', 
					choices = ['stdout', 'eventlog'],
					required = False,
                    help="Choose an alert output from 'stdout', 'eventlog' ")
    parser.add_argument("-L", "--log_file", nargs=1, metavar='FileName',
                    help="Log to local log file instead stdout ")
						
    args = parser.parse_args()
    
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
		
    if args.log_file:
		logging.basicConfig(level=loglevel,
						filename= args.log_file[0],
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S ')
    else:
		logging.basicConfig(level=loglevel,
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S ')

    log = logging
	
	# Configuring Schema version for parser default 3.4
    if args.schema:
		SYSMON_SCHEMA = getSysmonXmlSchema(args.schema[0])
		log.info("Using schema " + args.schema[0] + " for log parsing")
		
    else:
		m = "Using default Sysmon config schema 3.4, this can afect log parsing"
		log.warning(m)
		SYSMON_SCHEMA = getSysmonXmlSchema('sysmonSchema3.4.xml')
	
	#Cheking correct parsing
    if len(SYSMON_SCHEMA) == 0:
		log.error("Can't parse Sysmon Schema file")
		exit(1)
  
	
	# Loading rules file
    if args.rules:
		rules_file = args.rules[0]
    else:
		rules_file = 'detection.rules'

    try:
		with open(rules_file) as json_rules:
			detection_rules = json.load(json_rules)
    except Exception, e:
		log.error("Opening or parsing rules file:  %s" % e)
		return False
    json_rules.close()
	
	# Loading rules macros
    try:
		with open('detection.macros') as json_macros:
			detection_macros = json.load(json_macros)[0]
    except Exception, e:
		log.error("Opening or parsing macros rules file:  %s" % e)
		return False	
    json_macros.close()

	# Loading baseline rules
    try:
		with open('baseline.rules') as json_baseline:
			baseline_rules = json.load(json_baseline)[0]
    except Exception, e:
		log.error("Opening or parsing baseline rules file:  %s" % e)
		return False	
    json_baseline.close()
	
    return args, detection_macros, detection_rules, baseline_rules

	

	
def main():
	"""Main Function"""
	global num_alerts
	
	res = []
	root ={}
	
	# Loggin and args initialitation
	args, detection_macros, detection_rules, baseline_rules = init()
	if not args:
		exit(1)
		
	# Creating presentation object
	output = CorrelatorOutput(log, args.output, args.full_log)	
	
	# Creating detection engine
	engine = ProcessHierarchyEngine(detection_rules, detection_macros, output)

	# Creating baseline engine
	baseline =  BaselineEngine(args.baseline, baseline_rules, detection_macros)
	
	# checking filter attributes for option -e
	if args.attribute:
		f_attribute = args.attribute[0]
	else:
		f_attribute = False

	# Searching for an EventID in a file
	if args.file and args.eventid:
		searchInEvtx(args.file[0], args.eventid[0], f_attribute)
		exit(0)
	# Reading from a evtx file
	elif args.file:
		readFromEvtx(args.file[0], root, baseline)
		
	# Live monitoring 
	elif args.daemon:
		monitEventlog(root, args, engine, baseline)
		
	elif not args.file and args.eventid:
		searchInEvtx(False, args.eventid[0], f_attribute)
		exit(0)
	# read from local eventlog
	else:
		readFromEvtx(False, root, baseline)

	log.info("Building process tree finished")
	for machine in root:
		log.info("Total number of process for machine %s: %d" %\
				( machine, root[machine]['total_procesos']) )
				
		log.info("Total number of connections for machine %s: %d" %\
				( machine, root[machine]['total_conexiones']) )
				
	# Execute user defined anomalies against process tree.
	num_alerts += engine.run(root)
	log.info("Total number of alerts: %d" % num_alerts)	

if __name__== "__main__":
	main()





