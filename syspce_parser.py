import logging
import xml.etree.ElementTree as ET
import re

log = logging.getLogger('sysmoncorrelator')

def get_image_fileName(image):
	ImageFileName = ''
	
	try:
		ImageFileName = image.split('\\')[-1].lower()
	except Exception , e:
		log.error("Getting ImageFileName: %s" % str(e))
		
	return ImageFileName

def get_sysmon_xml_schema(xmlfile):
	
	try:
		tree = ET.parse(xmlfile)
		root = tree.getroot()
		events = root[1]
	except Exception, e:
		log.error("Parsing XML Schema: %s" % e)
		return {}
	
	return events

def parse_eventlog_IDx(schema, event):
	event_details = {'computer': '', 'idEvent': event.EventID}
	message = event.StringInserts
	
	i = 0
	if not message:
		log.error("Add registry key, in order to read sysmon event log")
		exit(1)

	for line in message:
		#special case for error 255
		if event.EventID == 255:
			event.EventID = 0
		try:
			event_parameter = schema[event.EventID][i].attrib['name']
			event_parameter = normalize_event_parameter(event_parameter)
			event_details[ event_parameter ] = line

		except Exception, e:
			log.error("Probably wrong Sysmon Schema version %s " % str(e))
			log.error("Use: #sysmon -s > schemaVersion.xml")
			log.error("     #python sysmonCorrelator.py -s schemaVersion.xml")
			exit(1)
		i += 1

	event_details['computer'] = get_machine_guid(event_details['ProcessGuid'])

	return event_details


def get_machine_guid(ProcessGuid):
	''' Function for getting MachineGUID from ProcessGUID
	'''
	trunk_guid = re.match(r"\{(\w{8})", ProcessGuid)
	return trunk_guid.group(1)


def get_list_of_actions(action):
	'''
		There are special events that we need to manage as two diferent actions, 
		associated to Source and target Image process nodes:
		Event 8, 10, 1 -> 108, 110, 100
		So if we find an ID 8 we need to return both 8 and the new one 108
	'''
	action_list = [action]
	
	newreq = action.copy()
	multi_action = False
	
	if (action['idEvent'] == 8):
	
		newreq['idEvent'] = 108
		
		aux = newreq['TargetProcessGuid']
		newreq['SourceProcessGuid'] = newreq['ProcessGuid']
		newreq['ProcessGuid'] = aux	
		
		aux = newreq['TargetImage']
		newreq['SourceImage'] = newreq['Image']
		newreq['Image'] = aux

		aux = newreq['TargetProcessId']
		newreq['SourceProcessId'] = newreq['ProcessId']
		newreq['ProcessId'] = aux
		
		action_list.append(newreq)
		
	elif (action['idEvent'] == 10):
	
		newreq['idEvent'] = 110
		
		aux = newreq['TargetProcessGuid']
		newreq['SourceProcessGuid'] = newreq['ProcessGuid']
		newreq['ProcessGuid'] = aux
						
		aux = newreq['TargetImage']
		newreq['SourceImage'] = newreq['Image']
		newreq['Image'] = aux

		aux = newreq['TargetProcessId']
		newreq['SourceProcessId'] = newreq['ProcessId']
		newreq['ProcessId'] = aux
		
		action_list.append(newreq)
		
	elif (action['idEvent'] == 1):

		newreq = {}
		newreq['computer'] = action['computer']
		newreq['idEvent'] = 100
		newreq['ChildProcessGuid'] = action['ProcessGuid']
		newreq['ChildProcessId'] = action['ProcessId']
		newreq['ChildCommandLine'] = action['CommandLine']
		newreq['ChildLogonGuid'] = action['LogonGuid']
		newreq['ChildImage'] = action['Image']
		newreq['ProcessGuid'] = action['ParentProcessGuid']
		newreq['ProcessId'] = action['ParentProcessId']
		newreq['Image'] = action['ParentImage']
		newreq['UtcTime'] = action['UtcTime']
		action_list.append(newreq)
		
	else:
		newreq = {}
		
	return action_list
	

def normalize_event_parameter(parameter):
	#Special case for events 10 and 8. Ej. SourceImage -> Image
	parameter = parameter.replace('Source', '')
	parameter = parameter.replace('GUID', 'Guid')
	
	return parameter
	
def get_action_from_id(id):
	
	if id == 1:
		return "PROCESS CREATED"
	elif id == 2:
		return "[A] FILE TIME CHANGED"
	elif id == 3:
		return "[A] CONNECTION TO"
	elif id == 5:
		return "[A] PROCESS TERMINATE" 
	elif id == 7:
		return "[A] IMAGE LOADED" 
	elif id == 8:
		return "[A] CREATE REMOTE THREAD TO" 
	elif id == 9:
		return "[A] RAW ACCESS READ"
	elif id == 10:
		return "[A] OPEN REMOTE PROCESS"
	elif id == 11:
		return "[A] FILE CREATE"
	elif id == 12:
		return "[A] REG KEY ADDED"
	elif id == 13:
		return "[A] REG KEY SET VALUE"
	elif id == 14:
		return "[A] REG KEY RENAMED"
	elif id == 15:
		return "[A] ALTERNATE DATA STREAM CREATED"
	elif id == 17:
		return "[A] PIPE CREATED"
	elif id == 18:
		return "[A] PIPE CONNECTED"
	elif id == 22:
		return "[A] DNS QUERY"
	elif id == 23:
		return "[A] FILE DELETE"
	elif id == 100:
		return "[A] CHILD PROCESS CREATED" 
	elif id == 101:
		return "[A] THREAD CREATED"
	elif id == 102:
		return "[A] VAD CREATED" 
	elif id == 103:
		return "[A] TOKEN CREATED" 
	elif id == 108:
		return "[A] STARTED THREAD CREATED BY REMOTE PROCESS" 
	elif id == 110:
		return "[A] PROCESS WAS OPENED BY"
	else:
		return ""

def get_default_parameter_from_id(id):
	
	if id == 1:
		return "Image"
	elif id == 2:
		return "TargetFilename"
	elif id == 3:
		return "DestinationIp"
	elif id == 5:
		return "Image" 
	elif id == 7:
		return "ImageLoaded" 
	elif id == 8:
		return "TargetImage" 
	elif id == 9:
		return "Device"
	elif id == 10:
		return "TargetImage"
	elif id == 11:
		return "TargetFilename"
	elif id == 12:
		return "TargetObject"
	elif id == 13:
		return "TargetObject"
	elif id == 14:
		return "TargetObject"
	elif id == 15:
		return "TargetFilename"
	elif id == 17:
		return "PipeName"
	elif id == 18:
		return "PipeName"
	elif id == 22:
		return "QueryName"
	elif id == 23:
		return "TargetFilename"
	elif id == 100:
		return "ChildImage"
	elif id == 101:
		return "ThreadId"
	elif id == 102:
		return "VadNode"
	elif id == 103:
		return "User"
	elif id == 108:
		return "SourceImage"
	elif id == 110:
		return "SourceImage"
	else:
		return "UNKNOW ACTION"
