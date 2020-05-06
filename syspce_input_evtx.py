import logging
try:
	import win32evtlog
	import win32event
except:
	print "Missing dependencies win32evtlog, consider install pywin32"
	print "#pip install pywin32"
	exit(1)

from syspce_input import Input
from syspce_parser import get_action_from_id
from syspce_parser import parse_eventlog_IDx
from syspce_parser import get_list_of_actions
from syspce_message import *

log = logging.getLogger('sysmoncorrelator')

class InputEvtx(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src,
				 filepath, schema):

		Input.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		self.filepath = filepath
		self.schema = schema
		self.name = 'Input Evtx'
		self.module_id = Module.INPUT_EVTX

	def do_action(self):

		server = "localhost"
		events_list = []

		# Reading from a file 
		if self.filepath:
			try:
				h_log = win32evtlog.OpenBackupEventLog(server, self.filepath)
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

		#log.info("Total events: %d" % total_events)

		flags = win32evtlog.EVENTLOG_FORWARDS_READ|\
				win32evtlog.EVENTLOG_SEQUENTIAL_READ
	
		num_events = 0

		while num_events < total_events and self._running:

			records = win32evtlog.ReadEventLog(h_log, flags,0)
			num_events += len(records)

			#print 'Progress: %d/%d \r' % (num_events, total_events),

			for event in records:
				req_parsed = {}
				if event.EventID in self.EVENTLOG_EVENTID:
					req_parsed = parse_eventlog_IDx(self.schema,
													event)
					try:
						actions_list = get_list_of_actions(req_parsed)
					except Exception, e:
						log.error(str(e))
						log.error("Missing Sysmon/Operational registry key")
						log.error("Add key located in RegistryKey directory")
						log.error("See README for more info")
						exit(1)

					for action in actions_list:
						events_list.append(action)

		if self._running:
			self.send_message(events_list)
		self.terminate()
		log.debug("%s terminated." % (self.name))