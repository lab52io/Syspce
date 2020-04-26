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

class InputEventlog(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src, schema):

		Input.__init__(self, data_buffer_in,
					   data_condition_in, src)

		self.schema = schema
		self.name = 'Input Eventlog'
		self.module_id = Module.INPUT_EVENTLOG


	def do_action(self):

		server = "localhost"
		events_list = []

		source_type = "Microsoft-Windows-Sysmon/Operational"
		num_events = 0
	
		h_log = win32evtlog.OpenEventLog(server, source_type)
		flags = win32evtlog.EVENTLOG_FORWARDS_READ|\
				win32evtlog.EVENTLOG_SEQUENTIAL_READ
						
		total_events = win32evtlog.GetNumberOfEventLogRecords(h_log)
		h_evt = win32event.CreateEvent(None, 1, 0, "evt0")
		win32evtlog.NotifyChangeEventLog(h_log, h_evt)
	
		while self._running:
			events_read = []
			events_list = []

			while self._running:
				aux = win32evtlog.ReadEventLog(h_log, flags, 0)
				#print 'Progress: %d/%d \r' % (num_events, total_events),
				if not aux:
					break
				events_read += aux

			if events_read and self._running:

				num_events += len(events_read)
				log.debug("Read from eventlog: %d  - Total readed: %d \r" %\
						(len(events_read), num_events))
					
				for event in events_read:
					req_parsed = {}

					if event.EventID in self.EVENTLOG_EVENTID:
						req_parsed = parse_eventlog_IDx(self.schema,
														event, server)
						try:
							actions_list = get_list_of_actions(req_parsed)
						except:
							log.error("Missing Sysmon/Operational registry key")
							log.error("Add key located in RegistryKey directory")
							log.error("See README for more info")
							exit(1)

						for action in actions_list:
							events_list.append(action)

				self.send_message(events_list)

				# Wait for proccess all the tree
				if (num_events >= total_events):
				
					log.debug("Waiting for events on eventlog")
					#win32event.WaitForSingleObject(h_evt, -1)
					win32event.WaitForSingleObject(h_evt, 1000)

		log.debug("%s terminated." % (self.name))