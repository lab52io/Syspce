import logging
try:
	import win32evtlog
	import win32event
except:
	print "Missing dependencies win32evtlog, consider install pywin32"
	print "#pip install pywin32"
	exit(1)

from syspce_input import Input
from syspce_parser import *
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

		server = None
		events_list = []

		# Reading from a file 
		if self.filepath:
			try:
				h_log = win32evtlog.OpenBackupEventLog(server, self.filepath)
			except Exception, e:
				log.error(str(e))
				self.console_print(e.args[2])
				exit(1)
			
		# Reading from evetnlog
		else:
			#Hack, we need to add this registry key if we want to use win32event lib
			#Equipo\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\
			#	Services\EventLog\Microsoft-Windows-Sysmon/Operational
		
			source_type = "Microsoft-Windows-Sysmon/Operational" 
			try:
				h_log = win32evtlog.OpenEventLog(server, source_type)
			except win32evtlogutil.error, details:
				self.console_print(str(details))
				log.error(str(details))
				exit(1)
		
		total_events = win32evtlog.GetNumberOfEventLogRecords(h_log)

		log.info("Total events: %d" % total_events)

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
					try:
						req_parsed = parse_eventlog_IDx(self.schema, event)
					except KeyNotFound as knf:
						self.console_print(knf.message)
						exit(1)
					except WrongSchema as ws:
						self.console_print(ws.message)
						exit(1)

					try:
						actions_list = get_list_of_actions(req_parsed)
					except KeyNotFound as knf:
						self.console_print(knf.message)
						exit(1)

					for action in actions_list:
						events_list.append(action)

		if self._running:
			self.send_message(events_list)
		self.terminate()
		log.debug("%s terminated." % (self.name))