import logging

from syspce_manager import Manager_
from syspce_message import *
from syspce_job import Job
from syspce_console import Console
from time import sleep
log = logging.getLogger('sysmoncorrelator')

class ControlManager(Manager_):

    def __init__(self, data_buffer_in, data_condition_in):

		Manager_.__init__(self, data_buffer_in,
					   data_condition_in)

		self.name = 'Control Manager'
		self.module_id = Module.CONTROL_MANAGER
		self.messages_accepted = [MessageType.COMMAND, 
								  MessageType.ALERT,
								  MessageType.COMMAND_RES,
								  MessageType.DATAIN]       
		self.console = Console(data_buffer_in, data_condition_in)
		self.console.start()
		self.modules_list.append(self.console)

    def _process_messages(self, message_list):
		for message in message_list:

			### MANAGEMENT
			# Ending and closing all
			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()

			### USER COMMANDS
			# Read from a evtx/eventlog user command
			elif message._subtype == MessageSubType.READ_FROM_FILE:
				self.read_evtx(message._content[0],
							   message._content[1], message._origin)

			elif message._subtype == MessageSubType.READ_FROM_MEMDUMP:
				self.read_memdump(message._content[0],
								  message._content[1], message._origin)

			### ENGINES RESULTS
			# Results from a eventlog/evtx search user command
			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.FILTER_ENGINE:
				self.console.print_search_result(message._content[0])


			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.HIERARCHY_ENGINE:
				self.console.print_alert_hierarchy(message._content[0])

			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.BASELINE_ENGINE:
				self.console.print_alert_baseline(message._content[0])

			elif message._type == MessageType.COMMAND_RES:
				self.console.print_command_result(message._content[0])

    def read_evtx(self, filepath, detection_rules,
				  detection_macros,  baseline_rules,
				  schema, origin):

		read_evtx_job = Job(self.data_buffer_in, 
							self.data_condition_in,
							JobType.SINGLE_ACTION,
							MessageSubType.FILTER_DATA,
							origin)

		read_evtx_job.configure_IM(MessageType.COMMAND,
								   MessageSubType.READ_FROM_FILE,
								   [filepath, schema])

		read_evtx_job.configure_EM(MessageType.DATAIN,
								   MessageSubType.DETECT,
								   [detection_rules, baseline_rules,
									detection_macros])

		read_evtx_job.configure_CM(MessageType.ALERT,
								   MessageSubType.DETECT,
								   [])

		read_evtx_job.start()
		self.modules_list.append(read_evtx_job)

    def read_memdump(self, filepath, profile,  detection_rules,
				     detection_macros,  baseline_rules,
				     origin):

		read_memdump_job = Job(self.data_buffer_in, 
							   self.data_condition_in,
							   JobType.SINGLE_ACTION,
							   MessageSubType.READ_FROM_MEMDUMP,
							   origin)

		read_memdump_job.configure_IM(MessageType.COMMAND,
								      MessageSubType.READ_FROM_MEMDUMP,
								      [filepath, profile])

		read_memdump_job.configure_EM(MessageType.DATAIN,
								      MessageSubType.DETECT,
								      [detection_rules, baseline_rules,
									  detection_macros])

		read_memdump_job.configure_CM(MessageType.ALERT,
								      MessageSubType.DETECT,
								      [])

		read_memdump_job.start()
		self.modules_list.append(read_memdump_job)


    def search_event(self, filepath, schema, 
					 search_filter, filter_attribute, origin):

		search_event_job = Job(self.data_buffer_in,
							   self.data_condition_in,
							   JobType.SINGLE_ACTION,
							   MessageSubType.FILTER_DATA,
							   origin)

		search_event_job.configure_IM(MessageType.COMMAND,
									  MessageSubType.READ_FROM_FILE,
									  [filepath, 
									   schema])

		search_event_job.configure_EM(MessageType.DATAIN,
									  MessageSubType.FILTER_DATA, 
									  [search_filter,
									   filter_attribute])

		search_event_job.configure_CM(MessageType.DATAIN,
							          MessageSubType.FILTER_DATA,
									  [])

		search_event_job.start()
		self.modules_list.append(search_event_job)


    def read_eventlog(self, detection_rules,
					  detection_macros,  baseline_rules,
					  schema, origin):

		read_eventlog_job = Job(self.data_buffer_in, 
								self.data_condition_in,
								JobType.DAEMON,
								MessageSubType.FILTER_DATA,
								origin)

		read_eventlog_job.configure_IM(MessageType.COMMAND,
									   MessageSubType.READ_FROM_EVENTLOG,
									   [schema])

		read_eventlog_job.configure_EM(MessageType.DATAIN,
									   MessageSubType.DETECT,
									   [detection_rules, baseline_rules,
										detection_macros])

		read_eventlog_job.configure_CM(MessageType.ALERT,
									   MessageSubType.DETECT,
									   [])

		read_eventlog_job.start()
		self.modules_list.append(read_eventlog_job)