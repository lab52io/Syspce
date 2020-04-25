import logging

from syspce_input import Input
from syspce_input_evtx import InputEvtx
from syspce_input_eventlog import InputEventlog
from syspce_manager import Manager_
from syspce_message import *
from syspce_input_volatility import InputVolatility

log = logging.getLogger('sysmoncorrelator')

class InputManager(Manager_):

    def __init__(self, data_buffer_in, data_condition_in):

		Manager_.__init__(self, data_buffer_in,
					   data_condition_in)

		self.name = 'Input Manager'
		self.module_id = Module.INPUT_MANAGER
		self.messages_accepted = [MessageType.COMMAND]       
 
    def _process_messages(self, message_list):
		for message in message_list:

			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()

			elif message._subtype == MessageSubType.STOP_JOB:
				self.stop_job_modules(message._src)

			elif message._subtype == MessageSubType.READ_FROM_FILE:
				self._read_evtx( message._src, 
								message._content[0],
								message._content[1])

			elif message._subtype == MessageSubType.READ_FROM_EVENTLOG:
				self._read_eventlog(message._src,
									message._content[0])

			elif message._subtype == MessageSubType.READ_FROM_MEMDUMP:
				self._read_memdump(message._src,
								   message._content[0],
								   message._content[1])

    def _read_evtx(self, src, filepath, schema):
		input_evtx = InputEvtx(self.data_buffer_in,
							   self.data_condition_in,
							   src,
							   filepath,
							   schema)
		input_evtx.start()
		self.add_working_module(src, [input_evtx])

    def _read_eventlog(self, src, schema):
		input_eventlog = InputEventlog(self.data_buffer_in,
									   self.data_condition_in,
									   src,
									   schema)
		input_eventlog.start()
		self.add_working_module(src, [input_eventlog])

    def _read_memdump(self, src, memdump, profile):

		input_memdump = InputVolatility(self.data_buffer_in,
										self.data_condition_in,
										src, memdump,profile)
		input_memdump.start()
		
		self.add_working_module(src, [input_memdump])
