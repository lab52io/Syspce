import threading
import logging
from time import sleep

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')

class Input(threading.Thread):
    def __init__(self, data_buffer_in, 
				 data_condition_in, src):

		threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in
		self._running = False
		self.name = ''
		self.module_id = -1


		# which command/module produced the creation of this 
		# input , who created the message, needed for returnig
		# the results.
		self.origin = Module.INPUT_MANAGER
		self.src = src
		# Event ID from sysmon eventlog that correlator supports.
		self.EVENTLOG_EVENTID = [1,2,3,5,7,8,9,10,11,12,13,
								14,15,17,18,22,100,101,102,103,108,110]
		
    def run(self):
		self._running = True

		self.do_action()

    def send_message(self, content):

		message = Message(self.data_buffer_in, self.data_condition_in)
		message.send(MessageType.DATAIN,
                     None,
                     self.module_id,
                     self.src,		#returning data to the source job
					 self.origin,
					 [content])

    def console_print(self, content):

		message = Message(self.data_buffer_in, self.data_condition_in)

		message.send(MessageType.COMMAND_RES,
                     None,
                     self.module_id,
                     Module.CONTROL_MANAGER,
					 self.origin,
					 ["\n\t["  + str(self.module_id) + "] " + content])	
		
    def do_action(self):
		# To be overridden
		pass
		
    def terminate(self): 
		self._running = False
		log.debug("%s ending..." % (self.name))

