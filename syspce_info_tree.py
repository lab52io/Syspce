import threading
import logging
from time import sleep

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')

class InfoTree(threading.Thread):
    def __init__(self, data_buffer_in, data_condition_in,
				 src):

		threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in
		self._running = False
		self.name = ''
		self.module_id = -1
		self.origin = Module.ENGINE_MANAGER
		self.src = src
		
		# variable method threading
		self._target = None
		self._args = None


    def run(self):
		self._running = True
		if not self._target:
			log.error('Need to set method target first')
		else:
			self._target(*self._args)

		self.terminate()

    def set_method(self, target, *args):
		self._target = target
		self._args = args

    def send_message(self, content):

		message = Message(self.data_buffer_in, self.data_condition_in)
		message.send(MessageType.COMMAND_RES,
                     None,
                     self.module_id,
                     self.src,
					 self.origin,
					 [content])

    def terminate(self): 
		self._running = False
		log.debug("%s ending..." % (self.name))