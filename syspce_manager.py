import threading
import logging

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')


class Manager_(threading.Thread):
	def __init__(self, data_buffer_in, data_condition_in):
		threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in
		self.modules_list = []

		self._running = False

		# to be set by the subclass
		self.name = ''
		self.module_id = None
		self.messages_accepted = []

	def run(self):
		self._running = True	
		log.debug("%s ready" % (self.name))

		while self._running:
			with self.data_condition_in:
				messages = self._read_messages(self.data_buffer_in)
				while not messages:
					log.debug("%s - Wainting for commands/data " % (self.name))
					self.data_condition_in.wait()
					messages = self._read_messages(self.data_buffer_in)
			self._process_messages(messages)

		log.debug("%s terminated." % (self.name))


	def _read_messages(self, data_buffer_in):
		message_list = []

		# checking if this message is for me
		len_buffer = len(data_buffer_in)
		i = 0

		while i != len_buffer:
			message = data_buffer_in[i]

			if (message._dst == self.module_id) and \
			    (message._type in self.messages_accepted):

				# it's mine , let's pop it
				message_list.append(data_buffer_in.pop(i))
				len_buffer -= 1
			else:
				i += 1

		return message_list

	def _process_messages(self, message_list):
		# To be implemented by the subclass
		pass

	def add_working_module(self, module, job):
		pass
		#self.modules_list.append({job:[module]})

	def _terminate(self): 
		for module in self.modules_list:
			if module.is_alive():
				module.terminate()
				module.join()

		self._running = False


