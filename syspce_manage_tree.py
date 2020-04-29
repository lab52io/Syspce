import logging

from syspce_info_tree import InfoTree
from syspce_message import *


log = logging.getLogger('sysmoncorrelator')

class ManageTree(InfoTree):

	def __init__(self, data_buffer_in,
				 data_condition_in, 
				 processes_tree,
				 src):

		InfoTree.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		self.processes_tree = processes_tree

		self.name = 'Manage Tree'
		self.module_id = Module.MANAGE_TREE

	def add_events_to_tree(self, list_of_events):

		with self.processes_tree.tree_condition_in:
			i=0
			for event in list_of_events:
				node = self.processes_tree.add_event_to_tree(event)
				if node:
					i+=1
				if not self._running:
					break			
			self.processes_tree.tree_condition_in.notify_all()

		log.debug("Added %d all events to processes tree" % i)
		log.debug("%s %s terminated." % (self.name, self.ident))






