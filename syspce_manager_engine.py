import logging
import threading

from syspce_manager import Manager_
from syspce_message import *
from syspce_engine_filter import FilterEngine
from syspce_manage_tree import ManageTree
from syspce_engine_hierarchy import HierarchyEngine
from syspce_engine_baseline import BaselineEngine

log = logging.getLogger('sysmoncorrelator')

class EngineManager(Manager_):

    def __init__(self, data_buffer_in, data_condition_in):

		Manager_.__init__(self, data_buffer_in,
					   data_condition_in)

		self.name = 'Engine Manager'
		self.module_id = Module.ENGINE_MANAGER
		self.messages_accepted = [MessageType.COMMAND, MessageType.DATAIN]
		self.hierarchy_engine_enabled = True
		self.baseline_engine_enabled = True

		self.processes_tree = {}
		self.tree_condition_in = threading.Condition()


    def _process_messages(self, message_list):

		for message in message_list:
			
			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()
			
			# Filter engine, filter data from user
			elif message._subtype == MessageSubType.FILTER_DATA:

				self._filter_events(message._src,
									message._content[0],	#search filter
									message._content[1],	#search attributes
									message._content[2])	#data 

			# insert events to processes tree and start detection engines
			elif message._subtype == MessageSubType.DETECT:

				self._detect(message._src,
							 message._content[0],	#detection.rules
							 message._content[1],	#baseline.rules
							 message._content[2],	#detection.macros 
							 message._content[3])	#data

    def _filter_events(self, src, search_filter, filter_attribute, events):

		filter_event = FilterEngine(self.data_buffer_in,
							   self.data_condition_in,
							   src,
							   search_filter,
							   filter_attribute,
							   events)

		filter_event.start()
		self.modules_list.append(filter_event)

    def _detect(self, src, detection_rules, baseline_rules, macros, events):
		# add data to tree 
		manage_tree = ManageTree(self.data_buffer_in,
								 self.data_condition_in,
							     self.processes_tree, 
								 self.tree_condition_in,
								 src)

		manage_tree.set_method(manage_tree.add_events_to_tree, events)
		manage_tree.start()

		self.modules_list.append(manage_tree)


		# Execute engines

		# Hierarchy Engine
		hierarchy_engine = HierarchyEngine(self.data_buffer_in,
							   self.data_condition_in,
							   self.processes_tree,
							   self.tree_condition_in,
							   src,
							   detection_rules,
							   macros)

		hierarchy_engine.start()

		self.modules_list.append(hierarchy_engine)

		# Baseline Engine

		baseline_engine = BaselineEngine(self.data_buffer_in,
							   self.data_condition_in,
							   self.processes_tree,
							   self.tree_condition_in,
							   src,
							   baseline_rules,
							   macros, events)

		baseline_engine.start()

		self.modules_list.append(baseline_engine)



