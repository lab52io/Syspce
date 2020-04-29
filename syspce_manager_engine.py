import logging
import threading

from syspce_manager import Manager_
from syspce_message import *
from syspce_engine_filter import FilterEngine
from syspce_manage_tree import ManageTree
from syspce_engine_hierarchy import HierarchyEngine
from syspce_engine_baseline import BaselineEngine
from syspce_processes_tree import ProcessesTree

log = logging.getLogger('sysmoncorrelator')

class EngineManager(Manager_):

	def __init__(self, data_buffer_in, data_condition_in):

		Manager_.__init__(self, data_buffer_in,
					   data_condition_in)

		self.name = 'Engine Manager'
		self.module_id = Module.ENGINE_MANAGER
		self.messages_accepted = [MessageType.COMMAND, MessageType.DATAIN]
		self.hierarchy_engine_enabled = True
		self.baseline_engine_enabled = False

		self.processes_tree = ProcessesTree()


	def _process_messages(self, message_list):

		for message in message_list:
			
			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()

			elif message._subtype == MessageSubType.STOP_JOB:
				self.stop_job_modules(message._src)	
				
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
		self.add_working_module(src, [filter_event])

	def _detect(self, src, detection_rules, baseline_rules, macros, events):

		# adding more info to Sysmon events and deleting incorrect data
		self.processes_tree.pre_process_events(events)

		# add data to tree 
		manage_tree = ManageTree(self.data_buffer_in,
								 self.data_condition_in,
							     self.processes_tree, 
								 src)

		manage_tree.set_method(manage_tree.add_events_to_tree, events)
		manage_tree.start()

		self.add_working_module(src, [manage_tree])

		
		# Execute engines
		if self.hierarchy_engine_enabled:
			# Hierarchy Engine
			hierarchy_engine = HierarchyEngine(self.data_buffer_in,
											   self.data_condition_in,
											   self.processes_tree,
											   src,
											   detection_rules,
											   macros)

			hierarchy_engine.start()

			self.add_working_module(src, [hierarchy_engine])

		# Baseline Engine
		if self.baseline_engine_enabled:
			baseline_engine = BaselineEngine(self.data_buffer_in,
											 self.data_condition_in,
											 self.processes_tree,
											 src,
											 baseline_rules,
											 macros, events)

			baseline_engine.start()

			self.add_working_module(src, [baseline_engine])

