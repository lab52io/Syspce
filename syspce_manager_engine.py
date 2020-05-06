import logging
import threading
from time import sleep

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
		self.daemon_ = False

		self.processes_tree = ProcessesTree()


	def _process_messages(self, message_list):

		for message in message_list:
			
			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()

			elif message._subtype == MessageSubType.STOP_JOB:
				#Stoping a daemon job
				if self.daemon_module_executing(message._src):
					self.daemon_ = False
				self.stop_job_modules(message._src)

			elif message._subtype == MessageSubType.STATS:
				self._stats(message._src)	

			elif message._subtype == MessageSubType.SET_CONFIG:
				# message._content[0] config to set, message._content[1] value
				if message._content[0][0] == "hierarchy_engine_enabled":
					self.hierarchy_engine_enabled =  message._content[0][1]
				elif message._content[0][0] == "baseline_engine_enabled":
					self.baseline_engine_enabled = message._content[0][1]


			# Filter engine, filter data from user
			elif message._subtype == MessageSubType.FILTER_DATA:

				self._filter_events(message._src,
									message._content[0],	#search filter
									message._content[1],	#search attributes
									message._content[2])	#data 

			# insert events to processes tree and start detection engines
			# but not in daemon mode, it dies after do the jobs
			elif message._subtype == MessageSubType.DETECT_SINGLE:

				self._detect_single(message._src,
							 message._content[0],	#detection.rules
							 message._content[1],	#baseline.rules
							 message._content[2],	#detection.macros 
							 message._content[3])	#data

			# insert events to processes tree and start detection engines
			# using daemon mode, engines are executing always
			elif message._subtype == MessageSubType.DETECT_DAEMON:

				self._detect_daemon(message._src,
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

	def _stats(self, src):
		# getting statistics  
		manage_tree = ManageTree(self.data_buffer_in,
								 self.data_condition_in,
							     self.processes_tree, 
								 src)

		manage_tree.set_method(manage_tree.get_ptree_stats_str)
		manage_tree.start()

		self.add_working_module(src, [manage_tree])


	def _detect_daemon(self, src, detection_rules, baseline_rules, macros, events):

		# add data to tree 
		manage_tree = ManageTree(self.data_buffer_in,
								 self.data_condition_in,
							     self.processes_tree, 
								 src)

		manage_tree.set_method(manage_tree.add_events_to_tree, events)
		manage_tree.start()

		self.add_working_module(src, [manage_tree])
		
		# Check if is already in daemon mode, don't create new intances
		if not self.daemon_:
			# dont like this sync, TODO
			sleep(1)
			# Execute engines
			if self.hierarchy_engine_enabled:

				# Hierarchy Engine
				hierarchy_engine = HierarchyEngine(self.data_buffer_in,
												   self.data_condition_in,
												   self.processes_tree,
												   src,
												   detection_rules,
												   macros, True)

				hierarchy_engine.start()

				self.add_working_module(src, [hierarchy_engine])

		self.daemon_ = True

		# dont like this sync, TODO
		sleep(1)

		# Baseline Engine
		if self.baseline_engine_enabled:
			baseline_engine = BaselineEngine(self.data_buffer_in,
												self.data_condition_in,
												self.processes_tree,
												src,
												baseline_rules,
												macros, events, True)

			baseline_engine.start()

			self.add_working_module(src, [baseline_engine])

		

	def _detect_single(self, src, detection_rules, baseline_rules, macros, events):



		# add data to tree 
		manage_tree = ManageTree(self.data_buffer_in,
								 self.data_condition_in,
							     self.processes_tree, 
								 src)

		manage_tree.set_method(manage_tree.add_events_to_tree, events)
		manage_tree.start()

		self.add_working_module(src, [manage_tree])
		
		# dont like this sync, TODO
		sleep(1)

		# Execute engines
		if self.hierarchy_engine_enabled:

			# Hierarchy Engine
			hierarchy_engine = HierarchyEngine(self.data_buffer_in,
												self.data_condition_in,
												self.processes_tree,
												src,
												detection_rules,
												macros,False)

			hierarchy_engine.start()

			self.add_working_module(src, [hierarchy_engine])

		# dont like this sync, TODO
		sleep(1)

		# Baseline Engine
		if self.baseline_engine_enabled:
			baseline_engine = BaselineEngine(self.data_buffer_in,
												self.data_condition_in,
												self.processes_tree,
												src,
												baseline_rules,
												macros, events, False)

			baseline_engine.start()

			self.add_working_module(src, [baseline_engine])