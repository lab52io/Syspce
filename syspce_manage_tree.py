import logging

from syspce_info_tree import InfoTree
from syspce_message import *
from syspce_parser import get_action_from_id

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
			# adding more info to Sysmon events and deleting incorrect data
			self.processes_tree.pre_process_events(list_of_events)

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


	def get_ptree_stats_str(self):
		if self.processes_tree.stats:
			stats = '\n\n\t------------ ENGINES STATISTICS ---------\n'
		else:
			stats = '\nNo stats yet, reading data...\n'

		for computer in self.processes_tree.stats:
			stats += '\n\tStats for hostname ' + computer + '\n\n'

			stats += '\t\tActions stats:\n'
			for id in self.processes_tree.stats[computer]['Actions']:
				
				if id == '1':
					action_name = '[A] PROCESS CREATED'
				else:

					action_name = get_action_from_id(int(id))

				stats += '\t\t\t(' + id + ')\t' + action_name + ': ' 
				stats += str(self.processes_tree.stats[computer]['Actions'][id])
				stats += '\n'

			stats += '\n\t\tRules execution stats:\n'
			total_exec_time = 0
			total_rules = 0

			for rule in self.processes_tree.stats[computer]['RulesExecTime']:
				total_exec_time += self.processes_tree.stats[computer]['RulesExecTime'][rule]
				total_rules += 1

				stats += '\t\t\t' + str(rule) + ': ' 
				stats += str(self.processes_tree.stats[computer]['RulesExecTime'][rule])
				stats += ' seconds\n'

			stats += '\t\tOther stats:\n'
			for stat in self.processes_tree.stats[computer]:
				# skip actions list
				if stat != 'Actions' and stat != 'RulesExecTime':
					stats += '\t\t\t' + stat + ':\t'
					stats += str(self.processes_tree.stats[computer][stat])
					stats += '\n'

			stats += '\t\t\tTotalRulesTime: ' + str(total_exec_time) + ' seconds\n'
			stats += '\t\t\tTotalRules: ' + str(total_rules)
			stats += '\n'

		self.send_message(stats)




