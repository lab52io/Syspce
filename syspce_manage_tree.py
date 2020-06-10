import logging
import pprint
from datetime import datetime

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

	def info_eventid(self, pid, eventid, computer):
		ptree = self.processes_tree.processes_tree

		with self.processes_tree.tree_condition_in:
			if not computer or not ptree.has_key(computer):
				clist = ptree.keys()
			else:
				clist = [computer]
			try:
				info_events = ''
				for host in clist:
					for process in ptree[host]:
						if ptree[host][process].pid == pid:
							for action in ptree[host][process].acciones[eventid]:
								info_events += '\n'+ pprint.pformat(action)
								info_events += '\n'
				if not info_events:
					self.send_message('\nNot found')
				else:
					self.send_message(info_events)

			except Exception, e:
				print str(e)
				self.send_message("Command Error %s" % e)

			self.processes_tree.tree_condition_in.notify_all()

	def ps(self, tree_id, computer):
		tree_id_list = {}
		pt = self.processes_tree.processes_tree
		tree_id = int(tree_id)

		with self.processes_tree.tree_condition_in:
			# We need here to identify diferent process tree boot sessions
			#getting first process detected by sysmon (smss.exe)
			for host in pt:
				tree_id_list[host] = []

				for processGuid in pt[host]:
					process = pt[host][processGuid].acciones['1'][0]

					if '\\system32\\smss.exe' in process['CommandLine'].lower() and \
					  'system' == process['ParentImage'].lower():

						smss_time = datetime.strptime(process['UtcTime'], 
													 '%Y-%m-%d %H:%M:%S.%f')
						tree_id_list[host].append(smss_time)

				tree_id_list[host].sort()
			
			# Case only 1 machine and 1 session
			if len(pt) == 1 and len(tree_id_list[host]) == 1:
				computer = host
				tree_id = 0

			if tree_id >=0 and computer:
				res_str = '\n\n\t------------ PROCESS LIST ---------\n'
			else:
				res_str = '\n\n\t------------ BOOT SESSIONS LIST ---------\n'

			# If user already provided a session ID lets find all processes
			#created in this session. Using first creation smss.exe we know 
			#all processes that belongs to a boot session
			if tree_id_list.has_key(computer) and  tree_id >=0 and \
			   tree_id < len(tree_id_list[computer]):
				logon_sessions = []
				process_list = []

				# Let's find all processes created between 2 smss.exe instances
				#so first we determine init and final dates
				try:
					datetime_ini = tree_id_list[computer][tree_id]

					if (tree_id + 1) == len(tree_id_list[computer]):
						datetime_end = datetime.strptime("2120-02-19 17:36:40",
														  '%Y-%m-%d %H:%M:%S')
					else:
						datetime_end = tree_id_list[computer][tree_id + 1]

				except Exception, e:
					self.send_message('\n\t\t%s\n' % str(e))

				# Now get only process between init and end timestamps
				for processGuid in pt[computer]:
					p_1 = pt[computer][processGuid].acciones['1'][0]
					str_t = p_1['UtcTime']
					logon_t = datetime.strptime(str_t, '%Y-%m-%d %H:%M:%S.%f')

					# Current process belongs to User's selected session
					if logon_t >= datetime_ini and logon_t <= datetime_end:
						process_list.append(pt[computer][processGuid])

				formated_plist = self.pslist(process_list)

				if formated_plist:
					self.send_message(formated_plist)
				else:
					self.send_message('\n\t\tNo processes found\n')
		
			# No Session id provided so let's list all avaiable sessions 
			else:
				for host in tree_id_list:
					res_str += '\tComputer %s \n' % (host)

					if tree_id_list[host]:
						for i, tree_id in enumerate(tree_id_list[host]):
							res_str += '\t\t[%d] Boot time %s\n' % \
									(i, tree_id_list[host][i])
					else:
						res_str +='\t\tNo smss.exe processes found\n'

				self.send_message(res_str)

			self.processes_tree.tree_condition_in.notify_all()

	def pslist(self, process_list):
		str_res = '\n\tName\t\t\t\tPID\tPPID\tStart\t\t\t\t'
		str_res += 'ProcessTTL         CreationType\n'
		str_res += '\t------------------------------- '
		str_res += '------  '
		str_res += '------  '
		str_res += '-------------------------       '
		str_res += '----------------   '
		str_res += '---------------\n'
		for process in process_list:
			p_1 = process.acciones['1'][0]
			str_res += '\t' + process.ImageFileName
			str_res += (' ')*(32-(len(process.ImageFileName)))
			str_res += p_1['ProcessId'] + '\t'
			str_res += p_1['ParentProcessId'] + '\t'
			str_res += p_1['UtcTime'] + '\t\t'
			str_res += p_1['ProcessTTL'] + (' ')*(19-(len(p_1['ProcessTTL'])))
			str_res += p_1['CreationType'] + '\t\t\n'
		return str_res

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




