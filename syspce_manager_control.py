import logging
from time import sleep
import threading
import json

from syspce_manager import Manager_
from syspce_message import *
from syspce_job import Job
from syspce_parser import get_sysmon_xml_schema
#from syspce_console import Console


log = logging.getLogger('sysmoncorrelator')

class ControlManager(Manager_):

    def __init__(self, data_buffer_in, data_condition_in,
				 console, output_lock, args):

		Manager_.__init__(self, data_buffer_in,
					   data_condition_in)

		self.name = 'Control Manager'
		self.module_id = Module.CONTROL_MANAGER
		self.messages_accepted = [MessageType.COMMAND, 
								  MessageType.ALERT,
								  MessageType.COMMAND_RES,
								  MessageType.DATAIN]  
		
		self.console = console
		self.output_lock = output_lock
		self.args = args
		self.config_ = {'sysmon_schema':'sysmonSchema3.4.xml',
						'sysmon_schema_content':{},
                        'detection_rules' : 'detection.rules',
                        'detection_macros' : 'detection.macros',
                        'baseline_rules' : 'baseline.rules',
                        'detection_rules_content' : {},
                        'detection_macros_content' : {},
                        'baseline_rules_content' : {},
                        'daemon': False,
                        'evtx_file' : '',
                        'memdump' : '',
                        'profile' : '',
                        'search_filter' : {},
                        'filter_attribute' : '',
                        'baseline_engine_enabled' : False,
						'hierarchy_engine_enabled' : True
                        }

		self.parse_args()
		self.do_jobs()

		'''
		# Console printing sync
		self.output_lock = threading.Lock()

		self.console = Console(data_buffer_in, data_condition_in, 
							   self.output_lock)
		self.console.start()

		# Let's registre which modules are working, 
		# needed later for stop them 
		self.add_working_module(self.console.name, [self.console])
		'''
    def _process_messages(self, message_list):
		for message in message_list:

			### MANAGEMENT
			# Ending and closing all
			if message._subtype == MessageSubType.TERMINATE:
				self._terminate()

			### CONSOLE/NETWORK COMMANDS
			# Read from a evtx user command
			elif message._subtype == MessageSubType.READ_FROM_FILE:
				self.read_evtx(message._content[0],
							   message._content[1], message._origin)

			# Run actions configured in conf
			elif message._subtype == MessageSubType.RUN:
				self.do_jobs()

			# Read memory from volatility module user command
			elif message._subtype == MessageSubType.READ_FROM_MEMDUMP:
				self.read_memdump(message._content[0],
								  message._content[1], message._origin)

			# List active Jobs
			elif message._subtype == MessageSubType.SHOW_JOBS:
				self.show_jobs(message._origin)

			# List active config
			elif message._subtype == MessageSubType.SHOW_CONFIG:
				self.show_config(message._origin)

			# Show statistics
			elif message._subtype == MessageSubType.STATS:
				self.send_message(Module.ENGINE_MANAGER, MessageSubType.STATS,
								  message._origin, [])

			# List active Jobs
			elif message._subtype == MessageSubType.STOP_JOB:
				self.stop_job(message._content[0], message._origin)

			# Show eventid
			elif message._subtype == MessageSubType.INFO_EVENTID:
				self.send_message(Module.ENGINE_MANAGER,
								  MessageSubType.INFO_EVENTID,
								  message._origin, [message._content[0], 
													message._content[1],
													message._content[2]])


			# Sets program configuration parameters
			elif message._subtype == MessageSubType.SET_CONFIG:
				if self.config_.has_key(message._content[0]):
					if message._content[1].lower() == "true" or \
					   message._content[1].lower() == "false":

						message._content[1] = str2bool(message._content[1])

					self.config_[message._content[0]] = message._content[1]
					self.console.print_command_result("\nConfig updated")
				else:
					self.console.print_command_result("\nError setting config")

			### ENGINES RESULTS
			# Results from a eventlog/evtx search user command
			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.FILTER_ENGINE:
				self.console.print_search_result(message._content[0])


			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.HIERARCHY_ENGINE:
				self.console.print_alert_hierarchy(message._content[0])

			elif message._type == MessageType.ALERT and \
				 message._subtype == MessageSubType.DETECT and \
				 message._src == Module.BASELINE_ENGINE:
				self.console.print_alert_baseline(message._content[0])

			elif message._type == MessageType.COMMAND_RES:
				self.console.print_command_result(message._content[0])

    def read_evtx(self, filepath, detection_rules,
				  detection_macros,  baseline_rules,
				  schema, origin):

		read_evtx_job = Job(self.data_buffer_in, 
							self.data_condition_in,
							JobType.SINGLE_ACTION,
							MessageSubType.READ_FROM_FILE,
							origin)

		read_evtx_job.configure_IM(MessageType.COMMAND,
								   MessageSubType.READ_FROM_FILE,
								   [filepath, schema])

		read_evtx_job.configure_EM(MessageType.DATAIN,
								   MessageSubType.DETECT_SINGLE,
								   [detection_rules, baseline_rules,
									detection_macros])

		read_evtx_job.configure_CM(MessageType.ALERT,
								   MessageSubType.DETECT,
								   [])

		read_evtx_job.start()
		self.add_working_module(read_evtx_job.name, [read_evtx_job])

    def read_memdump(self, filepath, profile,  detection_rules,
				     detection_macros,  baseline_rules,
				     origin):

		read_memdump_job = Job(self.data_buffer_in, 
							   self.data_condition_in,
							   JobType.SINGLE_ACTION,
							   MessageSubType.READ_FROM_MEMDUMP,
							   origin)

		read_memdump_job.configure_IM(MessageType.COMMAND,
								      MessageSubType.READ_FROM_MEMDUMP,
								      [filepath, profile])

		read_memdump_job.configure_EM(MessageType.DATAIN,
								      MessageSubType.DETECT_SINGLE,
								      [detection_rules, baseline_rules,
									  detection_macros])

		read_memdump_job.configure_CM(MessageType.ALERT,
								      MessageSubType.DETECT,
								      [])

		read_memdump_job.start()
		self.add_working_module(read_memdump_job.name, [read_memdump_job])

    def search_event(self, filepath, schema, 
					 search_filter, filter_attribute, origin):

		search_event_job = Job(self.data_buffer_in,
							   self.data_condition_in,
							   JobType.SINGLE_ACTION,
							   MessageSubType.FILTER_DATA,
							   origin)

		search_event_job.configure_IM(MessageType.COMMAND,
									  MessageSubType.READ_FROM_FILE,
									  [filepath, 
									   schema])

		search_event_job.configure_EM(MessageType.DATAIN,
									  MessageSubType.FILTER_DATA, 
									  [search_filter,
									   filter_attribute])

		search_event_job.configure_CM(MessageType.DATAIN,
							          MessageSubType.FILTER_DATA,
									  [])

		search_event_job.start()
		self.add_working_module(search_event_job.name, [search_event_job])

    def read_eventlog(self, detection_rules,
					  detection_macros,  baseline_rules,
					  schema, origin):

		read_eventlog_job = Job(self.data_buffer_in, 
								self.data_condition_in,
								JobType.DAEMON,
								MessageSubType.READ_FROM_EVENTLOG,
								origin)

		read_eventlog_job.configure_IM(MessageType.COMMAND,
									   MessageSubType.READ_FROM_EVENTLOG,
									   [schema])

		read_eventlog_job.configure_EM(MessageType.DATAIN,
									   MessageSubType.DETECT_DAEMON,
									   [detection_rules, baseline_rules,
										detection_macros])

		read_eventlog_job.configure_CM(MessageType.ALERT,
									   MessageSubType.DETECT,
									   [])

		read_eventlog_job.start()
		self.add_working_module(read_eventlog_job.name, [read_eventlog_job])

    def show_jobs(self, origin):
		result = ""

		for job_name in self.modules_list:
			m = self.modules_list[job_name][0]

			if "Job_" in job_name:
				result += "\n\t" +  job_name + "\n"
				result += "\t\tJob running:\t" + str(m._running) + "\n"
				result += "\t\tIM job done:\t" + str(m.IM_job_done) + "\n"
				result += "\t\tEM job done:\t" + str(m.EM_job_done) + "\n"
				result += "\t\tType:\t" + str(m.job_type).split(".")[1] + "\n"
				result += "\t\tTask:\t" + str(m.task_type).	split(".")[1] + "\n"
		if not result:
			result += "\n\t No jobs running"

		self.console.print_command_result(result)

    def show_config(self, origin):
		result = "\n"

		for element in self.config_:
			if element == 'detection_rules_content' or \
			   element == 'detection_macros_content' or \
			   element == 'sysmon_schema_content' or \
			   element == 'baseline_rules_content':
				content = 'Too long'
			else:
				content = self.config_[element]

			result += "\t" + element + ": " + str(content) + "\n"


		self.console.print_command_result(result)

    def stop_job(self, job_name, origin):
		''' Sends a stop order to the Job by Job_name'''

		job = None

		for module_name in self.modules_list:
			if job_name == module_name:
				job = self.modules_list[module_name][0]

		if job:
			self.send_message(job.name, MessageSubType.STOP_JOB,
							  origin, [])

			#del self.modules_list[job_name]

			self.console.print_command_result("\n\t" + job_name + " stopped")
		else:
			self.console.print_command_result("\n\t" + job_name + " not found")


    def do_jobs(self):
		
		error = False

		#configure engines Enable/disable
		self.send_message(Module.ENGINE_MANAGER ,
						  MessageSubType.SET_CONFIG,
						  Module.CONTROL_MANAGER,
						  ['baseline_engine_enabled',
							self.config_['baseline_engine_enabled']
						  ])

		# Setting schema version
		self.config_['sysmon_schema_content'] = get_sysmon_xml_schema(
                                                self.config_['sysmon_schema'])
		log.info("Using schema " + self.config_['sysmon_schema'] + \
				 " for log parsing")

		 #Cheking correct parsing
		if len(self.config_['sysmon_schema_content']) == 0:
			log.error("Can't parse Sysmon Schema file, using default 3.4")
			error = True

		if self.config_['search_filter']:
			try:
				filter = eval(self.config_['search_filter'])
				self.config_['search_filter'] = filter
			except Exception, e:
				log.error("Search filter incorrect:  %s" % e)
				error = True

		if not error:

			if self.config_['memdump'] and self.config_['profile']:
				self.read_memdump(self.config_['memdump'],
								  self.config_['profile'],
								  self.config_['detection_rules_content'],
								  self.config_['detection_macros_content'],
								  self.config_['baseline_rules_content'],
								  Origin.SYSPCE_CORE)

			if self.config_['search_filter']:
				self.search_event(self.config_['evtx_file'],
										  self.config_['sysmon_schema_content'],
										  self.config_['search_filter'],
										  self.config_['filter_attribute'],
										  Origin.SYSPCE_CORE)

			if self.config_['evtx_file'] and not self.config_['search_filter']:
				self.read_evtx(self.config_['evtx_file'],
										  self.config_['detection_rules_content'],
										  self.config_['detection_macros_content'],
										  self.config_['baseline_rules_content'],
										  self.config_['sysmon_schema_content'],
										  Origin.SYSPCE_CORE)

			if self.config_['daemon']:
				self.read_eventlog(self.config_['detection_rules_content'],
											  self.config_['detection_macros_content'],
											  self.config_['baseline_rules_content'],
											  self.config_['sysmon_schema_content'],
											  Origin.SYSPCE_CORE)
			'''
			# REading from eventlog only 1 time
			else:
				self.read_evtx('',
							   self.config_['detection_rules_content'],
							   self.config_['detection_macros_content'],
							   self.config_['baseline_rules_content'],
							   self.config_['sysmon_schema_content'],
							   Origin.SYSPCE_CORE)
			'''
		else:
			self.console.print_command_result("Config error, check logfile")

    def parse_args(self):


	    # Configuring Schema version for parser default 3.4
        if self.args.schema:
            self.config_['sysmon_schema'] = self.args.schema[0]

		# Loading rules file
        if self.args.rules:
            self.config_['detection_rules'] = self.args.rules[0]

        try:
           with open(self.config_['detection_rules']) as json_rules:
               self.config_['detection_rules_content'] = json.load(json_rules)

        except Exception, e:
            log.error("Opening or parsing rules file:  %s" % e)
            exit(1)

        json_rules.close()

	    # Loading rules macros
        try:
            with open(self.config_['detection_macros']) as json_macros:
                self.config_['detection_macros_content'] = json.load(json_macros)[0]

        except Exception, e:
            log.error("Opening or parsing macros rules file:  %s" % e)
            exit(1)	

        json_macros.close()

	    # Loading baseline rules
        try:
            with open(self.config_['baseline_rules']) as json_baseline:
                self.config_['baseline_rules_content'] = json.load(json_baseline)[0]

        except Exception, e:
            log.error("Opening or parsing baseline rules file:  %s" % e)
            exit(1)
        
        json_baseline.close()

        # Daemon mode for eventlog continous read
        if self.args.daemon:
            self.config_['daemon'] = True

        # Evtx file search filter functionality
        if self.args.eventid:
			self.config_['search_filter'] = self.args.eventid[0]

        # Evtx file
        if self.args.file:
            self.config_['evtx_file'] = self.args.file[0]

        # Evtx file search filter subfilter 
        if self.args.attribute:
            self.config_['filter_attribute'] = self.args.attribute[0]

        # Memdump
        if self.args.memdump:
            self.config_['memdump'] = self.args.memdump[0]

        # Memedump profile
        if self.args.profile:
            self.config_['profile'] = self.args.profile[0]

        # Memedump profile
        if self.args.baseline:
            self.config_['baseline_engine_enabled'] = True

def str2bool(v):
	return v.lower() in ("yes", "true", "t", "1")