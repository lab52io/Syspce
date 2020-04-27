# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import threading
import logging
import json
import os
import re
import pprint
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import CompleteStyle, prompt

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')


#class Console(threading.Thread):
class Console(object):
	''' Console user module '''

	def __init__(self, data_buffer_in,
					   data_condition_in,
					   output_lock, config):

		#threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in

		self._running = False
		self.name = 'Console'
		self.module_id = Module.CONSOLE
		self.output_lock = output_lock	
		self.config = config
		self.console_history = FileHistory('history.dat')
		self.session = PromptSession(history=self.console_history,
									 auto_suggest=AutoSuggestFromHistory(),
									 enable_history_search=True)

		self.syspce_completer = WordCompleter(
				[
					"run",
					"jobs",
					"stop_job",
					"show_config",
					"show_alerts",
					"exit",
				],
				meta_dict={
					"run": "It keeps on monitoring Sysmon log from Eventlog",
					"jobs": "Show current active Jobs",
					"stop_job": "Stops a Job by job name",
					"show_config": "Show current config",
					"show_alerts": "Show alerts detected",
					"exit": "Bye bye",
				},
				ignore_case=True,
				)

	def run(self):
		''' Thread console main code'''

		self._running = True	
		log.debug("%s working..." % (self.name))

		while self._running:
			
		    try:
				#command = unicode(raw_input("SYSPCE#>"), 'utf-8')
				command = self.session.prompt('SYSPCE#>',
								completer=self.syspce_completer,
								complete_style=CompleteStyle.MULTI_COLUMN)

		    except ValueError, e:
			    print "Input error: %s" % str(e)
			    command = "exit"
			
		    #Logica de control de los comandos de la consola	
		    if (command == "jobs"): # ejecuta la busqueda con los inputs del usuario
				self.jobs()	
		
		    elif(re.match("^run", command)):
				self.run_eventlog()
				self.s_print('Runnig sysmon eventlog events monitoring')
			
		    elif(("show commands" in command) or ("help" in command)):
			    self.help()

		    elif(re.match("^stop_job ", command)):
				try:
					job_name = command.split('stop_job ')[1].replace(' ','')
					self.job_stop(job_name)
				except Exception, e:
					self.s_print('Command error %s' % e)

		    elif(command == "exit" or command == "quit"):
				self.terminate()
				self.quit()

				
		log.debug("%s terminated." % (self.name))

	## COMMAND METHODS
	##################

	def help(self):
		''' Basic console help message'''

		help = '''
		 ---------------------------------------------------------------------------------------------------
		|HELP                                                                                              |
		 ---------------------------------------------------------------------------------------------------
	 
		COMMANDS
		--------
		jobs 			 - Show current active Jobs
		jobs stop [Name] - Stops a Job by job name
		help 			 - List commads helps
		exit|quit 		 - Bye bye. 
		'''
		self.s_print(help)

	def quit(self):
		''' Terminate all modules and program execution '''

		end_message = Message(self.data_buffer_in, self.data_condition_in)

		end_message.send(MessageType.COMMAND,
						 MessageSubType.TERMINATE,
						 Module.CONSOLE,
						 Module.ENGINE_MANAGER,
						 Module.CONSOLE,
						 [])

		end_message = Message(self.data_buffer_in, self.data_condition_in)

		end_message.send(MessageType.COMMAND,
						 MessageSubType.TERMINATE,
						 Module.CONSOLE,
						 Module.INPUT_MANAGER,
						 Module.CONSOLE,
						 [])

		end_message = Message(self.data_buffer_in, self.data_condition_in)

		end_message.send(MessageType.COMMAND,
						 MessageSubType.TERMINATE,
						 Module.CONSOLE,
						 Module.CONTROL_MANAGER,
						 Module.CONSOLE,
						 [])


	def jobs(self):
		''' List current active Jobs'''

		jobs_message = Message(self.data_buffer_in, self.data_condition_in)

		jobs_message.send(MessageType.COMMAND,
						  MessageSubType.SHOW_JOBS,
						  Module.CONSOLE,
						  Module.CONTROL_MANAGER,
						  Module.CONSOLE,
						  [])

	def run_eventlog(self):
		''' It keeps on monitoring Sysmon log from Eventlog'''

		jobs_message = Message(self.data_buffer_in, self.data_condition_in)

		jobs_message.send(MessageType.COMMAND,
						  MessageSubType.READ_FROM_EVENTLOG,
						  Module.CONSOLE,
						  Module.CONTROL_MANAGER,
						  Module.CONSOLE,
						  [self.config['detection_rules'],
						   self.config['detection_macros'],
						   self.config['baseline_rules'],
						   self.config['sysmon_schema'],
						  ])

	def job_stop(self, name):
		''' Stops a Job by name'''

		job_stop_message = Message(self.data_buffer_in, self.data_condition_in)

		job_stop_message.send(MessageType.COMMAND,
							  MessageSubType.STOP_JOB,
							  Module.CONSOLE,
							  Module.CONTROL_MANAGER,
							  Module.CONSOLE,
							  [name])
	## ADDITIONAL METHODS
	#####################

	def print_search_result(self, results):
		f = open('salida', 'a')
		f.write(pprint.pformat(results))
		f.close()
		#self.s_print(pprint.pformat(results))

	def print_alert_hierarchy(self, alerts):
		for alert in alerts:
			self.s_print(alert)

	def print_alert_baseline(self, alerts):
		self.s_print(alerts)

	def print_command_result(self, result):
		self.s_print(result)

	def print_notification(self, results):
		self.s_print("\nNOTIFICATION RES: %s" % results)

	def s_print(self, string):
		''' Safe print method avoiding collisions when printing out to
			console
		'''
		self.output_lock.acquire()
		print string
		self.output_lock.release()

	def terminate(self): 
		self._running = False
		log.debug("%s ending..." % (self.name))