# -*- coding: utf-8 -*-

import threading
import logging
import json
import os
import re
import pprint

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')

class Console(threading.Thread):
	def __init__(self, data_buffer_in,
					   data_condition_in,
					   output_lock):

		threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in

		self._running = False
		self.name = 'Console'
		self.module_id = Module.CONSOLE
		self.output_lock = output_lock

	def run(self):
		self._running = True	
		log.debug("%s working..." % (self.name))

		while self._running:
			
		    try:
				command = unicode(raw_input("SYSPCE#>"), 'utf-8')
		    except ValueError, e:
			    print "Input error: %s" % str(e)
			    command = "exit"
			
		    #Logica de control de los comandos de la consola	
		    if (command == "jobs"): # ejecuta la busqueda con los inputs del usuario
				self.jobs()	
			
		    elif(re.match("^run module", command)):
				self.s_print('run module')
			
		    elif(("show commands" in command) or ("help" in command)):
			    self.help()

		    elif(command == "exit"):
				self.terminate()
				self.stop_all()

				
		log.debug("%s terminated." % (self.name))

	## COMMAND METHODS
	##################
	def help(self):

		help = '''
		 ---------------------------------------------------------------------------------------------------
		|HELP                                                                                              |
		 ---------------------------------------------------------------------------------------------------
	 
		COMMANDS
		--------
		jobs 			- Show current active JObs
		help 			- List commads helps
		exit|quit 		- Bye bye. 
		'''
		self.s_print(help)

	def stop_all(self):

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

	## ADDITIONAL METHODS
	#####################

	def print_search_result(self, results):
		self.s_print(pprint.pformat(results))

	def print_alert_hierarchy(self, alerts):
		for alert in alerts:
			self.s_print(alert)

	def print_alert_baseline(self, alerts):
		self.s_print(alerts)

	def print_command_result(self, result):
		self.s_print(result)

	def print_notification(self, results):
		self.s_print("\nNOTIFICATION RES: %s" % results)

	# Safe print
	def s_print(self, string):
		self.output_lock.acquire()
		print string
		self.output_lock.release()

	def terminate(self): 
		self._running = False
		log.debug("%s ending..." % (self.name))