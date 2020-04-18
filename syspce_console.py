# -*- coding: utf-8 -*-

import threading
import logging
import json
import readline
import os
import re
import pprint

from syspce_message import *
from syspce_output import Output_

log = logging.getLogger('sysmoncorrelator')

class Console(threading.Thread):
	def __init__(self, data_buffer_in,
					   data_condition_in):

		threading.Thread.__init__(self)
		self.data_buffer_in = data_buffer_in
		self.data_condition_in = data_condition_in
		self._running = False
		self.history_file = 'console_history.log'
		
		self.name = 'Console'
		self.module_id = Module.CONSOLE
		self.output = Output_(log)

	def run(self):
		self._running = True	
		log.debug("%s working..." % (self.name))
		# Command console initialitation

		readline.parse_and_bind('tab: complete')
		readline.set_history_length(100)

		if os.path.exists(self.history_file):
			readline.read_history_file(self.history_file)

		readline.set_completer(BufferAwareCompleter(
		{'run':['module'],
		 'help':['byname', 'bysize'],
		 'show':['commands', 'modules','info', 'options','attributes','results'],
		 'stop':['server'],
		 'get':['results'],
		 'clear':['options'],
		 'twitter':['usernames','nicks','mentions','hashtags','clients', 'coordinates'],
		 'emails':[],
		 'restart':['modules'],
		 'save':['session'],
		 'load':['session'],
		 'list':['sessions'],
		 'delete':['session'],
		 'set':['company_name', 'name','surname1','surname2','license_plate','NIF', 'email', 'twitter_user_nick','domain','site', 'ip', 'username','telephone','image_url'],
		 'unset':['company_name', 'name','surname1','surname2','license_plate','NIF', 'email', 'twitter_user_nick','domain','site', 'ip', 'username'],
		 'status':[],
		 'makedict':[],
		 'export':[],
		 'exit':[],
		 'quit':[],
		}).complete)





		while self._running:
			
		    try:
				command = unicode(raw_input("SYSPCE#>"), 'utf-8')
				
				readline.add_history(command)

		    except ValueError, e:
			    print "Error al introducir comando: %s" % str(e)
			    command = "exit"
			
		    #Logica de control de los comandos de la consola	
		    if (command == "run"): # ejecuta la busqueda con los inputs del usuario
				print 'run'			
			
		    elif(re.match("^run module", command)):
				print 'run module'
			
		    elif(("show commands" in command) or ("help" in command)):
			    print self.help()
			
		    elif(command == "show modules"): # muestra los modulos actuales
				print 'show results'

		    elif(command == "show results"): 
			    print 'show results'

		    elif(command == "exit"):
				readline.write_history_file(self.history_file)
				self.terminate()
				self.stop_all()
		    else:
				print command
				
		log.debug("%s terminated." % (self.name))

	def print_hola(self):
		readline.insert_text("Hola")
		readline.redisplay()
	def print_search_result(self, results):
		pprint.pprint(results)

	def print_alert_hierarchy(self, alerts):
		for alert in alerts:
			print alert

	def print_alert_baseline(self, alerts):
		print alerts

	def print_command_result(self, results):
		log.info("COMMANDS RES: %s" % results)

	def print_notification(self, results):
		log.info("NOTIFICATION RES: %s" % results)

	def help(self):

		return '''
		 ---------------------------------------------------------------------------------------------------
		|AYUDA                                                                                              |
		 ---------------------------------------------------------------------------------------------------
	 
		COMANDOS
		--------
		run 			- Ejecuta la busqueda con los parámetros establecidos
		run module [modulo] 	- Ejecuta un módulo en concreto
		help 			- Muestra esta ayuda
		show commands 		- Muestra esta ayuda
		show modules 		- Lista modulos disponibles
		stop server 		- Para el servidor de SERP
		show info		- Muestra información de la consola
		show info server 	- Muestra información del servidor
		show info [modulo]	- Muestra información del modulo
		show attributes		- Muestra el conjunto de posibles atributos de busqueda
		show options		- Muestra los atributos introducidos por el usuario
		show/get results	- Muestra los resultados obtenidos
		clear options		- Elimina todas las opciones configuradas
		set [atributo] [valor]	- Establece el valor de un atributo
		unset [atributo]	- Elimina un atributo
		status			- Informa del estado de ejecución de los modulos
		twitter usernames	- Lista los usuarios de Twitter de los resultados obtenidos
		twitter nicks		- Lista los niknames de Twitter de los resultados obtenidos
		twitter mentions	- Lista las manciones de Twitter de los resultados obtenidos
		twitter hashtags	- Lista los hashtags de Twitter de los resultados obtenidos
		twitter clients		- Lista las aplicaciones/clientes de Twitter utilizados por el usuario
		twitter coordinates	- Lista las coordenadas de posicionamiento de los Tweets del usuario
		emails			- Lista los emails de los resultados obtenidos
		restart modules		- Reinicia todos los modulos y elimina los resultados actuales
		save session [nombre]	- Guarda los resultados de la sesion actual
		load session [nombre]	- Carga una sesion anterior
		list sessions		- Muestra las sesiones guardadas
		delete session [nombre]	- Elimina una sesion del archivo
		export [nombre]		- Exporta los resultados a un fichero xml en el directorio de ejecución
		makedict		- Genera un diccionario tomado como fuente: contenido de webs, nicks y 
					usernames de twitter,correos electronicos o nombres de usuario (realizando
					permutaciones)
		exit|quit 		- Salida de la consola sin cerrar el server 
		'''

	def terminate(self): 
		self._running = False
		log.debug("%s ending..." % (self.name))

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


class BufferAwareCompleter(object):
    
    def __init__(self, options):
        self.options = options
        self.current_candidates = []
        return

    def complete(self, text, state):
        response = None
        if state == 0:
            # This is the first time for this text, so build a match list.
            
            origline = readline.get_line_buffer()
            begin = readline.get_begidx()
            end = readline.get_endidx()
            being_completed = origline[begin:end]
            words = origline.split()
            
            if not words:
                self.current_candidates = sorted(self.options.keys())
                #self.current_candidates = readline.get_history_items()
            else:
                try:
                    if begin == 0:
                        # first word
                        candidates = self.options.keys()

                    else:
                        # later word
                        first = words[0]
                        candidates = self.options[first]
                    
                    if being_completed:
                        # match options with portion of input
                        # being completed
                        self.current_candidates = [ w for w in candidates
                                                    if w.startswith(being_completed) ]
                    else:
                        # matching empty string so use all candidates
                        self.current_candidates = candidates

                except (KeyError, IndexError), err:
                    self.current_candidates = []
        
        try:
            response = self.current_candidates[state]
        except IndexError:
            response = None

        return response