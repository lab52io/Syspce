# -*- coding: utf-8 -*-
'''                                                                                
   _____           _                             
  / ____|         | |                            
 | (___  _   _ ___| |_ ___ _ __ ___              
  \___ \| | | / __| __/ _ \ '_ ` _ \             
  ____) | |_| \__ \ ||  __/ | | | | |            
 |_____/ \__, |___/\__\___|_| |_| |_|            
          __/ |                                  
  _ __  _|___/__   ___ ___  ___ ___              
 | '_ \| '__/ _ \ / __/ _ \/ __/ __|             
 | |_) | | | (_) | (_|  __/\__ \__ \             
 | .__/|_|  \___/ \___\___||___/___/             
 | |                     | |     | |             
 |_|__ ___  _ __ _ __ ___| | __ _| |_ ___  _ __  
  / __/ _ \| '__| '__/ _ \ |/ _` | __/ _ \| '__| 
 | (_| (_) | |  | |_|  __/ | (_| | || (_) | |    
  \___\___/|_|  |_(_)\___|_|\__,_|\__\___/|_|    
   ___ _ __   __ _ _ _ __   ___                  
  / _ \ '_ \ / _` | | '_ \ / _ \                 
 |  __/ | | | (_| | | | | |  __/                 
  \___|_| |_|\__, |_|_| |_|\___|                 
              __/ |                              
             |___/                                                                       

 This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''


__version__ = '1.2.0'
__author__ = '@ramado78'
__contributors__ = '@J0SM1'

'''
- Date: 18/12/2019
- Bugs suggestions: ramado@s2grupo.es
- Web: https://lab52.io
'''

import threading
import logging
import argparse

import signal
from time import sleep

from syspce_console import Console

from syspce_message import *
from syspce_manager_input import InputManager
from syspce_manager_engine import EngineManager
from syspce_manager_control import ControlManager


class Syspce(object):

    def __init__(self):

        self.data_buffer_in = []

        self.console_buffer_in = []

        self.output_lock = threading.Lock()

        self.data_condition_in = threading.Condition()

        self.console_buffer_in = threading.Condition()

        self.args = []


    def parse_arguments(self):
        """Initialization Function"""
        global log

        parser = argparse.ArgumentParser()

        parser.add_argument("-p", "--profile",
                            nargs=1, 
                            metavar='Volatility profile',
                            help="Volatility memdump profile" )

        parser.add_argument("-m", "--memdump",
                            nargs=1,
                            help="Memdump",
                            metavar='Volatility memdump')

        parser.add_argument("-c", "--memcache",
                            nargs=1,
                            help="Memory dump Hash",
                            metavar='Memdump cache hash')

        parser.add_argument("-v", "--verbose", 
                            help="Verbose debug",
                            action="store_true")

        parser.add_argument("-d", "--daemon", 
                            help="Live detection",
                            action="store_true")

        parser.add_argument("-b", "--baseline", 
                            help="Baseline detection engine",
                            action="store_true")

        parser.add_argument("-r", "--rules", 
                            nargs=1, 
                            metavar='FileName',
                            help="Rules definition file")

        parser.add_argument("-f", "--file",
                            nargs=1, 
                            metavar='FileName',
                            help="File .evtx to process")

        parser.add_argument("-e", "--eventid",
                            nargs=1,
                            metavar='Dictionary',
					        help="Search for EventIDs or attributes as JSON filter")

        parser.add_argument("-a", "--attribute",
                            nargs=1, metavar='Attribute',
					        help="Show only an specific attribute when using -e option")

        parser.add_argument("-s", "--schema",
                            nargs=1,
                            metavar='FileName',
					        help="Sysmon schema xml file")

        parser.add_argument("-l", "--full_log", 
                            help="Full actions details of process chain",
						    action="store_true")

        parser.add_argument("-g", "--eventlog", 
                            help="Read local event log one time and generates alerts",
						    action="store_true")

        self.args = parser.parse_args()
    
        if self.args.verbose:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO

        
        logging.basicConfig(level=loglevel,
						    filename= 'syspce.log',
                            format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%d/%m/%Y %H:%M:%S ')
        '''

        logging.basicConfig(level=loglevel,
                            format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%d/%m/%Y %H:%M:%S ')
             
        '''
        
        log = logging



    def start(self):
        """Initialization Function"""

        
        console = Console(self.data_buffer_in, self.data_condition_in, 
							   self.output_lock)

        input_manager = InputManager(self.data_buffer_in,
                                     self.data_condition_in)
        input_manager.start()

        engine_manager = EngineManager(self.data_buffer_in,
                                       self.data_condition_in)
        engine_manager.start()

        control_manager = ControlManager(self.data_buffer_in,
                                         self.data_condition_in,
                                         console,
                                         self.output_lock,
                                         self.args)
        control_manager.start()

        #blocking call
        console.run()

        input_manager.join()
        engine_manager.join()
        control_manager.join()
        log.debug("SYSPCE_CORE ending...")


if __name__== "__main__":

    syspce = Syspce()
    syspce.parse_arguments()
    syspce.start()
    print "Thanks for using Syspce"
