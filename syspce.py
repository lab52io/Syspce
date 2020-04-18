# -*- coding: utf-8 -*-
'''                                                                                
  ___ _   _ ___ _ __ ___   ___  _ __                                                  
 / __| | | / __| '_ ` _ \ / _ \| '_ \                                                 
 \__ \ |_| \__ \ | | | | | (_) | | | |                                                
 |___/\__, |___/_| |_| |_|\___/|_| |_|_          _                 _                  
       __/ |                         | |        | |               (_)                 
  _ __|___/_ ___   ___ ___  ___ ___  | |__   ___| |__   __ ___   ___  ___  _   _ _ __ 
 | '_ \| '__/ _ \ / __/ _ \/ __/ __| | '_ \ / _ \ '_ \ / _` \ \ / / |/ _ \| | | | '__|
 | |_) | | | (_) | (_|  __/\__ \__ \ | |_) |  __/ | | | (_| |\ V /| | (_) | |_| | |   
 | .__/|_|  \___/ \___\___||___/___/ |_.__/ \___|_| |_|\__,_| \_/ |_|\___/ \__,_|_|   
 | |                     | |     | |                                                  
 |_|__ ___  _ __ _ __ ___| | __ _| |_ ___  _ __                                       
  / __/ _ \| '__| '__/ _ \ |/ _` | __/ _ \| '__|                                      
 | (_| (_) | |  | | |  __/ | (_| | || (_) | |                                         
  \___\___/|_|  |_|  \___|_|\__,_|\__\___/|_|                                         

 
 This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/> .
'''


__version__ = '1.2.0'
__author__ = '@ramado78'

'''
- Date: 18/12/2019
- Bugs suggestions: ramado@s2grupo.es
- Web: https://lab52.io
'''

import threading
import logging
import argparse
import json
import signal
from time import sleep

from syspce_parser import get_sysmon_xml_schema
from syspce_message import *
from syspce_manager_input import InputManager
from syspce_manager_engine import EngineManager
from syspce_manager_control import ControlManager

#python syspce.py -m file:///C:\Users\ramad\Desktop\josemi\cridex.vmem -p WinXPSP2x86

class Syspce(object):

    def __init__(self):

        self.data_buffer_in = []

        self.console_buffer_in = []

        self.data_condition_in = threading.Condition()

        self.console_buffer_in = threading.Condition()

        self.config_ = {'sysmon_schema':'',
                     'detection_rules' : {},
                     'detection_macros' : {},
                     'baseline_rules' : {},
                     'daemon': False,
                     'evtx_file' : '',
                     'memdump' : '',
                     'profile' : '',
                     'search_filter' : {},
                     'filter_attribute' : '',
                     'baseline_enabled' : ''
                     }

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



        args = parser.parse_args()
    
        if args.verbose:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO

        ''' 
        logging.basicConfig(level=loglevel,
						    filename= 'syspce.log',
                            format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%d/%m/%Y %H:%M:%S ')
        '''

        logging.basicConfig(level=loglevel,
                            format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%d/%m/%Y %H:%M:%S ')
       
        
        log = logging

	    # Configuring Schema version for parser default 3.4
        if args.schema:
            self.config_['sysmon_schema'] = get_sysmon_xml_schema(args.schema[0])
            log.info("Using schema " + args.schema[0] + " for log parsing")

        else:
            m = "Using default Sysmon config schema 3.4, this can afect log parsing"
            log.warning(m)
            self.config_['sysmon_schema'] = get_sysmon_xml_schema('sysmonSchema3.4.xml')

	    #Cheking correct parsing
        if len(self.config_['sysmon_schema']) == 0:
            log.error("Can't parse Sysmon Schema file")
            exit(1)

	    # Loading rules file
        if args.rules:
            rules_file = args.rules[0]
        else:
            rules_file = 'detection.rules'

        try:
           with open(rules_file) as json_rules:
                self.config_['detection_rules'] = json.load(json_rules)

        except Exception, e:
            log.error("Opening or parsing rules file:  %s" % e)
            exit(1)

        json_rules.close()

	    # Loading rules macros
        try:
            with open('detection.macros') as json_macros:
                self.config_['detection_macros'] = json.load(json_macros)[0]

        except Exception, e:
            log.error("Opening or parsing macros rules file:  %s" % e)
            exit(1)	

        json_macros.close()

	    # Loading baseline rules
        try:
            with open('baseline.rules') as json_baseline:
                self.config_['baseline_rules'] = json.load(json_baseline)[0]

        except Exception, e:
            log.error("Opening or parsing baseline rules file:  %s" % e)
            exit(1)
        
        json_baseline.close()

        # Daemon mode for eventlog continous read
        if args.daemon:
            self.config_['daemon'] = True

        # Evtx file search filter functionality
        if args.eventid:
            try:
                filter = eval(args.eventid[0])
                self.config_['search_filter'] = filter
            except Exception, e:
                log.error("Search filter incorrect:  %s" % e)
                exit(1)
            

        # Evtx file
        if args.file:
            self.config_['evtx_file'] = args.file[0]

        # Evtx file search filter subfilter 
        if args.attribute:
            self.config_['filter_attribute'] = args.attribute[0]

        # Memdump
        if args.memdump:
            self.config_['memdump'] = args.memdump[0]

        # Memedump profile
        if args.profile:
            self.config_['profile'] = args.profile[0]

        # Memedump profile
        if args.baseline:
            self.config_['baseline_enabled'] = True

    def start(self):
        """Initialization Function"""

        input_manager = InputManager(self.data_buffer_in,
                                     self.data_condition_in)
        input_manager.start()

        engine_manager = EngineManager(self.data_buffer_in,
                                     self.data_condition_in)
        engine_manager.start()

        control_manager = ControlManager(self.data_buffer_in,
                                     self.data_condition_in)
        control_manager.start()

        init_message = Message(self.data_buffer_in, self.data_condition_in)

        if self.config_['baseline_enabled']:
            engine_manager.baseline_engine_enabled = True

        if self.config_['search_filter']:
            control_manager.search_event(self.config_['evtx_file'],
                                      self.config_['sysmon_schema'],
                                      self.config_['search_filter'],
                                      self.config_['filter_attribute'],
                                      Origin.SYSPCE_CORE)
        elif self.config_['evtx_file']:
            control_manager.read_evtx(self.config_['evtx_file'],
                                      self.config_['detection_rules'],
                                      self.config_['detection_macros'],
                                      self.config_['baseline_rules'],
                                      self.config_['sysmon_schema'],
                                      Origin.SYSPCE_CORE)

        elif self.config_['daemon']:
            control_manager.read_eventlog(self.config_['detection_rules'],
                                          self.config_['detection_macros'],
                                          self.config_['baseline_rules'],
                                          self.config_['sysmon_schema'],
                                          Origin.SYSPCE_CORE)

        elif self.config_['memdump'] and self.config_['profile']:
            control_manager.read_memdump(self.config_['memdump'],
                                         self.config_['profile'],
                                         self.config_['detection_rules'],
                                         self.config_['detection_macros'],
                                         self.config_['baseline_rules'],
                                         Origin.SYSPCE_CORE)
        else:
            control_manager.read_evtx('',
                                      self.config_['detection_rules'],
                                      self.config_['detection_macros'],
                                      self.config_['baseline_rules'],
                                      self.config_['sysmon_schema'],
                                      Origin.SYSPCE_CORE)




        input_manager.join()
        engine_manager.join()
        control_manager.join()
        log.debug("SYSPCE_CORE ending...")


if __name__== "__main__":

    syspce = Syspce()
    syspce.parse_arguments()
    syspce.start()
    print "Thanks for using Syspce"
