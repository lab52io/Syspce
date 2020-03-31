import logging
from SysmonParser import *
import win32api
import win32con
import win32security
import win32evtlogutil
import win32evtlog
import os
import ctypes

STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12

FOREGROUND_BLUE = 0x01 # text color contains blue.
FOREGROUND_GREEN= 0x02 # text color contains green.
FOREGROUND_RED  = 0x04 # text color contains red.
FOREGROUND_WHITE= 0x07 # text color contains withe.

FOREGROUND_INTENSITY = 0x08 # text color is intensified.
BACKGROUND_BLUE = 0x10 # background color contains blue.
BACKGROUND_GREEN= 0x20 # background color contains green.
BACKGROUND_RED  = 0x40 # background color contains red.
BACKGROUND_INTENSITY = 0x80 # background color is intensified.

std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)


"""
	Class for printing to stdout or sending to eventlog alerts.
"""

class CorrelatorOutput(object):
	def __init__(self, logger, output, full_log=False):
	
		self.log = logger
		
		self.output = output

		self.full_log = full_log
		
	def set_color(self, color, handle=std_out_handle):
		"""(color) -> BOOL
		
		Example: set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
		"""
		bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
		return bool
		
	def printResult(self, res):
		"""Print to stdout alerts
			res: list of dicctionary entries representing the alerts
			[{'Computer': machine name ,'ProcessChain': list of nodes,
				'Rulename': name,'RuleID': rule id}, ...]
		"""

		for anomaly in res:
			self.log.info("")
			self.log.info("PHE ALERT [%s]: %s" % (anomaly['RuleID'],
												  anomaly['Rulename']))
			tab = '--'
			ntabs = 0
			
			for process in reversed(anomaly['ProcessChain']):
				ntabs +=1
				
				if process.acciones['1'][0]['Alert']:
					self.set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
					self.log.info("!%s> %s (%s) [%s] %s" % (
									tab*ntabs, 
									getAcctionFromID(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd))
					self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)				
					process.acciones['1'][0]['Alert'] = False
				else:
					self.log.info("%s> %s (%s) [%s] %s" % (tab*ntabs, 
									getAcctionFromID(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd))
									
				for action_type in process.acciones:
					for action in process.acciones[action_type]:
						param = getDefaultParameterFromID(\
													int(action_type))
						if int(action_type) != 1:
						
							if action['Alert']:
								self.set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
								self.log.info("!%s> %s %s" %\
									(tab*(ntabs+2), \
									getAcctionFromID(int(action_type)),
											action[param]))
								self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)
								action['Alert'] = False
							else:
								if self.full_log:
									self.log.info("%s> %s %s" %\
										(tab*(ntabs+2), \
										getAcctionFromID(int(action_type)),
															action[param]))										
						# Special case for Real Parent
						elif action['CreationType'] == 'InjectedThread':
							self.set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
							self.log.info("!%s> [I] REAL PARENT %s" % \
										(tab*(ntabs+2),
										action['RealParent']))							
							self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)
	
	def writeResultToEventlog(self, res):

		ph = win32api.GetCurrentProcess()
		th = win32security.OpenProcessToken(ph, win32con.TOKEN_READ)
		my_sid = win32security.GetTokenInformation(\
												th, win32security.TokenUser)[0]
		myType = win32evtlog.EVENTLOG_WARNING_TYPE
		applicationName = "SysmonCorrelator"
		tab = '--'	
		data = "Not configured, use -l option"
		
		for anomaly in res:
			eventID = anomaly['RuleID']
			category = 1
	
			descr = [
					"RuleName: " + anomaly['Rulename'],
					"RuleID: " + str(anomaly['RuleID']),
					"Computer: " + anomaly['Computer'],
					"Data: ",
					]
					
			ntabs = 0
			if self.full_log:
				for process in reversed(anomaly['ProcessChain']):
				
					ntabs +=1
					data = "%s> %s (%s) %s" % (tab*ntabs, getAcctionFromID(1),
												process.pid, process.cmd)
					descr.append(data)
					
					for action_type in process.acciones:
					
						for action in process.acciones[action_type]:
						
							if action['Alert']:
								param = getDefaultParameterFromID(\
													int(action_type))
													
								data = "%s> %s %s" % (tab*(ntabs+2), \
									getAcctionFromID(int(action_type)),
									action[param])
										
								descr.append(data)		
			else:
				descr.append(data)
				
			self.log.debug("Writing to eventlog: %s" % anomaly)
			win32evtlogutil.ReportEvent(applicationName, eventID,
											eventCategory=category, 
											eventType=myType, strings=descr,
											data=data, sid=my_sid)
											
	def processResult(self, res):
		"""Function for processing results"""
	
		if self.output == 'eventlog':
			self.writeResultToEventlog(res)
		else:
			self.printResult(res)
			
class bcolors:
    HEADER = '\033[95m'
    RED = '\033[91m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'