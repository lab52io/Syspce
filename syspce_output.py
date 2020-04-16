import logging
import win32api
import win32con
import win32security
import win32evtlogutil
import win32evtlog
import os
import ctypes

from syspce_parser import get_action_from_id
from syspce_parser import get_default_parameter_from_id

log = logging.getLogger('sysmoncorrelator')

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

class Output_(object):
	def __init__(self, full_log=False):
	
		self.log = log
		
		self.full_log = full_log
		
	def set_color(self, color, handle=std_out_handle):
		"""(color) -> BOOL
		
		Example: set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
		"""
		bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
		return bool
		
	def format_result_hierarchy(self, res):
		"""Print to stdout alerts
			res: list of dicctionary entries representing the alerts
			[{'Computer': machine name ,'ProcessChain': list of nodes,
				'Rulename': name,'RuleID': rule id}, ...]
		"""
		alerts = []

		for anomaly in res:
			alert = ""
			alert += "\n"
			alert += "PHE ALERT [%s]: %s\n" % (anomaly['RuleID'],
												  anomaly['Rulename'])
			tab = '--'
			ntabs = 0
			
			for process in reversed(anomaly['ProcessChain']):
				ntabs +=1
				
				if process.acciones['1'][0]['Alert']:
					alert += "!%s> %s (%s) [%s] %s\n" % (
									tab*ntabs, 
									get_action_from_id(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd)			
					process.acciones['1'][0]['Alert'] = False
				else:
					alert += "%s> %s (%s) [%s] %s\n" % (tab*ntabs, 
									get_action_from_id(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd)
									
				for action_type in process.acciones:
					for action in process.acciones[action_type]:
						param = get_default_parameter_from_id(\
													int(action_type))
						if int(action_type) != 1:
						
							if action['Alert']:
								alert += "!%s> %s %s\n" %\
									(tab*(ntabs+2), \
									get_action_from_id(int(action_type)),
											action[param])
								action['Alert'] = False
							else:
								if self.full_log:
									alert += "%s> %s %s\n" %\
										(tab*(ntabs+2), \
										get_action_from_id(int(action_type)),
															action[param])									
						# Special case for Real Parent
						elif action['CreationType'] == 'InjectedThread':
							alert += "!%s> [I] REAL PARENT %s\n" % \
										(tab*(ntabs+2),
										action['RealParent'])
			alerts.append(alert)
		return alerts

	def log_result_hierarchy(self, res):
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
									get_action_from_id(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd))
					self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)				
					process.acciones['1'][0]['Alert'] = False
				else:
					self.log.info("%s> %s (%s) [%s] %s" % (tab*ntabs, 
									get_action_from_id(1),
									process.pid, 
									process.acciones['1'][0]['ProcessTTL'],
									process.cmd))
									
				for action_type in process.acciones:
					for action in process.acciones[action_type]:
						param = get_default_parameter_from_id(\
													int(action_type))
						if int(action_type) != 1:
						
							if action['Alert']:
								self.set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
								self.log.info("!%s> %s %s" %\
									(tab*(ntabs+2), \
									get_action_from_id(int(action_type)),
											action[param]))
								self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)
								action['Alert'] = False
							else:
								if self.full_log:
									self.log.info("%s> %s %s" %\
										(tab*(ntabs+2), \
										get_action_from_id(int(action_type)),
															action[param]))										
						# Special case for Real Parent
						elif action['CreationType'] == 'InjectedThread':
							self.set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
							self.log.info("!%s> [I] REAL PARENT %s" % \
										(tab*(ntabs+2),
										action['RealParent']))							
							self.set_color(FOREGROUND_WHITE | FOREGROUND_INTENSITY)
	
	def write_result_eventlog_hierarchy(self, res):
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
					data = "%s> %s (%s) %s" % (tab*ntabs, get_action_from_id(1),
												process.pid, process.cmd)
					descr.append(data)
					
					for action_type in process.acciones:
					
						for action in process.acciones[action_type]:
						
							if action['Alert']:
								param = get_default_parameter_from_id(\
													int(action_type))
													
								data = "%s> %s %s" % (tab*(ntabs+2), \
									get_action_from_id(int(action_type)),
									action[param])
										
								descr.append(data)		
			else:
				descr.append(data)
				
			self.log.debug("Writing to eventlog: %s" % anomaly)
			win32evtlogutil.ReportEvent(applicationName, eventID,
											eventCategory=category, 
											eventType=myType, strings=descr,
											data=data, sid=my_sid)

	def log_result_baseline(self, pnode, s_actions):
		self.log.info("")
		self.log.info("BASELINE ENGINE ALERT [%s]: %s" % (pnode.pid, 
														pnode.ImageFileName ))
		self.log.info("--> Process Points: %s" % pnode.points)
		self.log.info("--> Parent CL: %s" % pnode.acciones["1"][0]\
														["ParentCommandLine"])
		for action in s_actions:
			if not action.has_key('PointsLeft'):
				param = get_action_from_id(int(action['EventType']))
				self.log.info("--> %s" % param)
				
				for attr in action:
					self.log.info("----> %s: %s" % (attr, action[attr]))

	def format_result_baseline(self, pnode, s_actions):
		alert_text = '\n'
		alert_text += "BASELINE ENGINE ALERT [%s]: %s\n" % (pnode.pid, 
														pnode.ImageFileName )
		alert_text += "--> Process Points: %s\n" % pnode.points
		alert_text += "--> Parent CL: %s\n" % pnode.acciones["1"][0]\
														["ParentCommandLine"]
		for action in s_actions:
			if not action.has_key('PointsLeft'):
				param = get_action_from_id(int(action['EventType']))
				alert_text += "--> %s\n" % param
				
				for attr in action:
					alert_text += "----> %s: %s\n" % (attr, action[attr])

		return alert_text

	def write_result_eventlog_baseline(self, res):
		ph = win32api.GetCurrentProcess()
		th = win32security.OpenProcessToken(ph, win32con.TOKEN_READ)
		my_sid = win32security.GetTokenInformation(\
												th, win32security.TokenUser)[0]
		myType = win32evtlog.EVENTLOG_WARNING_TYPE
		applicationName = "SysmonCorrelator"
		data = "Not configured, use -l option"
		eventID = 1
		category = 2
		descr = ["Engine: Baseline", "Data: "]

		descr.append(res)
				
		win32evtlogutil.ReportEvent(applicationName, eventID,
									eventCategory=category, 
									eventType=myType, strings=descr,
									data=data, sid=my_sid)


	def process_result_hierarchy(self, res):
		"""Function for processing results"""
		self.write_result_eventlog_hierarchy(res)
		self.log_result_hierarchy(res)

	def process_result_baseline(self, pnode, s_actions):
		"""Function for processing results"""
		res = self.format_result_baseline(pnode, s_actions) 
		self.write_result_eventlog_baseline(res)
		self.log_result_baseline(pnode, s_actions)
			
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