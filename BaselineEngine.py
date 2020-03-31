import logging
from SysmonParser import *
import os
import Bucket
from datetime import timedelta
log = logging.getLogger('sysmoncorrelator')

#----------------------------------------------------------------------------#
# Baseline class for anomaly behaviour detection                             #
#----------------------------------------------------------------------------#
class BaselineEngine(object):
	def __init__(self, active = True, baseline_rules = [],
					baseline_macros = {}):
					
		self.active = active
		
		self.baseline_rules = baseline_rules
		
		self.baseline_macros = baseline_macros
				
		self.total_sub_points = 0
		
		self.default_points = 100
		
		self.suspicious_actions = []
		
		self.ImageFileName = ""
		
		self.buckets = Bucket.BucketSystem()
		
	def runActionCheck(self, pnode, paction):
		if self.active:
			self.total_sub_points = 0
			self.suspicious_actions = []
			
			
			
			self.ImageFileName = pnode.ImageFileName
			
			# no baseline config for this process image
			if self.ImageFileName not in self.baseline_rules:
				# process isn't in the baseline yet
				return False
		
			# setting Image Baseline as a default points
			self.default_points = self.baseline_rules[self.ImageFileName]\
																	["Points"]
			
			must_subtract = False
			
			# Cheking list of process actions rules 
			if self.__checkProcessActionToBaseline(paction):
				must_subtract = True
			
			# Case Process termination, special final process checks  
			if paction["idEvent"] == 5 and \
									self.__processTerminationChecks(paction,
																	pnode):
				must_subtract = True
			
			if must_subtract:
				# some action was anomaly let's record it on the process node
				pnode.add_suspicious_action(self.suspicious_actions)

				# subtract points to current process
				pnode.subtract_points( self.total_sub_points )
				log.debug("[%s (%s)] Sustracting -%s points due to action %s" % \
						(pnode.ImageFileName,
						pnode.pid,
						self.total_sub_points,
						paction["idEvent"]))

		else:
			#log.debug("Baseline Engine off")
			pass
	
	def __checkProcessActionToBaseline(self, paction):

		# checking reverse search
		if self.baseline_rules[self.ImageFileName].has_key(\
													str(paction["idEvent"])):
			reverse  = False
			baseline_action = self.baseline_rules[self.ImageFileName]\
													[str(paction["idEvent"])]
		elif self.baseline_rules[self.ImageFileName].has_key("-" + \
													str(paction["idEvent"])):
			reverse  = True
			baseline_action = self.baseline_rules[self.ImageFileName]["-" + \
													str(paction["idEvent"])]
		# paction id not defined
		else:
			return False
		
		# setting Image Baseline concret action as a default points
		self.default_points = baseline_action["Points"]

		#True - must subtract points , an anomaly was indentified
		#False - no subtract points , the process behaviour is legit	
		result = self.__checkRuleActionToProcessAction(paction, baseline_action)

		#Checking process actions in a time period if we have more than N 
		# actions let's alert
		
		if not result and baseline_action.has_key("N") and \
							baseline_action.has_key("Seconds"):
							
			bucket_name = self.ImageFileName + str(paction["idEvent"])
			bucket = self.buckets.getBucket(bucket_name)
			
			if not bucket:
				bucket = self.buckets.createBucket(bucket_name, 
												baseline_action["N"],
												baseline_action["Seconds"])
												
			# True - there are more than "n" actions in a time period	

			result = bucket.insertAction(paction["UtcTime"])

			
			# let's alert
			if result:
				self.total_sub_points += self.default_points
			
				#let's record why we subtract point 
				s_action = {"EventType":paction["idEvent"],
							"Image":self.ImageFileName,
							"Action":"Process did more than " + 
								str(baseline_action["N"]) + \
								" actions of type " + \
								str(paction["idEvent"]) + " in " + \
								str(baseline_action["Seconds"]) + " seconds",\
							"NumEventsThreshold":str(baseline_action["N"]),
							"TimePeriodSeconds":str(baseline_action["Seconds"]),
							"Points": self.default_points * -1
								}
				self.suspicious_actions.append(s_action)
			

		if reverse:
			#reverse the result
			result ^= 1
		
		return result
		
	def __checkRuleActionToProcessAction(self, paction, baseline_action):
		
		suspicious_attr_seen =  False
		
		# Special case only atribute Points defined
		#Example "2":{"Points": 30}
		if len(baseline_action) == 1 and baseline_action.has_key("Points"):
		
			#Adding default action subtract points
			self.total_sub_points += self.default_points
			
			# Adding Suspicious action because EventID could have "-"
			defaultAtt = getDefaultParameterFromID(paction["idEvent"])
			s_action = {"EventType":paction["idEvent"],
						defaultAtt:paction[defaultAtt],
						"Points": self.total_sub_points * -1
						}
			self.suspicious_actions.append(s_action)
			
			return suspicious_attr_seen		
		
		# Special case, action with no atributes only  keys name "Points", "N"
		# and "seconds" Ex. "2":{"Points": 30, "N": 30, "Seconds": 86400}
		if len(baseline_action) == 3 and baseline_action.has_key("Points")\
									and baseline_action.has_key("N") \
									and baseline_action.has_key("Seconds"):
		
			return suspicious_attr_seen
		
		# Now let's process normal event atributes ex.
		#"7":{"Points": 10, "ImageLoaded": {"Points": 10, "Value": "lsass.dll"}
		for b_action_att in baseline_action:
			
			#Check if reverse action in attribute
			if "-" in b_action_att:
				reverse = True
				b_action_att_aux = b_action_att.replace("-","")
			else:
				b_action_att_aux = b_action_att
				reverse = False
				
			# skip attributes Points , ...
			if b_action_att not in ["Points", "N", "Seconds"]:
			
				# if reverse , reverse the result with XOR
				if self.__checkAttValueToProcessAtt(
										baseline_action[b_action_att]["Value"], 
										paction[b_action_att_aux])^reverse:
					
					# Set specific action attribute subtraction points
					if baseline_action[b_action_att].has_key("Points"):
						self.total_sub_points += baseline_action[b_action_att]\
																["Points"]
						sub_points = baseline_action[b_action_att]["Points"]
					else:
						self.total_sub_points += self.default_points
						sub_points = self.default_points
						
					suspicious_attr_seen = True
					
					#let's record why we subtract point 
					s_action = {"EventType":paction["idEvent"],
								b_action_att:paction[b_action_att_aux],
								"Points": sub_points * -1
								}
					self.suspicious_actions.append(s_action)

			
		return suspicious_attr_seen		
		
	def __checkAttValueToProcessAtt(self, b_action_att_value, 
									p_action_att_value):
		
		match = True
		# its a macro ?
		if b_action_att_value in self.baseline_macros:
			filter_list =  self.baseline_macros[b_action_att_value]
		else:
			filter_list = [b_action_att_value]

		for f in filter_list:
			if f.lower() in p_action_att_value.lower():
				match = False
				
		# return True when some action attribute dosen't match process attribute
		# so we need to subtract point to the process beacuse it's a behaviour 
		# that hasn't it seen yet
		return match
		
	def __processTerminationChecks(self, paction, pnode):
		
		res = False
		
		if self.__LiveTime(paction, pnode):
			res =  True
			
		if self.__AcctionNotPresent(pnode):
			res =  True		
			
		return res
		
	def __LiveTime(self, paction, pnode):
		if self.baseline_rules[self.ImageFileName].has_key("max_ttl") and \
			self.baseline_rules[self.ImageFileName].has_key("min_ttl"):
			max_b_ttl = self.baseline_rules[self.ImageFileName]["max_ttl"]
			min_b_ttl = self.baseline_rules[self.ImageFileName]["min_ttl"]
		else:
			max_b_ttl = False
			min_b_ttl  = False
			
		p_ttl = pnode.getLiveTime()
		max_b_ttl = timedelta(seconds = max_b_ttl)
		min_b_ttl = timedelta(seconds = min_b_ttl)
		
		# if process timelive is lower than the baseline timelive it's an 
		# anomalous process behavior
		if p_ttl and max_b_ttl and min_b_ttl and \
			((p_ttl > max_b_ttl) or (p_ttl < min_b_ttl)):
	
			self.total_sub_points += self.default_points
			
			#let's record why we subtract point 
			s_action = {"EventType":paction["idEvent"],
								"Image":pnode.acciones["1"][0]["Image"],
								"ProcessTTL":p_ttl,
								"BaselineMaxTTL":max_b_ttl,
								"BaselineMinTTL":min_b_ttl,
								"Points": self.default_points * -1
								}
			self.suspicious_actions.append(s_action)
			return True

		return False
		
	def __AcctionNotPresent(self, pnode):
		result = False
		for action in pnode.acciones: 
		
			# no action registrered for this action id
			if not pnode.acciones[action]:
			
				# There is an action defined on the baseline for this action id
				# so this process did not do an action that normaly does
				if self.baseline_rules[self.ImageFileName].has_key(action):
					if self.baseline_rules[self.ImageFileName][action]:
						subp = self.baseline_rules\
										[self.ImageFileName][action]["Points"]
						self.total_sub_points += subp
						
						#let's record why we subtract point 
						s_action = {"EventType":5,
											"Status":"Action not found after PT",
											"Action":getAcctionFromID(\
																int(action)),
											"Points": subp * -1
											}
						self.suspicious_actions.append(s_action)	
						result = True
		return result
		
	def fireAlert(self, pnode):
		if pnode.points <= 0:
			if not pnode.notified:
				s_actions = pnode.get_suspicious_actions()
				self.__printresults(pnode, s_actions)
				pnode.setNotified()
				return True
				
		return False
		
	def __printresults(self, pnode, s_actions):
		log.info("")
		log.info("BASELINE ENGINE ALERT [%s]: %s" % (pnode.pid, 
														pnode.ImageFileName ))
		log.info("--> Process Points: %s" % pnode.points)
		log.info("--> Parent CL: %s" % pnode.acciones["1"][0]\
														["ParentCommandLine"])
		for action in s_actions:
			if not action.has_key('PointsLeft'):
				param = getAcctionFromID(int(action['EventType']))
				log.info("--> %s" % param)
				
				for attr in action:
					log.info("----> %s: %s" % (attr, action[attr]))

	def getStatus(self):
		return self.active