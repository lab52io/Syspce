import datetime
import logging
log = logging.getLogger('sysmoncorrelator')

#----------------------------------------------------------------------------#
# Bucket class (FIFO) used for managing actions done by processes in a       #
#period of time																 #
#----------------------------------------------------------------------------#

class Bucket(object):
	def __init__(self, max_size, time_period, bucket_name):
					
		self.max_size = max_size
		
		self.time_period =  datetime.timedelta(seconds = time_period)
		
		self.action = []
		
		self.alert = True
		
		self.bucket_name = bucket_name
		
	def insertAction(self, date):
		
		# If bucket is disabled, no alert
		if self.alert == False:
			log.debug("Bucket %s disabled, already notified" % self.bucket_name)
			return False
		
		date = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
		
		# First action 
		if not self.action:
			self.action.append(date)
			
			if self.max_size < 2 and self.alert:
				self.alert = False
				return True
			else:
				return False
				
		#Check delta between first element and new element
		
		while self.action and (date - self.action[0]) > self.time_period:
			self.action.pop(0)
			
		self.action.append(date)
		
		if len(self.action) >= self.max_size:
			self.alert = False
			return True
		else:
			return False
	
	def actionExists(self, date):
		date = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
		if date in self.action:
			return True
		else:
			return False
	
class BucketSystem(object):
	def __init__(self):
		self.buckets = {}
		
	def getBucket(self, bucket_name):
	
		if self.buckets.has_key(bucket_name):
			return self.buckets[bucket_name]
		else:
			return False
	
	def createBucket(self, bucket_name, max_size, time_period):
	
		bucket = Bucket(max_size, time_period, bucket_name)
		self.buckets[bucket_name] = bucket
		
		return bucket
	


	