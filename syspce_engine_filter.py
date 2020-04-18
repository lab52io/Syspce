import logging

from syspce_engine import Engine
from syspce_message import *

log = logging.getLogger('sysmoncorrelator')

class FilterEngine(Engine):

	def __init__(self, data_buffer_in,
				 data_condition_in, src,
				 search_filter,
				 filter_attribute,
				 events):

		Engine.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		self.events = events
		self.search_filter = search_filter
		self.filter_attribute = filter_attribute

		self.name = 'Filter Engine'
		self.module_id = Module.FILTER_ENGINE

	def do_action(self):

		for event in self.events:
			try:
				match = True

				for search_filter in self.search_filter:
						
					#special case for filter attribute idEvent becouse
					# it's an int not string
					if search_filter == 'idEvent':
						if self.search_filter[search_filter] != \
							event[search_filter]:
							match = False
							break 
					else:
						if self.search_filter[search_filter].lower() not in \
							event[search_filter].lower():
							match = False
							break 								
									
				if match:
					if self.filter_attribute:
						self.send_message(event[self.filter_attribute])	
					else:
						self.send_message(event)

			except Exception, e:
				pass

		self.terminate()
