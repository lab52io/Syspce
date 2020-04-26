import logging
from syspce_input import Input
from syspce_message import *
import threading
import uuid
import hashlib

import volatility.conf as conf
import volatility.registry as registry
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.plugins.privileges as privm
import volatility.commands as commands
import volatility.addrspace as addrspace


log = logging.getLogger('sysmoncorrelator')

class InputVolatility(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src, 
				 filepath, profile):

		Input.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)


		self.config = conf.ConfObject()
		self.config.PROFILE = profile
		self.config.LOCATION = filepath
		registry.PluginImporter()
		registry.register_global_options(self.config, commands.Command)
		registry.register_global_options(self.config, addrspace.BaseAddressSpace)

		self.name = 'Input Volatility'
		self.module_id = Module.INPUT_VOLATILITY

	def do_action(self):

		# Plugin pslist volatility 
		###########################

		proc = taskmods.PSList(self.config)
		self.p1 = {}
		self.vprocess = []

		for process in proc.calculate():
			## Mapping to event id sysmon 1
			self.p1['computer'] = 'localhost' 
			self.p1['CommandLine'] = str(process.Peb.ProcessParameters.CommandLine)
			self.p1['CurrentDirectory'] = str(process.Peb.ProcessParameters.CurrentDirectory.DosPath)
			self.p1['Image'] = str(process.Peb.ProcessParameters.ImagePathName)
			self.p1['idEvent'] = 1 
			self.p1['UtcTime'] = str(process.CreateTime)
			self.p1['ProcessId'] = str(int(process.UniqueProcessId))
			self.p1['ParentProcessId'] = str(int(process.InheritedFromUniqueProcessId))
			self.p1['TerminalSessionId'] = str(int(process.SessionId))
			## Extra 
			self.p1['ExistTime'] = str(process.ExitTime)
			self.p1['BeingDebugged'] = str(process.Peb.BeingDebugged)
			self.p1['IsWow64'] = str(process.IsWow64)
			self.p1['NumHandles'] = str(int(process.ObjectTable.HandleCount))
			self.p1['NumThreads'] = str(int(process.ActiveThreads))
			self.p1['DllPath'] = str(process.Peb.ProcessParameters.DllPath)
			self.p1['ProcessGuid'] = str(uuid.uuid4())
			self.p1['ParentImage'] = ""
			self.p1['ParentCommandLine'] = ""
			self.p1['ParentProcessGuid'] = ""

			result = hashlib.md5(self.p1["ProcessId"]+self.p1["ParentProcessId"]+self.p1["computer"]+self.p1["UtcTime"])
			self.p1['SyspceId'] = result.hexdigest()

			self.vprocess.append(self.p1)
			self.p1 = {}
			self.modules = []

			## Modules 
			for module in process.get_load_modules():
				if module is not None:
					self.modules.append(str(module.FullDllName))

			self.p1['modules'] = self.modules

		for p in self.vprocess:
			for x in self.vprocess:
				if p['ParentProcessId'] == x['ProcessId']:
					p['ParentImage'] = x['Image']
					p['ParentCommandLine'] = x['CommandLine']
					p['ParentProcessGuid'] = x['ProcessGuid']

		# Plugin privs volatility
		###########################

		priv = privm.Privs(self.config)
		
		self.pi = {}
		self.pi2 = {}
		self.priv_vector = []

		for privs in priv.calculate():
			privileges = privs.get_token().privileges()
			self.pi['ProcessId'] = str(int(privs.UniqueProcessId))
			for value, present, enabled, default in privileges:
				try:
					name, desc = privm.PRIVILEGE_INFO[int(value)]
				except KeyError:
					continue
				attributes = []
				if present:
					attributes.append("Present")
				if enabled:
					attributes.append("Enabled")
					self.pi2[str(name)] = "enabled"
					self.pi.update(self.pi2)
					self.pi2 = {}
				if default:
					attributes.append("Default")
				
				
			self.priv_vector.append(self.pi)
			self.pi = {}

		for p in self.vprocess:
			for x in self.priv_vector:
				if p['ProcessId'] == x['ProcessId']:
						p.update(x)


		# To Send to the CORE
		############################

		events_list = self.vprocess
		
		self.send_message(events_list)
		
		self.terminate()
