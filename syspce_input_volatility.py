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
import volatility.plugins.malware.psxview as psxv
import volatility.commands as commands
import volatility.addrspace as addrspace


## TODO: 
## - Integrity plugins getsids
## - threads 
## - VADS

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

		###########################
		# Plugin pslist volatility 
		###########################

		proc = taskmods.PSList(self.config)
		pslist1 = {}
		vprocess = []

		for process in proc.calculate():
			## Mapping to event id sysmon 1
			pslist1['computer'] = 'localhost' 
			pslist1['CommandLine'] = str(process.Peb.ProcessParameters.CommandLine).replace('\"','')
			pslist1['CurrentDirectory'] = str(process.Peb.ProcessParameters.CurrentDirectory.DosPath)
			pslist1['Image'] = str(process.Peb.ProcessParameters.ImagePathName)
			pslist1['idEvent'] = 1 
			pslist1['UtcTime'] = str(process.CreateTime)
			pslist1['ProcessId'] = str(int(process.UniqueProcessId))
			pslist1['ParentProcessId'] = str(int(process.InheritedFromUniqueProcessId))
			pslist1['TerminalSessionId'] = str(int(process.SessionId))
			## Extra 
			pslist1['ExistTime'] = str(process.ExitTime)
			pslist1['BeingDebugged'] = str(process.Peb.BeingDebugged)
			pslist1['IsWow64'] = str(process.IsWow64)
			pslist1['NumHandles'] = str(int(process.ObjectTable.HandleCount))
			pslist1['NumThreads'] = str(int(process.ActiveThreads))
			pslist1['DllPath'] = str(process.Peb.ProcessParameters.DllPath)
			result = hashlib.md5(pslist1["ProcessId"]+pslist1["ParentProcessId"]+pslist1["computer"]+pslist1["UtcTime"])
			pslist1['ProcessGuid'] = result.hexdigest()
			pslist1['ParentImage'] = ""
			pslist1['ParentCommandLine'] = ""
			pslist1['ParentProcessGuid'] = ""

			pslist1['SyspceId'] = result.hexdigest()

			vprocess.append(pslist1)
			pslist1 = {}
			modules = ""

			## Modules 
			for module in process.get_load_modules():
				if module is not None:
					modules = modules + "," + str(module.FullDllName)

			pslist1['modules'] = modules

		for p in vprocess:
			for x in vprocess:
				if p['ParentProcessId'] == x['ProcessId']:
					p['ParentImage'] = x['Image']
					p['ParentCommandLine'] = x['CommandLine']
					p['ParentProcessGuid'] = x['ProcessGuid']

		###########################
		# Plugin privs volatility
		###########################

		priv = privm.Privs(self.config)
		
		privs_1 = {}
		privs_2 = {}
		priv_vector = []

		for privs in priv.calculate():
			privileges = privs.get_token().privileges()
			for value, present, enabled, default in privileges:
				try:
					name, desc = privm.PRIVILEGE_INFO[int(value)]
				except KeyError:
					continue
				privs_1 = {}
				privs_1['ProcessId'] = str(int(privs.UniqueProcessId))
				privs_1['Name'] = name 

				privileges_logged = ["SeImpersonatePrivilege","SeAssignPrimaryPrivilege","SeTcbPrivilege","SeBackupPrivilege","SeRestorePrivilege",
					  "SeCreateTokenPrivilege","SeLoadDriverPrivilege","SeTakeOwnershipPrivilege","SeDebugPrivilege"]
				privs_1['Present'] = "False"
				privs_1['Enabled'] = "False"
				if str(name) in privileges_logged:
					if present:
						privs_1['Present'] = "True"
					if enabled or default:
						privs_1["Enabled"] = "True"
					priv_vector.append(privs_1)

		for p in vprocess:
			for x in priv_vector:
				if p['ProcessId'] == x['ProcessId']:
						pvp = x['Name'] + "Present"
						p[pvp] = x['Present']
						pve = x['Name'] + "Enabled"
						p[pve] = x['Enabled']

		###########################
		# Plugin psxview volatility
		###########################

		command = psxv.PsXview(self.config)

		psxview_dict = {}
		psxview_vector = []

		for offset, process, ps_sources in command.calculate():
			psxview_dict['ProcessId'] = str(int(process.UniqueProcessId))
			psxview_dict['pslist'] = str(offset in ps_sources["pslist"])
			psxview_dict['psscan'] = str(offset in ps_sources["psscan"])
			psxview_dict['threadproc'] = str(offset in ps_sources["thrdproc"])
			psxview_dict['pspcid'] = str(offset in ps_sources["pspcid"])
			psxview_dict['csrss'] = str(offset in ps_sources["csrss"])
			psxview_dict['session'] = str(offset in ps_sources["session"])
			psxview_dict['deskthrd'] = str(offset in ps_sources["deskthrd"])
			psxview_vector.append(psxview_dict)
			psxview_dict = {}

		for p in vprocess:
			for x in psxview_vector:
				if p['ProcessId'] == x['ProcessId']:
						p['plist'] = x['pslist']
						p['plist_pooltag'] = x['psscan']
						p['plist_threadproc'] = x['threadproc']
						p['plist_pspcid'] = x['pspcid']
						p['plist_csrss'] = x['csrss']
						p['plist_session'] = x['session']
						p['plist_deskthrd'] = x['deskthrd']

		# To Send to the CORE
		############################

		events_list = vprocess

		self.send_message(events_list)
		
		self.terminate()
