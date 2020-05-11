import logging
from syspce_input import Input
from syspce_message import *
import threading
import uuid
import hashlib
import datetime

import volatility.conf as conf
import volatility.obj as obj
import volatility.registry as registry
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.plugins.privileges as privm
import volatility.plugins.malware.psxview as psxv
import volatility.plugins.registry.printkey as printkeyregistry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.registry.registryapi as registryapi

## TODO: 
## - Integrity plugins getsids
## - threads 
## - VADS - Malfind First step

log = logging.getLogger('sysmoncorrelator')

class InputVolatility(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src, 
				 filepath, profile):

		Input.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		
		self._config = conf.ConfObject()
		self._config.PROFILE = profile
		self._config.LOCATION = filepath
		self._config.hive_offset = None
		self._config.HIVE_OFFSET = None

		registry.PluginImporter()
		registry.register_global_options(self._config, commands.Command)
		registry.register_global_options(self._config, addrspace.BaseAddressSpace)

		self.name = 'Input Volatility'
		self.module_id = Module.INPUT_VOLATILITY
		self.machineguid = ""

	def get_registry_keys(self):

		addr_space = utils.load_as(self._config)

		hl = hivelist.HiveList(self._config)

		if not self._config.HIVE_OFFSET:
			hive_offsets = [h.obj_offset for h in hl.calculate()]
		else:
			hive_offsets = [self._config.HIVE_OFFSET]
		
		for hoff in set(hive_offsets):
			h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
			name = obj.Object("_CMHIVE", vm = addr_space, offset = hoff).get_name()
			root = rawreg.get_root(h)
			if not root:
				if self._config.HIVE_OFFSET:
					print("Unable to find root key. Is the hive offset correct?")
			else:
				if self._config.KEY:
					yield name, rawreg.open_key(root, self._config.KEY.split('\\'))
				else:
					yield name, root

	def do_action(self):

		###########################
		# Get MachineGUID
		###########################

		self._config.KEY = 'Microsoft\\Cryptography'

		for reg,key in self.get_registry_keys():
			if key:
				for v in rawreg.values(key):
					tp, dat = rawreg.value_data(v)
					if (v.Name == "MachineGuid"):
						self.machineguid = dat
 
		if self.machineguid == "":
			self.machineguid = "ffffffff-2cf2-4c6d-919d-686204658ab6"

		mg_vector = self.machineguid.split("-")
		computerid = mg_vector[0]

		###########################
		# Plugin pslist volatility 
		###########################

		proc = taskmods.PSList(self._config)
		pslist1 = {}
		vprocess = []

		for process in proc.calculate():
			## Mapping to event id sysmon 1
			pslist1['computer'] = computerid
			pslist1['Source'] = "Memory"
			pslist1['CommandLine'] = str(process.Peb.ProcessParameters.CommandLine).replace('\"','')
			pslist1['CurrentDirectory'] = str(process.Peb.ProcessParameters.CurrentDirectory.DosPath)
			pslist1['Image'] = str(process.Peb.ProcessParameters.ImagePathName)
			pslist1['idEvent'] = 1 
			pslist1['UtcTime'] = str(process.CreateTime)
			pslist1['ProcessId'] = str(int(process.UniqueProcessId))
			pslist1['ParentProcessId'] = str(int(process.InheritedFromUniqueProcessId))
			pslist1['TerminalSessionId'] = str(int(process.SessionId))
			## Extra 
			pslist1['ExitTime'] = str(process.ExitTime)
			pslist1['BeingDebugged'] = str(process.Peb.BeingDebugged)
			pslist1['IsWow64'] = str(process.IsWow64)
			pslist1['NumHandles'] = str(int(process.ObjectTable.HandleCount))
			pslist1['NumThreads'] = str(int(process.ActiveThreads))
			pslist1['DllPath'] = str(process.Peb.ProcessParameters.DllPath)
			pslist1['ParentImage'] = ""
			pslist1['ParentCommandLine'] = ""
			pslist1['ParentProcessGuid'] = ""

			#Exceptions 
			if pslist1['ProcessId'] == '4':
				pslist1['Image'] = "System"
			if pslist1['Image'] == "\\SystemRoot\\System32\\smss.exe":
				pslist1['Image'] = "C:\\Windows\\System32\\smss.exe"

			#Building processguid to merge events with Sysmon
			date_time_obj = datetime.datetime.strptime(pslist1["UtcTime"], '%Y-%m-%d %H:%M:%S UTC+%f')
			epoch = datetime.datetime.utcfromtimestamp(0)
			t = (date_time_obj-epoch).total_seconds()
			hex_string = '{:02x}'.format(int(t))
			firstpart, secondpart = hex_string[:len(hex_string)/2], hex_string[len(hex_string)/2:]

			if pslist1['Image'] != "" and pslist1['ProcessId'] != "":
				result2 = hashlib.md5(pslist1['computer']+"-"+secondpart+"-"+firstpart+"-"+pslist1['ProcessId']+pslist1['Image'].lower())
			else:
				result2 = hashlib.md5(pslist1['computer']+"-"+secondpart+"-"+firstpart+"-"+"666666"+"C:\syspce\dummy.exe")

			syspceid_datetime = date_time_obj.strftime('%Y-%m-%d %H:%M:%S')
			result = hashlib.md5(pslist1["ProcessId"]+pslist1["ParentProcessId"]+pslist1["computer"]+syspceid_datetime)
			pslist1['ProcessGuid'] = result2.hexdigest()
			pslist1['SyspceId'] = result.hexdigest()

			modules = ""

			## Modules 
			for module in process.get_load_modules():
				if module is not None:
					modules = modules + "," + str(module.FullDllName)

			pslist1['modules'] = modules
			vprocess.append(pslist1)
			pslist1 = {}

		for p in vprocess:
			for x in vprocess:
				if p['ParentProcessId'] == x['ProcessId']:
					p['ParentImage'] = x['Image']
					p['ParentCommandLine'] = x['CommandLine']
					p['ParentProcessGuid'] = x['ProcessGuid']

		###########################
		# Plugin privs volatility
		###########################

		priv = privm.Privs(self._config)
		
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

		command = psxv.PsXview(self._config)

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
