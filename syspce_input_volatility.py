import logging
from syspce_input import Input
from syspce_message import *
import threading
import uuid
import hashlib
import datetime
import os

import volatility.conf as conf
import volatility.obj as obj
import volatility.registry as registry
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.plugins.privileges as privm
import volatility.plugins.malware.psxview as psxv
import volatility.plugins.registry.printkey as printkeyregistry
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.threads as threads
import volatility.plugins.vadinfo as vadinfo
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.win32.tasks as tasks
import volatility.win32.modules as moduless
import volatility.plugins.modscan as modscan
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.registry.registryapi as registryapi


log = logging.getLogger('sysmoncorrelator')

# Example input memory execution:
# Param -p: Volatility profile 
# Param -m: Memory file
# python.exe syspce.py -m C:\Users\john\RAM.raw -p Win7SP1x64

class InputVolatility(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src, 
				 filepath, profile):

		Input.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		# Relative Path
		filepath2 = ""
		if filepath.find(":\\") == -1:
			filepath2 = os.getcwd()+"\\"+filepath
			filepath = "file:///" + filepath2
		else:
		# Absolute path
			filepath = "file:///" + filepath

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

	''' 
	Name: get_threads()
	Params: Process handle to extract the threads
	Return: True o False if PS_CROSS_THREAD_FLAGS_SYSTEM, PS_CROSS_THREAD_FLAGS_HIDEFROMDBG, PS_CROSS_THREAD_FLAGS_IMPERSONATING or UNKNOWN THREADS is enable o disable
	Description: This function detect unknown thread, hidden from debugger threads and impersonation threads. This funtion is very slow, be patient.
	'''
	def get_threads(self,process,vthreads,pslist1):

			result = []
			result.append("False")
			result.append("False")
			result.append("False")
			result.append("False")

			thread1 = {}

			addr_space = utils.load_as(self._config)
			system_range = tasks.get_kdbg(addr_space).MmSystemRangeStart.dereference_as("Pointer")
			mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in moduless.lsmod(addr_space))
			mod_addrs = sorted(mods.keys())
			seen_threads = dict()

			## Gather threads by list traversal of active/linked processes 
			for thread in process.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
				seen_threads[thread.obj_vm.vtop(thread.obj_offset)] = (False, thread)

			process_dll_info = {}

			for _offset, (found_by_scanner, thread) in seen_threads.items():
				# Do we need to gather DLLs for module resolution 
				if addr_space.address_compare(thread.StartAddress, system_range) != -1:
					owner = tasks.find_module(mods, mod_addrs,addr_space.address_mask(thread.StartAddress))
				else:
					owning_process = thread.owning_process() 
					if not owning_process.is_valid(): 
						owner = None
					else:
						try:
							user_mod_addrs, user_mods = process_dll_info[owning_process.obj_offset]
						except KeyError:
							user_mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in owning_process.get_load_modules())
							user_mod_addrs = sorted(user_mods.keys())
							process_dll_info[owning_process.obj_offset] = (user_mod_addrs, user_mods)

						owner = tasks.find_module(user_mods, user_mod_addrs, addr_space.address_mask(thread.StartAddress))
				
				# Specific fields
				thread1["ThreadId"] = ""
				thread1["PS_CROSS_THREAD_FLAGS_IMPERSONATING"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_HIDEFROMDBG"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_SYSTEM"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_TERMINATED"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_DEADTHREAD"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG"] = "False"
				thread1["PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG"] = "False"
				thread1["StartAddress"] = ""
				thread1["State"] = ""
				thread1["WaitReason"] = "" 
				thread1["CreateTime"] = ""
				thread1["ExitTime"] = ""
				thread1["Owner_name"] = ""
				thread1["Owning_process"] = ""
				thread1["Attached_process"] = ""
				# Process fields necessaries to a new idEvent
				thread1["idEvent"] = 101
				thread1["ProcessId"] = pslist1["ProcessId"]
				thread1["ProcessGuid"] = pslist1["ProcessGuid"]
				thread1["SyspceId"] = pslist1["SyspceId"]
				thread1["Image"] = pslist1["Image"]
				thread1["Source"] = "Memory"
				thread1['computer'] = pslist1['computer']
				thread1["Owning_process"] = str(thread.owning_process().ImageFileName)
				thread1["Attached_process"] = str(thread.attached_process().ImageFileName)

				if "PS_CROSS_THREAD_FLAGS_IMPERSONATING" in str(thread.CrossThreadFlags):
					result[1] = "True"
					thread1["PS_CROSS_THREAD_FLAGS_IMPERSONATING"] = "True"
					
				if "PS_CROSS_THREAD_FLAGS_HIDEFROMDBG" in str(thread.CrossThreadFlags):
					result[2] = "True"
					thread1["PS_CROSS_THREAD_FLAGS_HIDEFROMDBG"] = "True"
					
				if "PS_CROSS_THREAD_FLAGS_SYSTEM" in str(thread.CrossThreadFlags):
					result[3] = "True"
					thread1["PS_CROSS_THREAD_FLAGS_SYSTEM"] = "True"
				
				if "PS_CROSS_THREAD_FLAGS_TERMINATED" in str(thread.CrossThreadFlags):
					thread1["PS_CROSS_THREAD_FLAGS_TERMINATED"] = "True"

				if "PS_CROSS_THREAD_FLAGS_DEADTHREAD" in str(thread.CrossThreadFlags):
					thread1["PS_CROSS_THREAD_FLAGS_DEADTHREAD"] = "True"

				if "PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION" in str(thread.CrossThreadFlags):
					thread1["PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION"] = "True"

				if "PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG" in str(thread.CrossThreadFlags):
					thread1["PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG"] = "True"

				if "PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG" in str(thread.CrossThreadFlags):
					thread1["PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG"] = "True"

				if owner:
					owner_name = str(owner.BaseDllName or 'None')
					thread1["Owner_name"] =  str(owner.BaseDllName or 'None')
				else:
					# If there is a unknown thread we break for loop
					owner_name = "Unknown"
					thread1["Owner_name"] = "Unknown"
					result[0] = "True"

				thread1["StartAddress"] = int(thread.StartAddress)
				thread1["State"] = str(thread.Tcb.State)
				thread1["WaitReason"] = str(thread.Tcb.WaitReason)
				thread1["ThreadId"] = int(thread.Cid.UniqueThread)
				thread1["CreateTime"] = str(thread.CreateTime)
				thread1["ExitTime"] = str(thread.ExitTime)
				#print "Add PID: " + str(thread1["ProcessId"]) + " TID: " + str(thread1["ThreadId"])
				vthreads.append(thread1)
				thread1 = {}
				#print vthreads
			
			return result


	def is_vad_empty(self, vad, address_space):
		 PAGE_SIZE = 0x1000
		 all_zero_page = "\x00" * PAGE_SIZE
		 offset = 0
		 while offset < vad.Length:
			next_addr = vad.Start + offset
			if (address_space.is_valid_address(next_addr) and address_space.read(next_addr, PAGE_SIZE) != all_zero_page):
				return False
			offset += PAGE_SIZE
		 return True

	def normalize_utc_time(self, utc_time):
		
		try:
			aux = utc_time.split(' ')
			normalized = aux[0] + ' ' + aux[1] + '.000'
		except:
			normalized = ''

		return normalized

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
		# Plugin psxview volatility 
		###########################

		if self._running:
			proc = psxv.PsXview(self._config)
		else:
			exit
		pslist1 = {}
		vprocess = []
		vthreads = []

		for offset, process, ps_sources in proc.calculate():
			
			pslist1['computer'] = computerid
			pslist1['Source'] = "Memory"
			pslist1['LogonGuid'] = "{" + computerid + "-0000-0000-0000-000000000000}"
			pslist1['CommandLine'] = str(process.Peb.ProcessParameters.CommandLine).replace('\"','')
			pslist1['CurrentDirectory'] = str(process.Peb.ProcessParameters.CurrentDirectory.DosPath)
			pslist1['Image'] = str(process.Peb.ProcessParameters.ImagePathName)
			pslist1['idEvent'] = 1 
			pslist1['UtcTime'] = self.normalize_utc_time(str(process.CreateTime)) 
			pslist1['ProcessId'] = str(int(process.UniqueProcessId))
			pslist1['ParentProcessId'] = str(int(process.InheritedFromUniqueProcessId))
			pslist1['TerminalSessionId'] = str(int(process.SessionId))
			pslist1['ExitTime'] = str(process.ExitTime)
			pslist1['BeingDebugged'] = str(process.Peb.BeingDebugged)
			pslist1['IsWow64'] = str(process.IsWow64)
			pslist1['NumHandles'] = str(int(process.ObjectTable.HandleCount))
			pslist1['NumThreads'] = str(int(process.ActiveThreads))
			pslist1['DllPath'] = str(process.Peb.ProcessParameters.DllPath)
			pslist1['ParentImage'] = ""
			pslist1['ParentCommandLine'] = ""
			pslist1['ParentProcessGuid'] = ""
			pslist1["unknown_threads"] = "False"
			pslist1['pslist'] = str(offset in ps_sources["pslist"])
			pslist1['psscan'] = str(offset in ps_sources["psscan"])
			pslist1['threadproc'] = str(offset in ps_sources["thrdproc"])
			pslist1['pspcid'] = str(offset in ps_sources["pspcid"])
			pslist1['csrss'] = str(offset in ps_sources["csrss"])
			pslist1['session'] = str(offset in ps_sources["session"])
			pslist1['deskthrd'] = str(offset in ps_sources["deskthrd"])

			# Exception with terminated process
			if pslist1['ExitTime'] != "1970-01-01 00:00:00 UTC+0000":
				pslist1['Image'] = str(process.ImageFileName)
				pslist1['CommandLine'] = str(process.ImageFileName)
			# Exception with kernel
			if pslist1['ProcessId'] == '4':
				pslist1['Image'] = "system"
				pslist1['CommandLine'] = "system"
				pslist1['TerminalSessionId'] = "0"
			# Exception with smss.exe
			if pslist1['Image'] == "\\SystemRoot\\System32\\smss.exe":
				pslist1['CommandLine'] = "C:\\Windows\\System32\\smss.exe"
				pslist1['Image'] = "C:\\Windows\\System32\\smss.exe"
				pslist1['TerminalSessionId'] = "0"

			# We build the "PROCESSGUID" to merge this event ID with Sysmon
			################################################################
			date_time_obj = datetime.datetime.strptime(pslist1["UtcTime"], '%Y-%m-%d %H:%M:%S.%f')
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

			## MODULES
			###########

			modules = ""
			if self._running:
				for module in process.get_load_modules():
					if module is not None:
						modules = modules + "," + str(module.FullDllName)

				pslist1['modules'] = modules
			else:
				exit

			## VADS
			########
			"""
			  This looks for private allocations that are committed, 
			  memory-resident, non-empty (not all zeros) and with an 
			  original protection that includes write and execute. 
			"""

			if self._running:
				pslist1["rwx_page"] = "False"
				vads = process.get_vads(vad_filter=process._injection_filter)
				for vad, address_space in vads:
					if self.is_vad_empty(vad, address_space):
						continue
					else:
						protect_flags = str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), ""))
						pslist1["rwx_page"] = "True"
						# With one non-empty VAD is enough
						break
			else:
				exit

			## THREADS
			###########
 
			if self._running:
				resultt = self.get_threads(process,vthreads,pslist1)
				# This process has one thread with StartAddress unknow
				pslist1["unknown_threads"]  = resultt[0]
				# This process has one thread with ActiveImpersonationInfo = 1 (Cross-Thread Flags in the ETHREAD)
				pslist1["PS_CROSS_THREAD_FLAGS_IMPERSONATING"] = resultt[1]
				# This process has one thread with HideFromDebugger = 1 (Cross-Thread Flags in the ETHREAD)
				pslist1["PS_CROSS_THREAD_FLAGS_HIDEFROMDBG"] = resultt[2]
				# This process has one thread with SystemThread = 1 (Cross-Thread Flags in the ETHREAD)
				pslist1["PS_CROSS_THREAD_FLAGS_SYSTEM"] = resultt[3]
			else:
				exit
			
			vprocess.append(pslist1)
			pslist1 = {}

		## We fill Parent fields with calculated information
		for p in vprocess:
			for x in vprocess:
				if p['ParentProcessId'] == x['ProcessId']:
					p['ParentImage'] = x['Image']
					p['ParentCommandLine'] = x['CommandLine']
					p['ParentProcessGuid'] = x['ProcessGuid']

		winlogon_fake_father = False
		winlogon_csrss_father = False
		wininit_fake_father = False
		wininit_csrss_father = False
		winlogon_father_pid = -1
		wininit_father_pid = -1

		for p in vprocess:
			## WINLOGON problems with hierarchy in memory dumps (SMSS.exe die then it's possible collisions by pid)
			if p['Image'].find('winlogon') != -1:
				for x in vprocess:
					if p['ParentProcessId'] == x['ParentProcessId']:
						if p['Image'].find('smss.exe') == -1:
							winlogon_fake_father = True
							winlogon_father_pid = p['ParentProcessId']
							break
				for z in vprocess:
					if z['Image'].find('csrss') != -1:
						if z['ParentProcessId'] == winlogon_father_pid:
							winlogon_csrss_father = True
							z['ParentImage'] = "smss.exe"
							z['ParentCommandLine'] = 'smss.exe'
							z['ParentProcessId'] = ''
							z['ParentProcessGuid'] = ''
							for z in vprocess:
								if z['Image'].find('winlogon') != -1:
									if z['ParentProcessId'] == winlogon_father_pid:
										z['ParentImage'] = 'smss.exe'
										z['ParentCommandLine'] = 'smss.exe'
										z['ParentProcessId'] = ''
										z['ParentProcessGuid'] = ''
									
			## WININIT problems with hierarchy in memory dumps (SMSS.exe die then it's possible collisions by pid)
			if p['Image'].find('wininit') != -1:
				for x in vprocess:
					if p['ParentProcessId'] == x['ParentProcessId']:
						if p['Image'].find('smss.exe') == -1:
							wininit_fake_father = True
							wininit_father_pid = p['ParentProcessId']
							break
				for z in vprocess:
					if z['Image'].find('csrss.exe') != -1:
						if z['ParentProcessId'] == wininit_father_pid:
							wininit_csrss_father = True
							z['ParentImage'] = "smss.exe"
							z['ParentCommandLine'] = 'smss.exe'
							z['ParentProcessId'] = ''
							z['ParentProcessGuid'] = ''
							for z in vprocess:
								if z['Image'].find('wininit') != -1:
									if z['ParentProcessId'] == wininit_father_pid:
										z['ParentImage'] = 'smss.exe'
										z['ParentCommandLine'] = 'smss.exe'
										z['ParentProcessId'] = ''
										z['ParentProcessGuid'] = ''

		###########################
		# Plugin privs volatility
		###########################

		if self._running:
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


		# To Send to the CORE
		############################
		events_list = vprocess
		self.send_message(events_list)
		thread_list = vthreads

		#f = open("debug_threads.txt","w+")
		#f.write(str(thread_list))
		#f.close()

		self.send_message(thread_list)
		self.terminate()
