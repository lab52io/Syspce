import logging
from syspce_input import Input
from syspce_message import *
import threading
import uuid
import hashlib
import datetime
import os
import json
import sys

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
import volatility.plugins.getservicesids as getservicesids
import re, ntpath


log = logging.getLogger('sysmoncorrelator')

# Example input memory execution:
# Param -p: Volatility profile 
# Param -m: Memory file
# python.exe syspce.py -m C:\Users\john\RAM.raw -p Win7SP1x64


well_known_sid_re = [
  (re.compile(r'S-1-5-[0-9-]+-500$'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501$'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502$'), 'KRBTGT'),
  (re.compile(r'S-1-5-[0-9-]+-512$'), 'Domain Admins'),
  (re.compile(r'S-1-5-[0-9-]+-513$'), 'Domain Users'),
  (re.compile(r'S-1-5-[0-9-]+-514$'), 'Domain Guests'),
  (re.compile(r'S-1-5-[0-9-]+-515$'), 'Domain Computers'),
  (re.compile(r'S-1-5-[0-9-]+-516$'), 'Domain Controllers'),
  (re.compile(r'S-1-5-[0-9-]+-517$'), 'Cert Publishers'),
  (re.compile(r'S-1-5-[0-9-]+-520$'), 'Group Policy Creator Owners'),
  (re.compile(r'S-1-5-[0-9-]+-533$'), 'RAS and IAS Servers'),
  (re.compile(r'S-1-5-5-[0-9]+-[0-9]+'), 'Logon Session'),
  (re.compile(r'S-1-5-21-[0-9-]+-518$'), 'Schema Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-519$'), 'Enterprise Admins'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'RAS Servers'),
  (re.compile(r'S-1-5-21-[0-9-]+-498$'), 'Enterprise Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-521$'), 'Read-Only Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-522$'), 'Cloneable Domain Controllers'),
  (re.compile(r'S-1-5-21-[0-9-]+-525$'), 'Protected Users'),
  (re.compile(r'S-1-5-21-[0-9-]+-553$'), 'Remote Access Services (RAS)'),
]

well_known_sids = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local (Users with the ability to log in locally)',
  'S-1-2-1': 'Console Logon (Users who are logged onto the physical console)',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization (Used by the default IIS user)',
  'S-1-5-18': 'System',
  'S-1-5-19': 'Local Service',
  'S-1-5-20': 'Network Service',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
  'S-1-5-32-568': 'BUILTIN\\IIS IUSRS',
  'S-1-5-32-569': 'Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
  'S-1-5-33': 'Write Restricted',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authentication',
  'S-1-5-80': 'NT Service',
  'S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952': 'WMI (Local Service)',
  'S-1-5-86-615999462-62705297-2911207457-59056572-3668589837': 'WMI (Network Service)',
  'S-1-5-1000': 'Other Organization',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
  'S-1-5-21-0-0-0-496': 'Compounded Authentication',
  'S-1-5-21-0-0-0-497': 'Claims Valid',
  'S-1-5-32-575': 'RDS Remote Application Services',
  'S-1-5-32-576': 'RDS Endpoint Servers',
  'S-1-5-32-577': 'RDS Management Servers',
  'S-1-5-32-578': 'Hyper-V Admins',
  'S-1-5-32-579': 'Access Control Assistance Ops',
  'S-1-5-32-580': 'Remote Management Users',
  'S-1-5-65-1': 'This Organization Certificate (Kerberos PAC)',
  'S-1-5-84-0-0-0-0-0': 'Usermode Drivers',
  'S-1-5-113': 'Local Account',
  'S-1-5-114': 'Local Account (Member of Administrators)',
  'S-1-5-1000': 'Other Organization',
  'S-1-15-2-1': 'Application Package Context',
  'S-1-18-1': 'Authentication Authority Asserted Identity',
  'S-1-18-2': 'Service Asserted Identity',
}

class InputVolatility(Input):

	def __init__(self, data_buffer_in,
				 data_condition_in, src, 
				 filepath, profile):

		Input.__init__(self, data_buffer_in,
					   data_condition_in,
					   src)

		print "[SYSPCE] Starting INPUT VOLATILITY analysis"
		# Relative Path
		filepath2 = ""
		if filepath.find(":\\") == -1:
			filepath2 = os.getcwd()+"\\"+filepath
			self.filepath = filepath2
			filepath = "file:///" + filepath2
		else:
		# Absolute path
			self.filepath = filepath
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

	''' 
	Name: get_registry_key()
	Params: volatility class
	Return: Return value from "self._config.KEY"
	Description: This function returns registry value fixed in in self._config.KEY
	'''
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
				thread1["PsCrossThreadFlagsImpersonating"] = "False"
				thread1["PsCrossThreadFlagsHideFromDbg"] = "False"
				thread1["PsCrossThreadFlagsSystem"] = "False"
				thread1["PsCrossThreadFlagsTerminated"] = "False"
				thread1["PsCrossThreadFlagsDeadThread"] = "False"
				thread1["PsCrossThreadFlagsBreakOnTermination"] = "False"
				thread1["PsCrossThreadFlagsSkipCreationMsg"] = "False"
				thread1["PsCrossThreadFlagsSkipTerminationMsg"] = "False"
				thread1["StartAddress"] = ""
				thread1["State"] = ""
				thread1["WaitReason"] = "" 
				thread1["CreateTime"] = ""
				thread1["ExitTime"] = ""
				thread1["OwnerName"] = ""
				thread1["OwningProcess"] = ""
				thread1["AttachedProcess"] = ""
				thread1["Win32StartAddress"] = ""
				# Process fields necessaries to a new idEvent
				thread1["idEvent"] = 101
				thread1["ProcessId"] = pslist1["ProcessId"]
				thread1["ProcessGuid"] = pslist1["ProcessGuid"]
				thread1["SyspceId"] = pslist1["SyspceId"]
				thread1["Image"] = pslist1["Image"]
				thread1["Source"] = "Memory"
				thread1['computer'] = pslist1['computer']
				thread1["OwningProcess"] = str(thread.owning_process().ImageFileName)
				thread1["AttachedProcess"] = str(thread.attached_process().ImageFileName)

				if "PS_CROSS_THREAD_FLAGS_IMPERSONATING" in str(thread.CrossThreadFlags):
					result[1] = "True"
					thread1["PsCrossThreadFlagsImpersonating"] = "True"
					
				if "PS_CROSS_THREAD_FLAGS_HIDEFROMDBG" in str(thread.CrossThreadFlags):
					result[2] = "True"
					thread1["PsCrossThreadFlagsHideFromDbg"] = "True"
					
				if "PS_CROSS_THREAD_FLAGS_SYSTEM" in str(thread.CrossThreadFlags):
					result[3] = "True"
					thread1["PsCrossThreadFlagsSystem"] = "True"
				
				if "PS_CROSS_THREAD_FLAGS_TERMINATED" in str(thread.CrossThreadFlags):
					thread1["PsCrossThreadFlagsTerminated"] = "True"

				if "PS_CROSS_THREAD_FLAGS_DEADTHREAD" in str(thread.CrossThreadFlags):
					thread1["PsCrossThreadFlagsDeadThread"] = "True"

				if "PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION" in str(thread.CrossThreadFlags):
					thread1["PsCrossThreadFlagsBreakOnTermination"] = "True"

				if "PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG" in str(thread.CrossThreadFlags):
					thread1["PsCrossThreadFlagsSkipCreationMsg"] = "True"

				if "PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG" in str(thread.CrossThreadFlags):
					thread1["PsCrossThreadFlagsSkipTerminationMsg"] = "True"

				if owner:
					owner_name = str(owner.BaseDllName or 'None')
					thread1["OwnerName"] =  str(owner.BaseDllName or 'None')
				else:
					owner_name = "Unknown"
					thread1["OwnerName"] = "Unknown"
					result[0] = "True"

				thread1["StartAddress"] = str(thread.StartAddress)
				thread1["State"] = str(thread.Tcb.State)
				thread1["WaitReason"] = str(thread.Tcb.WaitReason)
				thread1["ThreadId"] = int(thread.Cid.UniqueThread)
				thread1["CreateTime"] = str(thread.CreateTime)
				thread1["ExitTime"] = str(thread.ExitTime)
				thread1["Win32StartAddress"] = str(thread.Win32StartAddress)
				vthreads.append(thread1)
				thread1 = {}
			
			return result

	''' 
	Name: is_vad_empty()
	Params: 
	Return: True o False if VAD is empty
	Description: This function detect if VAD is empty
	'''
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

	def sha256hash(self,filename):
		
		sha256_hash = hashlib.sha256()
		result_hash = ""
		with open(filename,"rb") as f:
			# Read and update hash string value in blocks of 4K
			for byte_block in iter(lambda: f.read(4096),b""):
				sha256_hash.update(byte_block)
			#print(sha256_hash.hexdigest())
			result_hash = sha256_hash.hexdigest()
		return result_hash

	def check_fields(self,pslist1):

			# Check PEB empty fileds

			#if pslist1['CommandLine'] == "":
			#	print "[SYSPCE] Warning commandline empty in: " + str(pslist1['ProcessId']) + " Image: " + str(pslist1['Image'])
			#if pslist1['CurrentDirectory'] == "":
			#	print "[SYSPCE] Warning CurrentDirectory empty in: " + str(pslist1['ProcessId']) + " Image: "+ str(pslist1['Image'])

			# Check EPROCESS empty or odd fields

			if pslist1['ProcessId'] == "":
				print "[SYSPCE] Warning ProcessId empty in: " + " Image: "+ str(pslist1['Image'])

			if pslist1['ParentProcessId'] == "":
				print "[SYSPCE] Warning ParentProcessId empty in: " + str(pslist1['ProcessId']) + " Image: "+ str(pslist1['Image'])

			if pslist1['TerminalSessionId'] == "-1":
				print "[SYSPCE] Warning TerminalSessionId is -1: " + " Image: "+ str(pslist1['Image']) + " " + str(pslist1['ProcessId'])



	def find_sid_re(self,sid_string, sid_re_list):
		for reg, name in sid_re_list:
			if reg.search(sid_string):
				return name

	def lookup_user_sids(self,config):

		regapi = registryapi.RegistryApi(config)
		regapi.set_current("hklm")

		key = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
		val = "ProfileImagePath"

		sids = {}

		for subkey in regapi.reg_get_all_subkeys(None, key = key):
			sid = str(subkey.Name)
			path = regapi.reg_get_value(None, key = "", value = val, given_root = subkey)
			if path:
				path = str(path).replace("\x00", "")
				user = ntpath.basename(path)
				sids[sid] = user

		return sids


	def do_action(self):

		###########################
		# Memory analysis CACHE
		###########################

		print "\n[SYSPCE] Calculating memory hash: "+self.filepath
		hresult = self.sha256hash(self.filepath)
		print "[SYSPCE] SHA256: " + hresult
		cache = False
		# WE CHECK IF THIS MEMORY HAS CACHE
		cache_process = hresult+"_"+"process"
		if os.path.exists(cache_process):
			with open (cache_process, 'r') as outfile:
				vprocess = json.load(outfile)
				cache = True
				outfile.close()
		cache_threads = hresult+"_"+"threads"
		if os.path.exists(cache_threads):
			with open (cache_threads, 'r') as outfile:
				vthreads = json.load(outfile)
				cache = True
				outfile.close()

		cache_vads = hresult+"_"+"vads"
		if os.path.exists(cache_vads):
			with open (cache_vads, 'r') as outfile:
				vvads = json.load(outfile)
				cache = True
				outfile.close()
		
		cache_tokens = hresult+"_"+"tokens"
		if os.path.exists(cache_tokens):
			with open (cache_tokens, 'r') as outfile:
				vtokens = json.load(outfile)
				cache = True
				outfile.close()
		if cache:
			print "[SYSPCE] Using process cache file: "+cache_process
			print "[SYSPCE] Using threads cache file: "+cache_threads
			print "[SYSPCE] Using threads cache file: "+cache_vads
			print "[SYSPCE] Using threads cache file: "+cache_tokens
			print "\n"
			self.send_message(vprocess)
			self.send_message(vthreads)
			self.send_message(vvads)
			self.send_message(vtokens)
			self.terminate()
		

		###########################
		# Get MachineGUID
		###########################
		if self._running:
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

			print "[SYSPCE] MACHINEGUID detected: " + str(computerid)

		###########################
		# Plugin psxview volatility 
		###########################

		if self._running:
			proc = psxv.PsXview(self._config)

			pslist1 = {}
			vprocess = []
			vthreads = []
			vvads = []
			vtokens = []

			for offset, process, ps_sources in proc.calculate():

				# Check if PEB structure is ready (psxview is a pool tag plugin)
				PEB = str(process.Peb)
				peb_empty = False
				if PEB == "":
					peb_empty = True
			
				# PEB 
				pslist1['CommandLine'] = str(process.Peb.ProcessParameters.CommandLine).replace('\"','')
				pslist1['CurrentDirectory'] = str(process.Peb.ProcessParameters.CurrentDirectory.DosPath)
				pslist1['Image'] = str(process.Peb.ProcessParameters.ImagePathName)
				pslist1['BeingDebugged'] = str(process.Peb.BeingDebugged)
				pslist1['DllPath'] = str(process.Peb.ProcessParameters.DllPath)
				# EPROCESS
				pslist1['UtcTime'] = self.normalize_utc_time(str(process.CreateTime)) 
				pslist1['ProcessId'] = str(int(process.UniqueProcessId))
				pslist1['ParentProcessId'] = str(int(process.InheritedFromUniqueProcessId))
				pslist1['TerminalSessionId'] = str(int(process.SessionId))
				pslist1['ExitTime'] = str(process.ExitTime)
				pslist1['IsWow64'] = str(process.IsWow64)
				pslist1['NumHandles'] = str(int(process.ObjectTable.HandleCount))
				pslist1['NumThreads'] = str(int(process.ActiveThreads))
				pslist1['computer'] = computerid
				pslist1['Source'] = "Memory"
				pslist1['LogonGuid'] = "{" + computerid + "-0000-0000-0000-000000000000}"
				pslist1['idEvent'] = 1 
				pslist1['IntegrityLevel'] = ""  # por calcular
				pslist1['User'] = ""  # por calcular
				pslist1['ParentImage'] = ""
				pslist1['ParentCommandLine'] = ""
				pslist1['ParentProcessGuid'] = ""
				pslist1["UnknownThreads"] = "False"
				pslist1['PsList'] = str(offset in ps_sources["pslist"])
				pslist1['PsScan'] = str(offset in ps_sources["psscan"])
				pslist1['ThreadProc'] = str(offset in ps_sources["thrdproc"])
				pslist1['PsPcid'] = str(offset in ps_sources["pspcid"])
				pslist1['Csrss'] = str(offset in ps_sources["csrss"])
				pslist1['Session'] = str(offset in ps_sources["session"])
				pslist1['DeskThrd'] = str(offset in ps_sources["deskthrd"])

				# Exception (I) If we don't find smss.exe in PEB structure, we get ImageFileName from EPROCESS.
				if pslist1['Image'] == "":
					pslist1['Image'] = str(process.ImageFileName)
					if pslist1['Image'] == "smss.exe":
						pslist1['CommandLine'] = "C:\\Windows\\System32\\smss.exe"
						pslist1['Image'] = "C:\\Windows\\System32\\smss.exe"
						pslist1['TerminalSessionId'] = "0"

				# Exception (II) Exception with terminated process
				if pslist1['ExitTime'] != "1970-01-01 00:00:00 UTC+0000":
					pslist1['Image'] = str(process.ImageFileName)
					pslist1['CommandLine'] = str(process.ImageFileName)

				# Exception (III) with kernel
				if pslist1['ProcessId'] == '4' and pslist1['TerminalSessionId'] == "-1":
					pslist1['Image'] = "system"
					pslist1['CommandLine'] = "system"
					pslist1['TerminalSessionId'] = "0"
					pslist1['IntegrityLevel'] = "System"
					pslist1['User'] = "System"  
				# Exception (IV) with smss.exe
				if pslist1['Image'] == "\\SystemRoot\\System32\\smss.exe" and pslist1['TerminalSessionId'] == "-1":
					pslist1['CommandLine'] = "C:\\Windows\\System32\\smss.exe"
					pslist1['Image'] = "C:\\Windows\\System32\\smss.exe"
					pslist1['CurrentDirectory'] = "C:\\Windows\\System32\\"
					pslist1['TerminalSessionId'] = "0"


				# We build the "PROCESSGUID" to MERGE this event ID with Sysmon
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

				###########
				# Process Integrity Level and User
				###########

				tokenprocess = process.get_token()
				user_sids = self.lookup_user_sids(self._config)
				if tokenprocess.is_valid():
					cont = 0
					for sid_string in tokenprocess.get_sids():
						if sid_string in well_known_sids:
									sid_name = well_known_sids[sid_string]
						elif sid_string in getservicesids.servicesids:
									sid_name = getservicesids.servicesids[sid_string]
						elif sid_string in user_sids:
									sid_name = user_sids[sid_string]
						else:
							sid_name_re = self.find_sid_re(sid_string, well_known_sid_re)
							if sid_name_re:
								sid_name = sid_name_re
							else:
								sid_name = ""
				
						if cont == 0:
							pslist1["User"] = str(sid_name)
							cont = cont + 1 
				
						if sid_string == "S-1-16-8192":
							pslist1["IntegrityLevel"] = "Medium"
						elif sid_string == "S-1-16-8448":
							pslist1["IntegrityLevel"] = "MediumPlus"
						elif sid_string == "S-1-16-4096":
							pslist1["IntegrityLevel"] = "Low"
						elif sid_string == "S-1-16-12288":
							pslist1["IntegrityLevel"] = "High"
						elif sid_string == "S-1-16-16384":
							pslist1["IntegrityLevel"] = "System"
					

				###########
				## TOKENS
				###########

				token1 = {}
				if self._running:
					#user_sids = self.lookup_user_sids(self._config)
					for handle in process.ObjectTable.handles():
						token = handle.dereference_as("_TOKEN")
						if token.is_valid():

							token1["idEvent"] = 103
							token1["ProcessId"] = pslist1["ProcessId"]
							token1["ProcessGuid"] = pslist1["ProcessGuid"]
							token1["SyspceId"] = pslist1["SyspceId"]
							token1["Image"] = pslist1["Image"]
							token1["Source"] = "Memory"
							token1['computer'] = pslist1['computer']
							token1["TokenOffset"] = ""
							token1["TokenHandleValue"] = ""
							token1["TokenGrantAccess"] = ""
							token1["User"] = ""
							token1["UserSid"] = ""
							token1["IntegrityToken"] = ""
							token1["IntegritySid"] = ""

							token_with_sid = 0
							list_tokens = token.get_sids()
							cont = 0

							for sid_string in list_tokens:
								if sid_string in well_known_sids:
									sid_name = well_known_sids[sid_string]
								elif sid_string in getservicesids.servicesids:
									sid_name = getservicesids.servicesids[sid_string]
								elif sid_string in user_sids:
									sid_name = user_sids[sid_string]
								else:
									sid_name_re = self.find_sid_re(sid_string, well_known_sid_re)
									if sid_name_re:
										sid_name = sid_name_re
									else:
										sid_name = ""

								if cont == 0:
									token1["UserSid"] = str(sid_string)
									token1["User"] = str(sid_name)
									cont = cont + 1
								token_with_sid = 1
								#TOKEN INTEGRITY LEVEL
								if sid_string == "S-1-16-8192":
									token1["IntegrityToken"] = "Medium"
									token1["IntegritySid"] = str(sid_string)
								elif sid_string == "S-1-16-8448":
									token1["IntegrityToken"] = "MediumPlus"
									token1["IntegritySid"] = str(sid_string)
								elif sid_string == "S-1-16-4096":
									token1["IntegrityToken"] = "Low"
									token1["IntegritySid"] = str(sid_string)
								elif sid_string == "S-1-16-12288":
									token1["IntegrityToken"] = "High"
									token1["IntegritySid"] = str(sid_string)
								elif sid_string == "S-1-16-16384":
									token1["IntegrityToken"] = "System"
									token1["IntegritySid"] = str(sid_string)

							if token_with_sid:
								token1["TokenOffset"] = str(handle.Body.obj_offset)
								token1["TokenHandleValue"] = str(handle.HandleValue)
								token1["TokenGrantAccess"] = str(handle.GrantedAccess)
								token_with_sid = 0
								vtokens.append(token1)
							
							token1 = {}
							
				else:
					sys.exit()


				## MODULES
				###########

				modules = ""
				if self._running:
					for module in process.get_load_modules():
						if module is not None:
							modules = modules + "," + str(module.FullDllName)

					pslist1['Modules'] = modules
				else:
					sys.exit()

				## VADS
				########
				"""
				  This looks for private allocations that are committed, 
				  memory-resident, non-empty (not all zeros) and with an 
				  original protection that includes write and execute. 
				"""

				vad1 = {}
				if self._running:
					pslist1["RwxPage"] = "False"
					vads = process.get_vads(vad_filter=process._injection_filter)
					#vads = process.get_vads()
					for vad, address_space in vads:
						if self.is_vad_empty(vad, address_space):
							vad1["VadEmpty"] = "True"
						else:
							vad1["VadEmpty"] = "False"

						protect_flags = str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), ""))
						# Process fields necessaries to a new idEvent
						vad1["idEvent"] = 102
						vad1["ProcessId"] = pslist1["ProcessId"]
						vad1["ProcessGuid"] = pslist1["ProcessGuid"]
						vad1["SyspceId"] = pslist1["SyspceId"]
						vad1["Image"] = pslist1["Image"]
						vad1["Source"] = "Memory"
						vad1['computer'] = pslist1['computer']
						# Fields VADs
						vad1["VadNode"] = str(vad.obj_offset)
						vad1["VadProtection"] = str(protect_flags)
						vad1["VadStart"] = str(vad.Start)
						vad1["VadEnd"] = str(vad.End)
						
						vvads.append(vad1)
						vad1 = {}
						pslist1["RwxPage"] = "True"
				else:
					sys.exit()

				## THREADS
				###########
				if self._running:
					self.get_threads(process,vthreads,pslist1)
				else:
					sys.exit()
			
				vprocess.append(pslist1)
				pslist1 = {}

			## We fill Parent fields with calculated information
			computer_alerts = 0
			for p in vprocess:
				for x in vprocess:
					if p['ParentProcessId'] == x['ProcessId']:
						p['ParentImage'] = x['Image']
						p['ParentCommandLine'] = x['CommandLine']
						p['ParentProcessGuid'] = x['ProcessGuid']
						p['RealParent'] = x['Image']
						# Exception (VII) with lsass.exe
						if p["Image"].find("lsass.exe") != -1 and p["ParentImage"].find("wininit.exe")!= -1 and p['TerminalSessionId'] == "0":
							p['CommandLine'] = "C:\\Windows\\System32\\lsass.exe"
							p['CurrentDirectory'] = "C:\\Windows\\System32\\"
						# Exception (V) with svchost.exe
						if p["Image"].find("svchost.exe") != -1 and (p['TerminalSessionId'] == "0" or p['TerminalSessionId'] == "-1") and p["ParentImage"].find("services.exe") != -1:
							p['CommandLine'] = "C:\\Windows\\System32\\svchost.exe"
							p['Image'] = "C:\\Windows\\System32\\svchost.exe"
							p['CurrentDirectory'] = "C:\\Windows\\System32\\"
							p['TerminalSessionId'] = "0"
						# Exception (VI) with sppsvc.exe
						if p["Image"].find("sppsvc.exe") != -1 and p['TerminalSessionId'] == "-1" and p["ParentImage"].find("services.exe") != -1:
							p['CommandLine'] = "C:\\Windows\\System32\\sppsvc.exe"
							p['Image'] = "C:\\Windows\\System32\\sppsvc.exe"
							p['CurrentDirectory'] = "C:\\Windows\\System32\\"
							p['TerminalSessionId'] = "0"
						# Check computer 
						self.check_fields(p)
					
						if p['computer'] == 'ffffffff' and computer_alerts == 0:
							print "[SYSPCE] Warning computer is ffffffff, problems while we try to read registry key"
							computer_alerts = 1

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
								z['RealParent'] = "smss.exe"
								z['ParentProcessId'] = ''
								z['ParentProcessGuid'] = ''
								for z in vprocess:
									if z['Image'].find('winlogon') != -1:
										if z['ParentProcessId'] == winlogon_father_pid:
											z['ParentImage'] = 'smss.exe'
											z['ParentCommandLine'] = 'smss.exe'
											z['RealParent'] = 'smss.exe'
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
		if self._running:
			events_list = vprocess
			self.send_message(events_list)
			thread_list = vthreads
			self.send_message(thread_list)
			vads_list = vvads
			self.send_message(vads_list)
			token_list = vtokens
			self.send_message(token_list)

		

			# WE BUILD MEMORY CACHE (PROCESS, THREADS AND VADS)
			cache_process = hresult+"_"+"process"
			if not os.path.exists(cache_process):
				with open (cache_process, 'w') as outfile:
					json.dump(vprocess,outfile)
					outfile.close()

			cache_threads = hresult+"_"+"threads"
			if not os.path.exists(cache_threads):
				with open (cache_threads, 'w') as outfile:
					json.dump(vthreads,outfile)
					outfile.close()
		
			cache_vads = hresult+"_"+"vads"
			if not os.path.exists(cache_vads):
				with open (cache_vads, 'w') as outfile:
					json.dump(vvads,outfile)
					outfile.close()
		
			cache_tokens = hresult+"_"+"tokens"
			if not os.path.exists(cache_tokens):
				with open (cache_tokens, 'w') as outfile:
					json.dump(vtokens,outfile)
					outfile.close()
