import re
from operator import itemgetter
from itertools import groupby
import pexpect
import sys
import datetime
import os
import subprocess
import getpass
import logging
from CiscoDevice import Switch, Router
import ColorPrint as cp

class CiscoHelper:

	def __init__(self):
		self.child = None
		self.logging = False
		self.start_ip = ""
		self.start_hostname = ""
		self.username = ""
		self.password = ""
		self.en_password = ""

	def signin(self):
		"""Prompts user for Start IP address, username, password, and enable password.

		Sets the responses to the corresponding class instance attributes.
		"""

		start_ip = str(input("Start IP Address: "))
		while not start_ip.strip():
			cp.printc(cp.FAIL, "[-]Please enter a Start IP Address")
			start_ip = str(input("Start IP Address: "))
		
		self.start_ip = start_ip
		self.username = str(input("Username: "))
		self.password = getpass.getpass("Password: ")
		self.en_password = getpass.getpass("Enable Password: ")

	def spawn(self):
		"""Initializes `self.child` as pexpect.spawn() object.

		Collects ACS account information to login, initializes self.child attributes
		to the return object from pexpect.spawn, and attempts to connect to `self.start_ip`.

		In the event of a timeout, bad password, or any exception, the program exits.
		Without sys.exit() after a failure, an ACS account could become locked out after
		multiple failed attempts.
		"""

		# Gather login credentials before proceeding.
		self.signin()

		try:
			cp.printc(cp.OKBLUE, "[*]Logging into Start IP ({0}) as {1}".format(self.start_ip,self.username))
			# Spawn SSH session
			self.child = pexpect.spawn("ssh {0}@{1}".format(self.username, self.start_ip),timeout=15,encoding="utf-8")
			# If self.logging is True, print the entire output of the SSH session to sys.stdout.
			if self.logging is True:
				self.child.logfile = sys.stdout
			self.child.timeout = 30
			# Check for the password prompt, then send the first password.
			self.child.expect("assword:")
			self.child.sendline(self.password)
			# If the password prompt reappears, the password was incorrect. Exits application if this occurs.
			failedAuth = self.child.expect([">","assword:"],timeout=15)
			if (failedAuth==1):
				logging.critical("Bad password")
				sys.exit("[!]Bad password. Exiting...")
			# Once logged in, attempts to enter ENABLE mode and send the ENABLE password.
			self.child.sendline("en")
			self.child.expect("assword:",timeout=15)
			self.child.sendline(self.en_password)
			# If the ENABLE password fails, the application exits to avoid locking the account for too many failed attempts.
			failedEnAuth = self.child.expect(["#",">"],timeout=15)
			if (failedEnAuth==1):
				logging.critical("Bad ENABLE password")
				sys.exit("[!]Bad ENABLE password. Exiting...")
		except Exception as error:
			# For a timeout, or any other error(s) not caught, the application exits.
			cp.printc(cp.FAIL, "[-]Start IP timed out. Error: \n{0}".format(str(error)))
			logging.critical("Start IP timed out with an error")
			sys.exit("Error in spawn")
		# Successfully logged into start device and entered ENABLE mode.
		logging.info("Spawned a child instance connected to Start IP")
		cp.printc(cp.OKGREEN, "[+]Connected to Start IP")
		# Saves start hostname to self for future comparison.
		self.start_hostname = self.location()	

	def exit_cmd(self):
		"""Exits device

		Attempts to sendline "exit" to `self.child` to disconnect from device.

		Returns:
			True if successful, False otherwise
		"""

		try:
			self.child.sendline("exit")
			self.child.expect("#",timeout=20)
			return True
		except:
			return False

	def location(self):
		"""Parses hostname from connected device.

		Splits the `self.child.before` attribute by double newlines, parsing out the hostname.

		Returns:
			str: Hostname if found, False otherwise
		"""

		if self.child != None:
			loc = self.child.before.split("\r\n")
			return loc[-1].strip()
		else:
			return False

	def connect(self,host):
		"""Connect to host.

		Pings the host first. If succsesful, checks location to verify that `self.child`
		is currently connected to Start IP. Loops for the duration of `max_attempts` to exit
		from current device, if not located in Start IP. After successfully exiting to
		Start IP, attempt to SSH to host, send credentials, and remove the terminal length
		from the switch/router.

		Args:
			host (str): Hostname or IP address of device to connect to

		Returns:
			True if successful, False otherwise
		"""
		
		cp.printc(cp.WARNING, "~"*80)
		# Pings host before attempting to connect, which saves time over letting the host timeout.
		cp.printc(cp.OKBLUE, "[*]Pinging {0}".format(host))
		if CiscoHelper.ping(host):
			cp.printc(cp.OKGREEN, "[+]{0} is online".format(host))
		else:
			cp.printc(cp.FAIL, "[-]{0} is offline".format(host))
			return False
		# Verifies the previous connection is disconnected before proceeding onto the next.
		max_attempts = 3
		attempt = 0
		while attempt < max_attempts:
			if self.child == None or self.location() == False:
				cp.printc(cp.WARNING, "[!]Child == None")
				return False
			elif self.location() != self.start_hostname:
				logging.info("Attempted connect while not in Start Device. Disconnecting")
				cp.printc(cp.OKBLUE, "[*]Disconnecting from {0}".format(self.location()))	
				self.exit_cmd()
				loc = self.location()
				attempt += 1
			else:
				break
		try:
			# Attempts to connect child SSH session to new host.
			self.child.sendline("ssh -l {0} {1}".format(self.username, host))
			cp.printc(cp.OKBLUE, "[*]Connecting to {0}".format(host))
			didConnect = self.child.expect(["password","%"],timeout=30)
			# If the password prompt does not appear, an error has occured, and the host is logged as a failure.
			if didConnect != 0:
				logging.warning("Failed to connect to {0}. Password prompt returned unknown string".format(host))
				raise Exception("Failure")
		except:
			# For timeouts, or any other errors, the host is logged as a failure.
			cp.printc(cp.FAIL, "[-]Failed to connect to {0}".format(host))
			logging.warning("Failed to connect to {0}".format(host))
			return False
		try:
			# Attempts to send first password to new host.
			self.child.sendline(self.password)
			badAuth = self.child.expect([">","password"],timeout=25)
			# If password fails, the application exits to avoid locking out the account.
			if (badAuth==1):
				logging.critical("Bad password")
				sys.exit("[-]Bad password on {0}".format(host))
			# Attempts to send ENABLE password to new host.
			self.child.sendline("en")
			self.child.sendline(self.en_password)
			badEnAuth = self.child.expect(["#",">"],timeout=25)
			# If the ENABLE password fails, the application exits to avoid locking out the account.
			if (badEnAuth==1):
				logging.critical("Bad ENABLE password")
				sys.exit("[-]Bad EN password on {0}".format(host))
		except:
			# Any other errors that occur during the authentication portion are logged as failures and exit the application.
			logging.critical("Authentication failure on {0}".format(host))
			sys.exit("[-]Authentication failed on {0}".format(host))
		try:
			# Remove breaks for commands with long outputs to ease parsing.
			self.child.sendline("terminal length 0")
			self.child.expect("#")
		except:
			logging.critical("'Terminal Length 0' failed on {0}".format(host))
			sys.exit("[-]Terminal Length 0 failed on {0}".format(host))
		cp.printc(cp.OKGREEN, "[+]Connected to {0}".format(host))
		# If the new host is successfully connected to and the `terminal length 0` command works, returns True.
		return True

	def config_ports(self,ports,commands,is_range=False,time_out=15):
		"""Send configuration to ports givens.

		Verifies device is in global menu, then enters configuration terminal. Interfaces
		either range or specific ports, depending on `is_range` parameter. Sends each command
		individually, and backs out to the global menu once finished.

		Args:
			ports (list): 1D list of ports, or 2D list of port ranges
			commands (list): List of commands to send
			is_range (bool): Flag to distinguish if ports is 1D or 2D list
			time_out (int): Timeout time for commands

		Returns:
			True if successful, False otherwise
		"""

		try:
			# Backs the host out from any options, like `configuration terminal`.
			self.child.sendline("end")
			self.child.expect("#")
			# Enters the `configuration terminal` to begin sending commands
			self.child.sendline("conf t")
			self.child.expect("#")
			# If the bool `is_range` is True, the range needs to be chu
			if is_range:
				# For a range, a 2D list of port ranges is sent. Begin looping through each list, or `chunk`, of port ranges.
				for chunk in ports:
					# Once inside the list of ports, begin looping through the individual port ranges, or `item`.
					for item in chunk:
						self.child.sendline("int range {0}".format(item))
						self.child.expect("#")
						# Send each command from `commands` to the current interface range iteration.
						for cmd in commands:
							self.child.sendline(cmd)
							# Wait for a response. 
							worked = self.child.expect(['#','%'], timeout=time_out)

							# This section can be used to escape from continuing commands in the event of a failure.
							# For trivial commands, this can be left commented out to continue through the list of commands.
							# If used on a network with multiple models and firmwares of Cisco switches/routers, there are bound
							# to be discrepencies in the commands, causing an error on execution.
							#if worked == 1:
								# Error in command - Exit before doing (possible) damage.
								#return False
			else:
				# `is_range` is False, which means a 1D list of ports was sent. Begin looping through the ports in the list `ports`.
				for item in ports:
					self.child.sendline("int {0}".format(item))
					self.child.expect("#")
					# Send each command from `commands` to the current interface port iteration.
					for cmd in commands:
						self.child.sendline(cmd)
						cp.printc(cp.OKBLUE, "[*]Sending command: {0} to port: {1}".format(cmd, item))
						worked = self.child.expect(['#','%'], timeout=time_out)

						# This section can be used to escape from continuing commands in the event of a failure.
						# For trivial commands, this can be left commented out to continue through the list of commands.
						# If used on a network with multiple models and firmwares of Cisco switches/routers, there are bound
						# to be discrepencies in the commands, causing an error on execution.
						#if worked == 1:
							# Error in command - Exit before doing (possible) damage.
							#return False
			# Exit from the `configuration terminal` menu.
			self.child.sendline("end")
			self.child.expect("#")
		except:
			# For any errors raised in the configuration portion, return False to indicate a failure.
			return False

		# After executing all commands on either the ports or port ranges, return True to indicate success.	
		return True

	def search_mac(self,mac):
		"""Search for specific MAC address

		Performs a `show mac address | i` command with the `mac` parameter. Prints
		the results of the command.

		Args:
			mac (str): MAC address to search for.
		"""

		try:
			# Parse alphanumeric characters from `mac`.
			safe_mac = ''.join(ch for ch in mac if ch.isalnum())
			# `last4mac` represents the last four characters from the MAC address `safe_mac`.
			last4mac = safe_mac[-4:]
			# Find the trunk ports from the `self.child` SSH location.
			trunks = self.get_trunk_ports(self.child)
			# Verify the current device is not in `configuration terminal` or any menu.
			self.child.sendline("end")
			self.child.expect("#")
			# Search for the MAC address with the `show mac address` command with a filter for the specified MAC address.
			self.child.sendline("sh mac add | i {0}".format(last4mac))
			results = child.before
			# Return the output from the command.
			return results
		except:
			# If any exceptions are raised, return False to indicate failure.
			cp.printc(cp.FAIL, "[-]Failure in search_mac function")
			return False

	def exclude_trunks(self,ports):
		"""Removes trunk ports from list of ports

		Declares and initializes `trunks` to the return value from `self.get_trunk_ports()`.
		Removes the found trunk ports from the ports list using set()'s.

		Args:
			ports (list): 1D list of ports

		Returns:
			list: 1D list of ports, excluding trunk ports
		"""

		trunks = self.get_trunk_ports()
		return list(set(ports)^set(trunks))

	def get_trunk_ports(self):
		"""Gather 1D list of trunk ports, based on interace status.

		Sends `show interface status | i trunk` command to narrow list of ports
		down to only trunk ports. Parses ports from this output 
		by using `CiscoHelper.parse_ports`.

		Returns:
			list: 1D list of trunk ports, False otherwise
		"""

		try:
			# Gather the trunk interfaces by filtering the `show interface status` command by trunks.
			self.child.sendline("sh int status | i trunk") 
			self.child.expect("#")
			raw_trunk = self.child.before
			# Parse the specific ports from the `self.child.before` output.
			trunks = CiscoHelper.parse_ports(raw_trunk)
			# If trunk ports are found and parsed, return them.
			if trunks:
				return trunks
			# No trunk ports were found.
			else:
				logging.info("No Trunk Ports found with get_trunk_ports function")
				cp.printc(cp.FAIL, "[-]No Trunk Ports found with get_trunk_ports function")
				return False
		except Exception as error:
			# An exception that is raised in this function prints the error and returns False.
			logging.warning("Error with get_trunk_ports function:\n{0}".format(str(error)))
			cp.printc(cp.FAIL, "[-]Error with get_trunk_ports function:\n{0}".format(str(error)))
			return False

	def save(self):
		"""Writes running configurations to start configurations.

		Attempts to send the command `wr` to device, and timeouts after 90 seconds.
		"""

		cp.printc(cp.OKBLUE, "[*]Saving configuration changes")

		try:
			# Write the running configurations to the start configurations with the `write` command.
			self.child.sendline("wr")
			self.child.expect("#", timeout=90)
			cp.printc(cp.OKGREEN, "[+]Successfully saved configuration changes")
		except:
			# For any exception raised (typically a timeout), print a failure message.
			logging.warning("Failed to save configuration changes")
			cp.printc(cp.FAIL, "[-]Failed to save configuration changes")

	def backup_remote(self,username,password,server_ip,server_dir="/"):
		"""Backs up running configurations to remote server.
			
		Copies the running configuration over SCP to a remote server.

		Args:
			username (str): Username for remote server account.
			password (str): Password for remote server account.
			server_ip (str): IP address of remote server.
			server_dir (str): Server directory to store the configuration. Default is ``/``
		"""

		cp.printc(cp.OKBLUE, "[*]Backing up configuration to {0}{1}".format(server_ip,server_dir))

		try:
			# Copy the running configuration to the server specified.
			self.child.sendline("copy run scp://{0}:{1}@{2}{3}".format(username,password,server_ip,server_dir))
			# Navigate the interactive menu to confirm the save.
			self.child.sendline('\r\n')
			self.child.expect('.')
			self.child.sendline('\r\n')
			self.child.expect('.')
			self.child.sendline('\r\n')
			# If the `#` symbol is returned, the backed was successful.
			self.child.expect('#')
			cp.printc(cp.OKGREEN, "[+]Successfully backed up configuration")
		except:
			# Any exception is raised, a failure message is printed.
			logging.warning("Failed to back up configuration")
			cp.printc(cp.FAIL, "[-]Failed to back up configuration")

	def get_access_ports(self):
		"""Gather 1D list of access ports, based on interace status.

		Sends `show interface status | e (trunk|disabled)` command to narrow list of ports
		down to only access ports. Parses ports from this output 
		by using `CiscoHelper.parse_ports`.

		Returns:
			list: 1D list of access ports, False otherwise
		"""

		try:
			# Get all non-trunk and enabled ports by using the `show interface status` command.
			self.child.sendline("sh int status | e (trunk|disabled)") 
			self.child.expect("#")
			raw_port = self.child.before
			# Parse ports from `self.child.before` output.
			ports = CiscoHelper.parse_ports(raw_port)
			if ports:
				# If ports were found and parsed, `ports` are returned.
				return ports
			else:
				return False
		except:
			# If any exception is raised, return False.
			return False

	def get_arp_macs(self):
		"""Gather MAC addresses from the IP ARP table.
		
		Sends `show ip arp` command, and parses all MAC addresses using
		Regular Expression. Formats MAC address with hyphens.

		Returns:
			list: 1D list of MAC addresses if MAC addresses found, False otherwise
		"""

		try:
			# Get the ARP table output from the `show ip arp` command.
			self.child.sendline("sh ip arp") 
			self.child.expect("#")
			raw_arp = self.child.before
			# Parse the MAC address(es) with the `mac_reg` regular expression.
			mac_reg = r"(([a-zA-Z0-9]{4}\.){2}([a-zA-Z0-9]{4})){1}"
			all_macs = re.findall(mac_reg, raw_arp)
			if all_macs:
				# If `all_macs` contains any elements, begin formatting the MAC addresses
				macs = [str(x[0].replace(".","")) for x in all_macs]
				formatted_macs = []
				for mac in macs:
					# Format the MAC addresses with hyphens, instead of the `XXXX.XXXX.XXXX` format.
					m = "-".join(["{0}".format(mac[i:i+2]) for i in range(0, 12, 2)])
					formatted_macs.append(m)
				# Return the formatted MAC addresses.
				return formatted_macs
			else:
				# If no MAC addresses were found, return False.
				logging.info("No MAC addresses found")
				cp.printc(cp.FAIL, "[-]No MACs found in IP ARP command")
				return False

		except Exception as error:
			# For any exception raised, print the error, and return False.
			logging.warning("Error in get_arp_macs function: \n{0}".format(str(error)))
			cp.printc(cp.FAIL, "[-]Error in get_arp_macs function: \n{0}".format(str(error)))
			return False

	def get_show_macs(self):
		"""Gather MAC addresses from the MAC address table.
		
		Sends `show mac add` command, and parses all MAC addresses using
		Regular Expression. Formats MAC address with hyphens.

		Returns:
			list: 1D list of MAC addresses if MAC addresses found, False otherwise
		"""

		try:
			# Gather the MAC address table with the `show mac address` command.
			self.child.sendline("sh mac add") 
			self.child.expect("#")
			raw_arp = self.child.before
			# Parse the MAC addresses from the `self.child.before` output.
			mac_reg = r"(([a-zA-Z0-9]{4}\.){2}([a-zA-Z0-9]{4})){1}"
			all_macs = re.findall(mac_reg, raw_arp)
			if all_macs:
				# If `all_macs` contains at least one element, begin formatting the MAC addresses.
				macs = [str(x[0].replace(".","")) for x in all_macs]
				formatted_macs = []
				for mac in macs:
					# Format the MAC addresses with hyphens, instead of the `XXXX.XXXX.XXXX` format.
					m = "-".join(["{0}".format(mac[i:i+2]) for i in range(0, 12, 2)])
					formatted_macs.append(m)
				# Return the formatted MAC addresses.
				return formatted_macs
			else:
				# If no MAC addresses were found, return False.
				logging.info("No MAC addresses found")
				cp.printc(cp.FAIL, "[-]No MACs found in show macs command")
				return False
		except Exception as error:
			# For any exception raised, print the error, and return False.
			logging.warning("Error in get_show_macs function: \n{0}".format(str(error)))
			cp.printc(cp.FAIL, "[-]Error in get_show_macs function: \n{0}".format(str(error)))
			return False

	def get_cdp_neighbors(self):
		"""Gather CDP neighbor details.

		Sends `show cdp neighbor detail` command to device, and parses the
		output per each neighbor entry. Collects the Hostname, IP address,
		and Native VLAN per entry.

		Returns:
			list: 1D list of dicts containing each CDP neighbor details
		"""

		# Gather CDP neighbor information from `show cdp neighbor detail` command.
		self.child.sendline("sh cdp neighbor detail")
		self.child.expect("#")
		text = self.child.before
		# Split each CDP neighbor by the hyphen seperator.
		sw_split = text.split("-------------------------")
		connected = []
		# Loop through the each CDP neighbor, skipping the first element.
		for dev in sw_split[1:]:
			# Split the element `dev` by newlines.
			l_split = dev.replace(": \r\n  ", ": ").replace(":\r\n", ": ").split("\r\n")
			sw = { "Hostname" : "", "IP" : "", "Native VLAN" : "" }
			# Loop through each line, parsing specific details, and saving them to `sw` dict.
			for x in l_split:
				if "Device ID" in x:
					device = x.replace("Device ID: ", "").replace(".eglin.af.mil", "").rstrip()
					sw["Hostname"] = device.upper()
				elif "IP address" in x:
					ip = x.replace("IP address: ", "").replace("Management address(es): ", "").replace("Entry address(es): ", "").rstrip()
					sw["IP"] = ip
				elif "Native VLAN" in x:
					vlan = x.replace("Native VLAN: ", "").rstrip()
					sw["Native VLAN"] = vlan
			# Append `sw` dict to `connected` list.
			connected.append(sw)
		# Return all of the CDP neighbors.
		return connected

	def get_router_info(self):
		"""Gets router details from `show version` command.

		Sends command `show version` to device, and parses the router
		information from the output.
		"""

		# Gather the version details with the `show version` command.
		self.child.sendline("show version")
		self.child.expect("#")
		text = self.child.before
		# Declare and initialize a new Router() object.
		ro_obj = Router()
		router = {"MAC": [], "Serial" : "", "Model" : "", "SW Version" : ""}
		# Split the lines from the `self.child.before` output.
		lines = text.split("\n")
		# Parse specific details from each line.
		for line in lines:
			if line.startswith("ROM: "):
				ro_obj.sw_version = line.replace("ROM: ", "").strip()
			if line.startswith("Processor board ID"):
				ro_obj.serial = line.replace("Processor board ID ", "").strip()
			if line.startswith("cisco "):
				ro_obj.model = line.split(" ")[1].strip()
		# Attempt to find MAC address(es) from `show module` command output.
		self.child.sendline("show module | i Ok")
		self.child.expect("#")
		mac_text = self.child.before
		# Split lines containing MAC address(es).
		mac_lines = mac_text.split("\n")[1:-1]
		for line in mac_lines:
			# Format MAC address(es) with hyphens.
			mac = line.split(" ")[2]
			mac = mac.replace(".","")
			mac = '-'.join(mac[i:i+2] for i in range(0,12,2))
			ro_obj.macs.append(mac)
		# Return the Router() object `ro_obj`.
		return ro_obj

	def get_stack_info(self):
		"""Parses switch stack details from `show version` command.

		Sends command `show version` to device, and parses the switch stack
		information from the output.
		"""

		# Gather the version details with the `show version` command.
		self.child.sendline("show version | b Base [Ee]thernet MAC Address")
		self.child.expect("#")
		text = self.child.before
		hostname = self.location()
		if len(text.split("\r\n")) < 10:
			# Less than 10 lines means this is likely a router
			# Parse router info instead and return the object.
			router = self.get_router_info()
			router.hostname = hostname
			return router
		switches = []
		sections = text.split("\r\n\r\n\r\n")
		# Grab the first switch information manually.
		first_sw = sections[0]
		switches.append(CiscoHelper.parse_switch_info(first_sw))
		summary = sections[1]
		all_switches = sections[2]
		# Grab the rest of the switches (if any).
		if "---------" in all_switches:
			switches_split = all_switches.split("Switch 0")[1:]
			for x in switches_split:
				switches.append(CiscoHelper.parse_switch_info(x))
		for row in summary.split("\n")[2:]:
			row = row.replace("*","")
			cols = (" ".join(row.split())).split(" ")
			sw_num = int(cols[0])
			for sw_obj in switches:
				# Match Switch() to current row.
				if sw_obj.switch_number == sw_num:
					sw_obj.hostname = hostname
					sw_obj.ports = int(cols[1])
					sw_obj.sw_version = cols[3]
					sw_obj.sw_image = cols[4]
					if len(cols) == 6:
						# Model: 3850+
						sw_obj.mode = cols[5]
		# Return list of Switch() object(s). 
		return switches


	@staticmethod
	def ping(host,c=1):
		"""Pings an IP address or hostname.

		Pings the `host` specified with the a default count `c` set to 1.

		Args:
			host (str): Hostname or IP address of device to ping
			c (int): Number of pings to send. Default is set to 1

		Returns:
			True if successful, False otherwise
		"""
		response = subprocess.Popen(["ping","-c",str(c),host],stdout=subprocess.PIPE)
		response.wait()
		if response.poll():
			logging.warning("No response from pinging {0}".format(host))
			return False
		else:
			logging.info("Successful ping to {0}".format(host))
			return True

	@staticmethod
	def parse_switch_info(text):
		"""Parse switch information from `show version` command.

		Pings the host first. If succsesful, checks location to verify that `self.child`
		is currently connected to Start IP. Loops for the duration of `max_attempts` to exit
		from current device, if not located in Start IP. After successfully exiting to
		Start IP, attempt to SSH to host, send credentials, and remove the terminal length
		from the switch/router.

		Args:
			text (str): Section from `show version` command output

		Returns:
			Switch() object with specific switch details
		"""

		sw_obj = Switch(switch_number=1)
		lines = text.split("\n")
		for line in lines:
			if line[:1].isdigit():
				sw_obj.switch_number = int(line[0])
			if "base ethernet mac address" in line.lower():
				sw_obj.mac = "-".join(line.split(":")[1:]).strip()
			if "system serial number" in line.lower():
				sw_obj.serial = line.split(":")[1].strip()
			if "model number" in line.lower():
				sw_obj.model = line.split(":")[1].strip()
		return sw_obj

	@staticmethod
	def chunks(l, n):
		"""Seperate list into `n` number of chunks.

		Args:
			l (list): List to be split
			n (int): Number of chunks to split list `l` into
		Returns:
			2D list of `l` list chunked `n` times
		"""
	    for i in range(0, len(l), n):
	        yield l[i:i + n]

	@staticmethod
	def get_ranges(ports):
		"""Gather port ranges from list of ports.

		Pings the host first.

		Args:
			ports (list): List of port names

		Returns:
			List of either ranges or ports, depending on a successful return from `CiscoHelper.combine_ports()`
			False if no ports given
		"""

		if ports:
			ranges = CiscoHelper.combine_ports(ports)
			if ranges:
				return ranges
			else:
				return ports
		return False

	@staticmethod
	def group_ranges(L):
		"""Groups similar port ranges.

		Generates port range(s) for a given list of ports.

		Args:
			L (list): List of port numbers

		Returns:
			List of ranges if successful, False otherwise
		"""

		ranges = []
		for k, g in groupby(enumerate(L), lambda x: x[1] - x[0]):
			group = list(map(itemgetter(1), g))
			ranges.append((group[0], group[-1]))
		if ranges:
			return ranges
		else: 
			return False

	@staticmethod
	def get_vlans(text):
		"""Parse VLAN numbers from `show vlan` output.

		Parses Integers from 1-4 digit lengths (VLAN numbers).

		Args:
			text (str): `show vlan` command output.

		Returns:
			List of Integers if any VLAN numbers found, False otherwise
		"""

		reg = r"^\d{1,4}"
		finder = re.compile(reg, re.MULTILINE)
		vfr = list(set(re.findall(finder,text)))
		vlans_found = []
		for vlan in vfr:
			vlans_found.append(int(vlan))
		if not vlans_found:
			return False
		return vlans_found

	@staticmethod
	def combine_ports(ports):
		"""Combines port numbers.

		Matches similar port names together, generating a list of port ranges.

		Args:
			ports (list): List of ports

		Returns:
			2D list of port ranges if successful, False otherwise
		"""

		pfh = re.compile("((Fa\d(\/\d\/|\/))|(Gi\d(\/\d\/|\/)))")
		res = set([m.group() for m in (pfh.match(ports) for ports in ports) if m])
		seen = {}
		all_ranges = []
		for sw_num in res:
			for port in ports:
				if sw_num == port[:len(sw_num)]:
					pn = port[-2:]
					port_num = int(re.findall("\d+",pn)[0])
					if sw_num not in seen.keys():
						seen[sw_num] = [port_num]
					else:
						seen[sw_num].append(port_num)
		for key in seen.keys():
			seen[key].sort()
			ranges = CiscoHelper.group_ranges(seen[key])
			if not ranges:
				return False
			for r in ranges:
				all_ranges.append("{0}{1} - {2}".format(key,r[0],r[1]))
		if all_ranges:
			return list(CiscoHelper.chunks(all_ranges,5))
		else: 
			return False

	@staticmethod
	def parse_ports(text):
		"""Parse ports from `show interface status` command.

		Parses various port names/numbers from the `show interface status` command, producing a list of ports.

		Args:
			text (str): `show interface status` command output

		Returns:
			List of ports if successful, False otherwise
		"""

		reg = r"((Gi|Te|Ten|Fa|Po)((\d\/\d\/\d{1,2})|(\d\/\d{1,2})|(\d{1,2}))(?=(.*([cC]onnected|[nN]otconnect))))"
		finder = re.compile(reg, re.MULTILINE)
		ports_list = re.findall(finder,text)
		output = []
		for port in ports_list:
			output.append(port[0])
		if output:
			return output
		else:
			return False

	@staticmethod
	def parse_ports_short(text):
		"""Parse ports from `show interface status` command (short naming convention).

		Parses various port names/numbers from the `show interface status` command, producing a list of 
		with the short naming convention ports.

		Args:
			text (str): `show interface status` command output

		Returns:
			List of ports with the short naming convention if successful, False otherwise
		"""

		reg = r"((Gi|Te|Ten|Fa|Po)((\d\/\d\/\d{1,2})|(\d\/\d{1,2})|(\d{1,2})))"
		finder = re.compile(reg, re.MULTILINE)
		ports_list = re.findall(finder,text)
		output = []
		for port in ports_list:
			output.append(port[0])
		if output:
			return output
		else:
			return False

	@staticmethod
	def read_file(filename):
		"""Reads file into stripped list of lines.

		Opens `filename`, and returns a list of stripped lines read from given file.

		Args:
			filename (str): Filename to read

		Returns:
			List of lines read from file if successful, False otherwise
		"""

		try:
			with open(filename, "r") as f:
				return [x.replace("\n","") for x in f.readlines()]
		except:
			logging.error("Error reading file {0}".format(filename))

		logging.warning("Could not read file {0}".format(filename))
		return False