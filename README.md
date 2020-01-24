[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/tr-ace/CiscoHelper)
# CiscoHelper
**CiscoHelper** is a module designed to assist automating interactions with Cisco switches and routers. These interactions include information collection and configuration changes. The **ColorPrint** class is used to print message to the terminal in color.

**CiscoDevice** is used for creating **Switch()** and **Router()** objects within **CiscoHelper**. **CiscoDevice** also utilizes **ColorPrint** to print device information using random (or specified) colors.

## Usage
In just a few lines of code, you can begin automating tasks with Cisco switches and routers.

```python
import CiscoHelper
handler = CiscoHelper() # Initialize new CiscoHelper() object.
ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"] # Provide a list of IP addresses and/or hostnames.
handler.spawn() # Spawn an SSH session. This function will gather login information to use.
for ip in ips: # Loop through IP addresses (or hostnames).
	if not handler.connect(ip): # Attempt to connect to IP address (or hostname).
		continue # If False is returned above, skip this host.
	# Successful connection!
	# Interact with the host here.
```

## Examples

### ARP Table Parsing Example
In a situation where the user would like to see all of the connected devices on the network, this example would solve the task. By providing a list of IP addresses for the Cisco switches/routers, the example script would then connect to each one. Next, the switch or router information would be gathered from the `get_stack_info()` function. Finally, the `get_arp_macs()` function would return the MAC addresses found from the ARP table in the device, and add them to the `unique_macs` set.

```python
import CiscoHelper

try:
	# Initialize new CiscoHelper() object.
	handler = CiscoHelper()
	# Provide list of IP addresses to connect to.
	handler.ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
	handler.unique_macs = set()

	# Begin signin process to collect login details.
	handler.spawn()

	# Loop through IP addresses to start connecting.
	for ip in handler.ips:
		# If an IP address fails to connect, skip to the next iteration.
		if not handler.connect(ip):
			continue
		# Gather Cisco stack information. Will return a Router() object if the device is determined to be a router.
		stack_info = handler.get_stack_info()
		# If the `stack_info` is not found, skip to the next iteration.
		if not stack_info:
			continue

		# Find MAC address from the ARP table, and save to the `unique_macs` set.
		arp_macs = handler.get_arp_macs()
		macs = list(set([x.mac.lower() for x in stack_info] + [x.lower() for x in arp_macs]))
		handler.unique_macs.update(macs)

except KeyboardInterrupt:
	exit("Ctrl+C detected. Exiting...")

```

## Testing
The following types of Cisco switches and routers have been used in testing this module. If using this module on a different series of Cisco networking devices, some of the regular expressions or commands may need to be altered.

### Switches
* 2960 Series
* 3560 Series
* 3750 Series
* 3850 Series

### Routers
* 4500 Series
* 6500 Series

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
