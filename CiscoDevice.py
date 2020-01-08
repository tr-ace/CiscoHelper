import ColorPrint as cp
import random
import re

colors = [cp.HEADER, cp.OKBLUE, cp.OKGREEN, cp.WARNING]


class Switch:
	def __init__(self,hostname="",switch_number=0,mac="",serial="",model="",ports=0,sw_version="",sw_image="",mode=""):
		self.name = "Switch"
		self.hostname = hostname
		self.switch_number = switch_number
		self.mac = self.format_mac(mac)
		self.serial = serial
		self.model = model
		self.ports = ports
		self.sw_version = sw_version
		self.sw_image = sw_image
		self.mode = mode

	def print(self):
		mode = ""
		if self.mode:
			mode = "\n|--Mode:        {0}".format(self.mode)
		text = """____________________________________
|
|--Hostname:    {0}
|--Switch #:    {1}
|--MAC:         {2}
|--Serial:      {3}
|--Model:       {4}
|--Ports:       {5}
|--SW Verion:   {6}
|--SW Image:    {7}{8}
|___________________________________
		""".format(self.hostname,self.switch_number,self.mac,self.serial,self.model,self.ports,self.sw_version,self.sw_image,mode)
		randcolor = colors[random.randint(0, len(colors) - 1 )]
		cp.printc(randcolor,text)

	def format_mac(self, mac):
		mac_r = re.sub(r"\W+", "", mac)
		formatted = "-".join(mac_r[i:i+2] for i in range(0,12,2))
		return formatted


class Router:
	def __init__(self,hostname="",macs=[],serial="",model="",sw_version=""):
		self.name = "Router"
		self.hostname = hostname
		self.macs = self.format_macs(macs)
		self.serial = serial
		self.model = model
		self.sw_version = sw_version

	def print(self):
		text = """
____________________________________
|
|--Hostname:    {0}
|--MACs:        {1}
|--Serial:      {2}
|--Model:       {3}
|--SW Verion:   {4}
|___________________________________
		""".format(self.hostname,"\n|               ".join(self.macs),self.serial,self.model,self.sw_version)
		randcolor = colors[random.randint(0, len(colors) - 1 )]
		cp.printc(randcolor,text)

	def format_macs(self, macs):
		formatted = []
		for mac in macs:
			mac_r = re.sub(r"\W+", "", mac)
			formatted.append("-".join(mac_r[i:i+2] for i in range(0,12,2)))
		return formatted