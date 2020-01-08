# Purple
HEADER = '\033[95m'
# Blue
OKBLUE = '\033[94m'
# Green
OKGREEN = '\033[92m'
# Yellow
WARNING = '\033[93m'
# Red
FAIL = '\033[91m'
# Bold
BOLD = '\033[1m'
# Underlined
UNDERLINE = '\033[4m'
# End color
ENDC = '\033[0m'

def printc(color,message):
	"""Print message with specified `color`.

	Parses various port names/numbers from the `show interface status` command, producing a list of 
	with the short naming convention ports.

	Args:
		color (ColorPrint str): Color to print the `message`
		message (str): Text to print
	"""

	print("{0}{1}{2}".format(color,message,ENDC))