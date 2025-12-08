# coding=utf-8

from typing import Optional
from cmd2 import Cmd
from binascii import hexlify, unhexlify
from FENRIR2 import FENRIR
import threading
import ipaddress
import re

class Interface(Cmd):
	FENRIR: FENRIR = FENRIR()
	FenrirThread: Optional[threading.Thread] = None
	stop_event: Optional[threading.Event] = None
	promptBase: str = "FENRIR"
	prompt: str = "\n\033[1m\033[31m" + promptBase + " >\033[0m "
	intro = """\n\033[1m
	                                                  ,a8b
	                                              ,,od8  8
	                                             d8'     8b
	                                          d8'ba     aP'
	                                       o8'         aP'
	                                        YaaaP'    ba
	                       \033[31mFENRIR\033[0m\033[1m         Y8'         88
	                                   ,8\"           `P
	                              ,d8P'              ba
	              ooood8888888P\"\"\"'                  P'
	           ,od                                  8
	        ,dP     o88o                           o'
	       ,dP          8                          8
	      ,d'   oo       8                       ,8
	      $    d$\"8      8           Y    Y  o   8
	     d    d  d8    od  \"\"boooaaaaoob   d\"\"8  8
	     $    8  d  ood'-I   8         b  8   '8  b
	     $   $  8  8     d  d8        `b  d    '8  b
	      $  $ 8   b    Y  d8          8 ,P     '8  b
	      `$$  Yb  b     8b 8b         8 8,      '8  o,
	           `Y  b      8o  $$       d  b        b   $o
	            8   '$     8$,,$\"      $   $o      '$o$$
	            $o$$P\"                 $$o$
	\033[0m"""


	def __init__(self) -> None:
		Cmd.__init__(self)
		
	### TOOLBOX ###
	def hexToStr(self, hexstr: bytes) -> str:
		"""
		Convertit une adresse MAC en bytes vers une string formatée.
		
		Args:
			hexstr: Adresse MAC en bytes (ou string d'octets)
			
		Returns:
			String formatée "XX:XX:XX:XX:XX:XX"
		"""
		# S'assurer que c'est bytes
		if isinstance(hexstr, str):
			hexstr = hexstr.encode('latin-1')
		# hexlify retourne bytes en Python 3, donc decode() est nécessaire
		string = hexlify(hexstr).decode('ascii')
		return string[:2] + ":" + string[2:4] + ":" + string[4:6] + ":" + string[6:8] + ":" + string[8:10] + ":" + string[-2:]

	def strToHex(self, string: str) -> bytes:
		"""
		Convertit une adresse MAC en string vers bytes.
		
		Args:
			string: Adresse MAC formatée "XX:XX:XX:XX:XX:XX"
			
		Returns:
			Adresse MAC en bytes
		"""
		hexes = string.split(":")
		hexstr = ''.join(hexes).encode("ascii")
		return unhexlify(hexstr)  # unhexlify retourne bytes en Python 3

	### VALIDATION HELPERS ###
	def _validate_ip(self, value: str) -> bool:
		try:
			ipaddress.ip_address(value)
			return True
		except ValueError:
			return False

	def _validate_mac(self, value: str) -> bool:
		# Format XX:XX:XX:XX:XX:XX
		return bool(re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value))

	def _validate_port(self, value: str) -> Optional[int]:
		try:
			port = int(value)
			if 1 <= port <= 65535:
				return port
			return None
		except ValueError:
			return None

	def changeRunningState(self, state: bool) -> None:
		if state == True:
			self.prompt = "\n\033[1m\033[32m" + self.promptBase + " >\033[0m "
			self.FENRIR.isRunning = True
		elif state == False:
			self.prompt = "\n\033[1m\033[31m" + self.promptBase + " >\033[0m "
			self.FENRIR.isRunning = False




	def do_create_virtual_tap(self,s):
		self.FENRIR.createTap()

	def help_create_virtual_tap(self):
		print("Creates the virtual tap for FENRIR core module")

	def do_destroy_virtual_tap(self,s):
		self.FENRIR.downTap()

	def help_destroy_virtual_tap(self):
		print("Deletes the virtual tap for FENRIR core module")



	def do_show(self,argString):
		args = argString.split()
		if len(args) != 1:
			print("*** Invalid number of arguments")
			self.help_show()
		else:
			if args[0] == "tap" and self.FENRIR.tap is not None:
				print("tap :")
				print("Address ===> " + self.FENRIR.tap.addr)
				print("MAC ===> " + self.hexToStr(self.FENRIR.tap.hwaddr))
				print("mtu ===> " + str(self.FENRIR.tap.mtu))
			elif args[0] == "host_ip" and self.FENRIR.hostip is not None:
				print("host_ip ===> " + self.FENRIR.hostip)
			elif args[0] == "host_mac" and self.FENRIR.hostmac is not None:
				print("host_mac ===> " + self.hexToStr(self.FENRIR.hostmac))
			elif args[0] == "rules":
				if self.FENRIR.FenrirFangs.ruleCount == 0:
					print("No rule added (yet)")
				else:
					num = 0
					for rule in self.FENRIR.FenrirFangs.userRules:
						num += 1
						print("Rule " + str(num) +" : \n\tport = " + str(rule.dst_port) + "\n\ttype = " + rule.type + "\n\tproto = " + rule.proto)
			elif args[0] == "netIface":
				print("netIface ===> " + self.FENRIR.switchIface)
			elif args[0] == "hostIface":
				print("hostIface ===> " + self.FENRIR.LhostIface)
			elif args[0] == "all":
				self.do_show("tap")
				self.do_show("host_ip")
				self.do_show("host_mac")
				self.do_show("hostIface")
				self.do_show("netIface")
				self.do_show("rules")

	def help_show(self):
		print("USAGE : show <attribute>")

	def complete_show(self, match, line, bindex, eindex):
		COMPLETION_ARRAY = ('tap', 'host_ip', 'host_mac', 'rules', 'hostIface ', 'netIface ', 'all')
		return [i for i in COMPLETION_ARRAY if i.startswith(match)]



	def do_set(self, argString):
		args = argString.split()
		if len(args) != 2:
			print("*** Invalid number of arguments")
			self.help_set()
		else:
			attrValue = args[1]
			if args[0] == "debug":
				Cmd.do_set(self, argString)
				return
			elif args[0] == "host_mac":
				if not self._validate_mac(args[1]):
					print("*** host_mac invalide. Format attendu : XX:XX:XX:XX:XX:XX")
					return
				attrValue = self.strToHex(args[1])
			elif args[0] == "host_ip":
				if not self._validate_ip(args[1]):
					print("*** host_ip invalide")
					return
			elif args[0] == "verbosity":
				try:
					attrValue_int = int(args[1])
				except ValueError:
					print("*** verbosity doit être un entier entre 0 et 3")
					return
				if attrValue_int < 0 or attrValue_int > 3:
					print("*** verbosity doit être entre 0 et 3")
					return
				attrValue = attrValue_int
			elif args[0] in ("netIface", "hostIface"):
				if not args[1]:
					print("*** Interface vide")
					return
			else:
				print("*** Attribut inconnu")
				self.help_set()
				return
			if self.FENRIR.setAttribute(args[0], attrValue) == False:
				print("*** Invalid argument")
				self.help_set()
			else:
				print(args[0] + " ===> " + args[1])

	def help_set(self):
		print("USAGE : set <attribute> <value>")
		print("Attributes = host_ip, host_mac, netIface, hostIface, verbosity <0-3>")

	def complete_set(self, match, line, bindex, eindex):
		COMPLETION_ARRAY = ('host_ip ', 'host_mac ', 'verbosity ', 'netIface ', 'hostIface ')
		if bindex == 4:
			return [i for i in COMPLETION_ARRAY if i.startswith(match)]
		else:
			return ('')



	def do_stats(self,s):
		if self.FENRIR.isRunning == True:
			print("Packet(s) processed by FENRIR : " + str(self.FENRIR.pktsCount))



	def do_add_reverse_rule(self, argString):
		args = argString.split()
		if len(args) != 3:
			print("*** Invalid number of arguments")
			self.help_add_rule()
		else:
			port = self._validate_port(args[0])
			if port is None:
				print("*** Le port doit être un entier entre 1 et 65535")
				self.help_add_rule()
				return
			TYPES_ARRAY = ('unique', 'multi')
			PROTO_ARRAY = ('IP', 'TCP', 'UDP', 'ICMP')
			if args[1] not in TYPES_ARRAY:
				print("*** type doit être 'unique' ou 'multi'")
				self.help_add_rule()
				return
			if args[2].upper() not in PROTO_ARRAY:
				print("*** proto doit être IP, TCP, UDP ou ICMP")
				self.help_add_rule()
				return
			self.FENRIR.FenrirFangs.addRule(port, args[2].upper(), args[1])
			print("New rule added : \n\tport = " + str(port) + "\n\ttype = " + args[1] + "\n\tproto = " + args[2].upper())

	def help_add_reverse_rule(self):
		print("USAGE : add_reverse_rule <port> <type = unique> <proto = IP>")
		print("Interface for adding port-specific rules to allow reverse connection to reach FENRIR. This is useful for reverse shell or for server-based exploits & fun (Responder)")
		print("Types include : \n\tunique = rule is triggered once before being deleted (useful to get a reverse shell from one host) \n\tmulti = rule can be triggered multiple times (useful for MitM stuff)")

	def complete_add_reverse_rule(self, match, line, bindex, eindex):
		if bindex <= 16:
			return (' ')
		elif bindex > 16:
			if line.count(' ') == 2:
				COMPLETION_ARRAY = ('unique ', 'multi ')
				return [i for i in COMPLETION_ARRAY if i.startswith(match)]
			elif line.count(' ') >= 3:
				return ('')
			else:
				return ('')
		else:
			return ('')



	def do_autoconf(self,s):
		print("Running initAutoconf...")
		self.FENRIR.initAutoconf()
		self.do_show('all')

	def help_autoconf(self):
		print("Runs the auto-configuration module")



	def do_run(self,s):
		if self.FENRIR.tap is None:
			self.do_create_virtual_tap("")
		if self.FENRIR.tap is not None and self.FENRIR.hostip != '' and self.FENRIR.hostmac != '':
			self.FENRIR.setAttribute("verbosity", 0)
			self.changeRunningState(True)
			self.stop_event = threading.Event()
			self.FenrirThread = threading.Thread(target=self.FENRIR.initMANGLE, args=(self.stop_event,))
			self.FenrirThread.daemon = True
			self.FenrirThread.start()
#			self.FENRIR.initMANGLE()
		else:
			print("*** FENRIR PANIC : Configuration problem")
			self.help_run()

	def help_run(self):
		print("USAGE : run")
		print("This will launch FENRIR core in a new thread and remove any verbosity !")
		print("(Disclaimer : you must have run the auto-configuration module or given correct information manually before running this command ! You need at least host_ip, host_mac and a virtual tap created !)")



	def do_run_debug(self,s):
		if self.FENRIR.tap is None:
			self.do_create_virtual_tap("")
		if self.FENRIR.tap is not None and self.FENRIR.hostip != '' and self.FENRIR.hostmac != '':
			self.changeRunningState(True)
			self.stop_event = threading.Event()
			self.FENRIR.initMANGLE(self.stop_event)
		else:
			print("*** FENRIR PANIC : Configuration problem")
			self.help_run_debug()

	def help_run_debug(self):
		print("USAGE : run_debug")
		print("This will launch FENRIR core WITHOUT creating a new thread !")
		print("(Disclaimer : you must have run the auto-configuration module or given correct information manually before running this command ! You need at least host_ip, host_mac and a virtual tap created !)")



	def do_stop(self,s):
		if self.FENRIR.isRunning == True:
			self.stop_event.set()
			self.FenrirThread.join()
			self.changeRunningState(False)
			print("Fenrir was stopped")
		else:
			print("Fenrir is not running at the moment...")

	def help_stop(self):
		print("Stops the FENRIR thread")



	def do_cookie(self,s):
		print("This cookie machine is brought to you by Valérian LEGRAND valerian.legrand@orange.com\n")
		print("COOKIE COOKIE COOKIE")
		print("COOKIE COOKIE COOKIE")
		print("COOKIE COOKIE COOKIE")
		print("COOKIE COOKIE COOKIE")
		print("COOKIE COOKIE COOKIE")



	def do_exit(self, s):
		return True



	def do_help(self,s):
		if s == '' :
			print("FENRIR Commands :")
			print("\tcookie")
			print("\tcreate_virtual_tap")
			print("\tdestroy_virtual_tap")
			print("\tadd_reverse_rule")
			print("\trun")
			print("\trun_debug")
			print("\tset")
			print("\tshell")
			print("\tshortcuts")
			print("\tautoconf")
			print("\tstop")
			print("\tquit")
			print("\thelp")
		else :
			Cmd.do_help(self,s)

	def complete_help(self, match, line, bindex, eindex):
		COMPLETION_ARRAY = ('cookie', 'create_virtual_tap', 'destroy_virtual_tap', 'add_reverse_rule', 'run', 'run_debug', 'set', 'shell', 'shortcuts', 'autoconf', 'stop', 'quit', 'exit', 'help')
		return [i for i in COMPLETION_ARRAY if i.startswith(match)]


	
	

if __name__ == '__main__':
	app = Interface()
	app.cmdloop()
