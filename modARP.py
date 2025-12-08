# coding=utf-8
######################################################################
##|# -------- modARP : ARP management module for MANGLE -------- #|###
##|# - It is responsible for handling ARP requests and replies - #|###
##|# - in order to avoid triggering switch's security measures - #|###
##|# - while still providing address resolution possibilities  - #|###
##|# -          to both the legitimate and rogue host          - #|###
######################################################################

from typing import Optional, List, Union
from scapy.all import Ether, ARP, ls
from scapy.packet import Packet as ScapyPacket
from FenrirTail import FenrirTail


###################################################################
### ---------------- Main component of modARP ---------------- ####
###################################################################
class modARP :

	def __init__(self, ip_host: str, ip_rogue: str, mac_host: str, mac_rogue: str, debugLevel: int = 1) -> None:
		self.FenrirTail: FenrirTail = FenrirTail(debugLevel)
		self.debugLevel: int = debugLevel
		self.FenrirTail.notify('Loading ARP module...', 1)
		self.ARPthreads: List['ARPthread'] = []
		self.ARPthread_number: int = 0
		self.host: str = ip_host
		self.rogue: str = ip_rogue
		self.mrogue: str = mac_rogue
		self.mhost: str = mac_host


	## modARP main routine ##
	def Fenrir_Address_Resolution_Protocol(self, ARPpkt: ScapyPacket) -> Union[ScapyPacket, bool]:
		if ARPpkt[ARP].op == 2 :  # ARP-reply
			self.FenrirTail.notify('ARP reply received', 3)
			for ARPthread in self.ARPthreads :
				if ARPthread.thisIsMyARP(ARPpkt) :
					self.FenrirTail.notify('Corresponding ARPthread found', 3)
					ARPthread.changeState()
					self.FenrirTail.notify("ARPthread state changed from 'rep_sent' to 'rep_rcvd'", 3)
					returnedPkt = self.ARPReplyMangling(ARPpkt, ARPthread)
					self.deleteARPthread(ARPthread)
					return returnedPkt
			self.FenrirTail.notify('No corresponding ARPthread found', 3)
			return ARPpkt # if no ARPthread, then forward the ARP-reply
		else :  # ARP request
			if self.checkForStrangeARP(ARPpkt) == False :  # check if ARP packet might compromise covertOps
				if ARPpkt[ARP].psrc == self.rogue or ARPpkt[ARP].psrc == self.host :
					self.FenrirTail.notify('Request from rogue or host, mangling...', 3)
					new_ARPthread = self.createARPthread(ARPpkt)
					return self.ARPRequestMangling(ARPpkt)
				elif ARPpkt[ARP].pdst == self.host :
					self.FenrirTail.notify('Request for host, forwarding...', 3)
					new_ARPthread = self.createARPthread(ARPpkt)
					return ARPpkt # if request for host, then forward
				else :
					return False  # drop pkt
			else :
				return False  # drop pkt


	## returns True if packet is strange and may need further processing, False otherwise ##
	def checkForStrangeARP(self, pkt: ScapyPacket) -> bool:
		if pkt[Ether].dst == self.mrogue or pkt[ARP].pdst == self.rogue :
			self.FenrirTail.notify('Strange ARP packet detected. Dropping it... You may want to check where this one came from : ', 1)
			ls(pkt)
			return True
		else : 
			self.FenrirTail.notify('ARP request received', 3)
			return False


	## Creates an ARPthread from an ARP-request packet ##
	def createARPthread(self, pkt: ScapyPacket) -> 'ARPthread': 
		self.ARPthread_number += 1
		ARPthread_instance = ARPthread(self.debugLevel, pkt[Ether].src, pkt[Ether].dst, pkt[ARP].psrc, pkt[ARP].pdst, 'req_sent')
		self.ARPthreads.append(ARPthread_instance)
		self.FenrirTail.notify('New ARPthread created', 3)
		return ARPthread_instance


	## Deletion of complete ICMPthread ##
	def deleteARPthread(self, ARPthread: 'ARPthread') -> bool:
		try :
			if ARPthread.state == 'zombie' :
				self.FenrirTail.fenrirPanic('Unexpected situation occured during deletion of ARPthread (ARPthread is a zombie)')
			else :
				self.ARPthreads.remove(ARPthread)
				self.ARPthread_number -= 1
				self.FenrirTail.notify('ARPthread deleted', 3)
			return True
		except ValueError :
			self.FenrirTail.fenrirPanic('Unexpected exception was raised during deletion of ARPthread')


	## ARP Mangling Routines ##
	def ARPRequestMangling(self, pkt: ScapyPacket) -> ScapyPacket:
		if pkt[ARP].psrc == self.rogue :
			return self.pktRewriter(pkt, self.host, 0, self.mhost, 0, self.mhost, 0)
		else :  # the ARP reply is for legit host
			return pkt
	def ARPReplyMangling(self, pkt: ScapyPacket, ARPthread: 'ARPthread') -> ScapyPacket:
		if ARPthread.src_mac == self.mrogue :  # the ARP reply is for rogue
			return self.pktRewriter(pkt, 0, self.rogue, 0, self.mrogue, 0, self.mrogue)
		else :  # the ARP reply is for legit host
			return pkt


	## Rewrites ARP packets ##
	def pktRewriter(self, pkt: ScapyPacket, src: Union[str, int], dst: Union[str, int], msrc: Union[str, int], mdst: Union[str, int], hwsrc: Union[str, int], hwdst: Union[str, int]) -> ScapyPacket:
		self.FenrirTail.notify('ARP packet is being rewritten :', 3)
		if src != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].psrc + ' --> ' + src, 3)
			pkt[ARP].psrc = src
		if dst != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].pdst + ' --> ' + dst, 3)
			pkt[ARP].pdst = dst
		if msrc != 0 :
			pkt[Ether].src = msrc
		if hwsrc != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].hwsrc + ' --> ' + hwsrc, 3)
			pkt[ARP].hwsrc = hwsrc
		if mdst != 0 :
			pkt[Ether].dst = mdst
		if hwdst != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].hwdst + ' --> ' + hwdst, 3)
			pkt[ARP].hwdst = hwdst
		pkt = pkt.__class__(bytes(pkt))
		self.FenrirTail.notify('ARP packet mangled and rewritten successfully', 3)
		return pkt




###################################################################
### --- Class representing an ARP exchange between 2 hosts --- ####
###################################################################
class ARPthread :
	states: List[str] = ['req_sent', 'rep_rcvd', 'zombie']

	#SOURCE is always from the host point of view (spoofed/rogue host)
	def __init__(self, debugLevel: int, msrc: str, mdst: str, asrc: str, adst: str, state: str = "req_sent") -> None:
		self.FenrirTail: FenrirTail = FenrirTail(debugLevel)
		self.src_mac: str = msrc
		self.src_ip: str = asrc
		self.dst_mac: str = mdst
		self.dst_ip: str = adst
		self.state: str = state


	def changeState(self) -> None:
		if self.state == 'req_sent' :
			self.state = 'rep_rcvd'
		elif self.state == 'rep_rcvd' :
			self.state = 'zombie'
		else :
			self.FenrirTail.fenrirPanic("STRANGE ARP STATE DETECTED : '" + self.state + "' - Look for the 'changeState' function in modARP.py")

	## Returns True if a packet is a reply to a previous request
	def thisIsMyARP(self, pkt: ScapyPacket) -> bool:
		if pkt[ARP].psrc == self.dst_ip :
			return True
		else :
			return False


	## UTILS FUNCTIONS ##
	def logdump(self) -> None:
		print('mac src : ' + self.src_mac)
		print('ip src : ' + self.src_ip)
		print('mac dst : ' + self.dst_mac)
		print('ip dst : ' + self.dst_ip)
		print('state : ' + self.state)