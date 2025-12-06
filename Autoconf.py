# coding=utf-8

import socket
import select
from scapy.all import Ether, IP, ARP
from logger import get_logger


class Autoconf :

	def __init__(self):
		self.hostmac = ""
		self.hostip = ""
		self.conf = True
		self.ifaceHost = "em1"
		self.ifaceNetwork = "eth0"
		self.logger = get_logger('FENRIR.Autoconf', verbosity=1)
		self.sockHost = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		self.sockNetwork = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		try:
			self.sockHost.bind((self.ifaceHost, 0))
			self.sockNetwork.bind((self.ifaceNetwork, 0))
		except (OSError, socket.error) as e:
			self.logger.warning("You need 2 physical network interfaces to use FENRIR !", 
			                    exc_info=True, iface_host=self.ifaceHost, iface_network=self.ifaceNetwork)
		self.inputs = [self.sockHost, self.sockNetwork]

	def startAutoconf(self):
		self.logger.info("Trying to detect @mac and @ip of spoofed host...", verbosity_level=1)
		while self.conf == True :
			try:
				inputready,outputready,exceptready = select.select(self.inputs, [], [])
			except select.error as e:
				break
			except socket.error as e:
				break
			for socketReady in inputready :
					#We check packets from iface1 and fwd them to iface2
					if socketReady == self.sockHost :
						packet = self.sockHost.recvfrom(1500)
						pkt = packet[0]
						dpkt = Ether(packet[0])
						if 'ARP' in dpkt :
							self.hostmac = dpkt[Ether].src
						elif 'IP' in dpkt :
							self.hostip = dpkt[IP].src
							self.hostmac = dpkt[Ether].src							
						#We send the packet to the other interface
						self.sockNetwork.send(pkt)
					#We forward packet from iface2 to iface1		
					if socketReady == self.sockNetwork :
						packet = self.sockNetwork.recvfrom(1500)
						pkt = packet[0]
						self.sockHost.send(pkt)
			if self.hostip != "" and self.hostmac !=  "" :
				#self.conf = False
				return self.hostip, self.hostmac