# coding=utf-8

from sys import exit
import os
from typing import Optional, Union, Set, Any
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI
from scapy.all import Ether, IP, ARP, ICMP, TCP, UDP, EAPOL, BOOTP, LLMNRQuery, fragment, Packet
from scapy.packet import Packet as ScapyPacket
from MANGLE import MANGLE
from FenrirFangs import FenrirFangs
from Autoconf import Autoconf
from logger import get_logger, FenrirLogger
from exceptions import (
    FenrirSocketError, FenrirNetworkError, FenrirTAPError,
    FenrirPacketError, FenrirError
)
import socket
import select
import time
from binascii import hexlify, unhexlify
import threading
from collections import deque

class FENRIR:

	def __init__(self) -> None:
		if os.geteuid() != 0:
			exit("You need root privileges to play with sockets !")	
		self.isRunning: bool = False
		self.tap: Optional[TunTapDevice] = None
		self.s: Optional[socket.socket] = None
		self.MANGLE: Optional[MANGLE] = None
		self.hostip: str = '10.0.0.5'
		self.hostmac: bytes = b'\x5c\x26\x0a\x13\x77\x8a'  # bytes explicit
		#self.hostmac = b'\x00\x1d\xe6\xd8\x6f\x02'
		self.hostmacStr: str = '5c:26:0a:13:77:8a'
		#self.hostmacStr = "00:1d:e6:d8:6f:02"
		self.verbosity: int = 3
		self.scksnd1: Optional[socket.socket] = None
		self.scksnd2: Optional[socket.socket] = None
		self.Autoconf: Autoconf = Autoconf()
		self.FenrirFangs: FenrirFangs = FenrirFangs(self.verbosity) #FenrirFangs instance
		self.pktsCount: int = 0
		self.LhostIface: str = 'em1'
		self.switchIface: str = 'eth0'
		self.hwaddrStr: str = ""
		self.logger: FenrirLogger = get_logger('FENRIR.Core', self.verbosity)

	def createTap(self) -> None:
		"""Crée une interface TAP virtuelle pour FENRIR."""
		try:
			self.tap = TunTapDevice(flags=IFF_TAP|IFF_NO_PI, name='FENRIR')
			self.tap.addr = "10.0.0.42"
			self.tap.netmask = '255.0.0.0'
			self.tap.mtu = 1500
			self.tap.hwaddr = b'\x00\x11\x22\x33\x44\x55'  # bytes explicit
			self.hwaddrStr = "00:11:22:33:44:55"
			self.tap.persist(True)
			self.tap.up()
			self.logger.info("TAP interface created successfully", 
			                 verbosity_level=1,
			                 tap_name="FENRIR",
			                 tap_addr=self.tap.addr)
		except OSError as e:
			error_msg = f"Failed to create TAP interface: {e}"
			self.logger.error(error_msg, exc_info=True)
			raise FenrirTAPError(error_msg, details={'error': str(e), 'error_type': type(e).__name__}) from e
		except Exception as e:
			error_msg = f"Unexpected error creating TAP interface: {e}"
			self.logger.critical(error_msg, exc_info=True)
			raise FenrirTAPError(error_msg, details={'error': str(e), 'error_type': type(e).__name__}) from e

	def downTap(self) -> None:
		if self.tap is not None:
			self.tap.down()

	def bindAllIface(self) -> None:
		"""Lie le socket à toutes les interfaces pour capturer les paquets."""
		try:
			self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
			self.logger.debug("Socket bound to all interfaces", verbosity_level=2)
		except (OSError, socket.error) as e:
			error_msg = f"Failed to create raw socket: {e}"
			self.logger.error(error_msg, exc_info=True)
			raise FenrirSocketError(error_msg, details={'error': str(e), 'error_type': type(e).__name__}) from e
		except Exception as e:
			error_msg = f"Unexpected error creating socket: {e}"
			self.logger.critical(error_msg, exc_info=True)
			raise FenrirSocketError(error_msg, details={'error': str(e), 'error_type': type(e).__name__}) from e

	def setAttribute(self, attributeName: str, attributeValue: Union[str, bytes, int]) -> bool:
		if attributeName == "host_ip":
			if not isinstance(attributeValue, str):
				return False
			self.hostip = attributeValue
		elif attributeName == "host_mac":
			# S'assurer que hostmac est en bytes
			if isinstance(attributeValue, str):
				# Si c'est une string, la convertir en bytes
				self.hostmac = attributeValue.encode('latin-1')
			elif isinstance(attributeValue, bytes):
				self.hostmac = attributeValue
			else:
				# Essayer de convertir
				try:
					self.hostmac = bytes(attributeValue)
				except Exception:
					return False
			
			# hexlify retourne bytes en Python 3, donc decode() est nécessaire
			tempStr = hexlify(self.hostmac).decode('ascii')
			self.hostmacStr = tempStr[:2] + ":" + tempStr[2:4] + ":" + tempStr[4:6] + ":" + tempStr[6:8] + ":" + tempStr[8:10] + ":" + tempStr[-2:]
		elif attributeName == "verbosity":
			if isinstance(attributeValue, int) and 0 <= attributeValue <= 3:
				self.verbosity = attributeValue
				self.FenrirFangs.changeVerbosity(self.verbosity)
			else:
				return False
		elif attributeName == "netIface":
			if not attributeValue:
				return False
			self.switchIface = str(attributeValue)
			self.Autoconf.sockNetwork = self.switchIface
		elif attributeName == "hostIface":
			if not attributeValue:
				return False
			self.LhostIface = str(attributeValue)
			self.Autoconf.ifaceHost = self.LhostIface
		else:
			return False
		return True

	def chooseIface(self, pkt: ScapyPacket) -> str:
		if pkt[Ether].dst == self.hwaddrStr :
			return 'FENRIR'
		elif pkt[Ether].dst == self.hostmacStr or ((pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' or pkt[Ether].dst == '01:80:c2:00:00:03') and pkt[Ether].src != self.hostmacStr)  :
		#elif pkt[Ether].dst == 'f8:ca:b8:31:c0:2c' or ((pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' or pkt[Ether].dst == '01:80:c2:00:00:03') and pkt[Ether].src != 'f8:ca:b8:31:c0:2c')  :
			return self.LhostIface
		else :
			return self.switchIface

	def sendeth2(self, raw: Union[bytes, ScapyPacket], interface: str) -> None:
		"""
		Envoie un paquet brut sur l'interface spécifiée.
		
		Args:
			raw: Données brutes du paquet (bytes ou convertible en bytes)
			interface: Nom de l'interface cible
		"""
		# Initialiser les sockets si nécessaire
		if self.scksnd1 is None or self.scksnd2 is None:
			try:
				self.scksnd1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
				self.scksnd2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
				self.scksnd1.bind((self.LhostIface, 0))
				self.scksnd2.bind((self.switchIface, 0))
				self.logger.debug("Sending sockets initialized", verbosity_level=3,
				                  iface_host=self.LhostIface, iface_network=self.switchIface)
			except (OSError, socket.error) as e:
				error_msg = f"Failed to initialize sending sockets: {e}"
				self.logger.error(error_msg, exc_info=True,
				                  iface_host=self.LhostIface, iface_network=self.switchIface)
				raise FenrirSocketError(error_msg, details={
					'error': str(e),
					'iface_host': self.LhostIface,
					'iface_network': self.switchIface
				}) from e
		
		# Convertir en bytes si nécessaire
		if not isinstance(raw, bytes):
			try:
				raw = bytes(raw)
			except (TypeError, ValueError) as e:
				error_msg = f"Failed to convert data to bytes: {e}"
				self.logger.error(error_msg, exc_info=True, data_type=type(raw).__name__)
				raise FenrirPacketError(error_msg, details={'error': str(e), 'data_type': type(raw).__name__}) from e
		
		# Envoyer sur l'interface appropriée
		target_socket = self.scksnd1 if interface == self.LhostIface else self.scksnd2
		try:
			target_socket.send(raw)
			self.logger.trace("Packet sent successfully", interface=interface, packet_size=len(raw))
		except (OSError, socket.error) as e:
			# Logger l'erreur mais ne pas faire échouer le traitement (comportement original)
			self.logger.warning(f"Failed to send packet on {interface}", 
			                    verbosity_level=2,
			                    interface=interface,
			                    error=str(e),
			                    error_type=type(e).__name__,
			                    packet_size=len(raw))
		except Exception as e:
			error_msg = f"Unexpected error sending packet: {e}"
			self.logger.error(error_msg, exc_info=True, interface=interface)
			# Ne pas lever d'exception pour maintenir le comportement original

	def initAutoconf(self) -> None:
		self.hostip, self.hostmacStr = self.Autoconf.startAutoconf()

	def initMANGLE(self, stop_event: threading.Event) -> None:
		"""Initialise et démarre la boucle principale de traitement des paquets."""
		try:
			self.bindAllIface()
		except FenrirSocketError as e:
			self.logger.critical("Failed to bind socket, cannot start MANGLE", exc_info=True)
			raise
		
		if self.tap is None:
			error_msg = "TAP interface not initialized"
			self.logger.error(error_msg)
			raise FenrirTAPError(error_msg)
		
		inputs = [self.s, self.tap]
		# Structure limitée pour éviter la croissance mémoire : set + file FIFO
		max_seen_packets = 512
		last_mangled_request_set = set()
		last_mangled_request_fifo = deque()

		def remember_packet(pkt_bytes: bytes) -> None:
			if pkt_bytes in last_mangled_request_set:
				return
			last_mangled_request_set.add(pkt_bytes)
			last_mangled_request_fifo.append(pkt_bytes)
			if len(last_mangled_request_fifo) > max_seen_packets:
				old = last_mangled_request_fifo.popleft()
				last_mangled_request_set.discard(old)

		def forget_packet(pkt_bytes: bytes) -> None:
			if pkt_bytes in last_mangled_request_set:
				last_mangled_request_set.discard(pkt_bytes)

		mycount = 1 ## DECOMISSIONNED
		
		try:
			self.MANGLE = MANGLE(self.hostip, self.tap.addr, self.hostmacStr, self.hwaddrStr, self.verbosity)
		except Exception as e:
			error_msg = f"Failed to initialize MANGLE: {e}"
			self.logger.critical(error_msg, exc_info=True)
			raise FenrirError(error_msg, details={'error': str(e)}) from e
		
		self.logger.info("MANGLE loop started", verbosity_level=1)
		
		while(not stop_event.is_set()):
			try:
				inputready, outputready, exceptready = select.select(inputs, [], [], 1.0)
			except select.error as e:
				self.logger.error("Select error in main loop", 
				                  exc_info=True,
				                  error=str(e),
				                  error_type=type(e).__name__)
				break
			except socket.error as e:
				self.logger.error("Socket error in main loop",
				                  exc_info=True,
				                  error=str(e),
				                  error_type=type(e).__name__)
				break
			except KeyboardInterrupt:
				self.logger.info("Received keyboard interrupt, stopping...")
				break
			except Exception as e:
				self.logger.critical("Unexpected error in main loop",
				                     exc_info=True,
				                     error=str(e),
				                     error_type=type(e).__name__)
				break

			for socketReady in inputready :
				roundstart_time = time.time()
				### FROM NETWORK ###
				if socketReady == self.s :
					try:
						packet = self.s.recvfrom(1600)
					except (OSError, socket.error) as e:
						self.logger.warning("Error receiving packet from socket",
						                   verbosity_level=2,
						                   error=str(e),
						                   error_type=type(e).__name__)
						continue
					
					raw_pkt = packet[0]  # bytes from socket
					# Utiliser bytes pour la comparaison (plus efficace et cohérent)
					if raw_pkt not in last_mangled_request_set: # éviter les doublons
						self.pktsCount += 1
						try:
							pkt = Ether(packet[0])
						except Exception as e:
							self.logger.warning("Failed to parse packet as Ether",
							                   verbosity_level=2,
							                   error=str(e),
							                   packet_size=len(raw_pkt))
							continue
						if self.FenrirFangs.checkRules(pkt) == True:
							if 'IP' in pkt and pkt[IP].dst != '224.0.0.252' and pkt[IP].dst != '10.0.0.255':
								self.MANGLE.pktRewriter(pkt, pkt[IP].src, self.MANGLE.rogue, pkt[Ether].src, self.MANGLE.mrogue)
							# Stocker en bytes pour cohérence avec la comparaison
							pkt_bytes = bytes(pkt)
							remember_packet(pkt_bytes)
							#print("PKT in rules")
							
							self.tap.write(pkt_bytes)
							break
						# Scapy retourne les MAC comme strings, donc utiliser hwaddrStr pour la comparaison
						elif 'ARP' in pkt and (pkt[Ether].src == self.hwaddrStr or pkt[ARP].pdst == self.hostip or pkt[ARP].psrc == self.hostip) :		
							epkt = pkt
						elif 'IP' in pkt and (pkt[Ether].src == self.hwaddrStr or pkt[IP].dst == self.hostip or pkt[IP].src == self.hostip or pkt[IP].dst == '224.0.0.252') :
							epkt = pkt
						elif 'EAPOL' in pkt :
							epkt = pkt
						elif 'BOOTP' in pkt :
							epkt = pkt
						else:
							break
		##### NBT-NS
						if not mycount and 'IP' in epkt and (epkt[IP].dst == '10.0.0.255' and epkt[IP].dport == 137) :
							self.logger.debug("UDP Packet NBT-NS", verbosity_level=2, 
							                   packet_type="NBT-NS", dst_ip=epkt[IP].dst, dport=epkt[IP].dport)
							epkt_bytes = bytes(epkt)
							last_mangled_request.add(epkt_bytes)
							self.tap.write(epkt_bytes)
		##### LLMNR
						elif not mycount and 'IP' in epkt and (epkt[IP].dst == '224.0.0.252' and epkt[IP].dport == 5355) :
							self.logger.debug("UDP Packet LLMNR", verbosity_level=2,
							                   packet_type="LLMNR", dst_ip=epkt[IP].dst, dport=epkt[IP].dport)
							epkt_bytes = bytes(epkt)
							remember_packet(epkt_bytes)
							self.tap.write(epkt_bytes)
		##### fin LLMNR / NBNS
						elif not mycount and 'IP' in epkt and epkt[IP].dport == 445 :
							self.logger.debug("Processing SMB packet", verbosity_level=2,
							                   packet_type="SMB", dport=epkt[IP].dport)
							self.MANGLE.pktRewriter(epkt, epkt[IP].src, self.MANGLE.rogue, epkt[Ether].src, self.MANGLE.mrogue)
							epkt_bytes = bytes(epkt)
							remember_packet(epkt_bytes)
							self.tap.write(epkt_bytes)
						else :
							mangled_request = self.MANGLE.Fenrir_Address_Translation(epkt)
							if mangled_request:  # Vérifier que le paquet n'a pas été rejeté
								ifaceToBeUsed = self.chooseIface(mangled_request)
								mangled_bytes = bytes(mangled_request)
								if ifaceToBeUsed == 'FENRIR' :
									self.tap.write(mangled_bytes)
								else :
									#mangled_request.show2()
									remember_packet(mangled_bytes)
									self.sendeth2(mangled_bytes, ifaceToBeUsed)
					else :
						# Paquet déjà traité, le retirer du set
						forget_packet(raw_pkt)  # discard() ne lève pas d'erreur si absent
				### FROM FENRIR ###
				elif socketReady == self.tap :
					self.pktsCount += 1
					try:
						buf = self.tap.read(self.tap.mtu)  # test paquet depuis Rogue
					except OSError as e:
						self.logger.warning("Error reading from TAP interface",
						                   verbosity_level=2,
						                   error=str(e),
						                   error_type=type(e).__name__)
						continue
					
					try:
						epkt = Ether(buf)  # idem que au dessus
					except Exception as e:
						self.logger.warning("Failed to parse packet from TAP as Ether",
						                   verbosity_level=2,
						                   error=str(e),
						                   buffer_size=len(buf))
						continue
					# Convertir le buffer en bytes pour la comparaison
					buf_bytes = buf if isinstance(buf, bytes) else bytes(buf)
					if buf_bytes not in last_mangled_request_set:
						mangled_request = self.MANGLE.Fenrir_Address_Translation(epkt)
						if not mangled_request:  # Paquet rejeté
							continue
						
						ifaceToBeUsed = self.chooseIface(mangled_request)

		########### debut LLMNR
						if 'LLMNRQuery' in mangled_request : 
							self.logger.trace("Processing LLMNR query", packet_type="LLMNRQuery")
							mangled_request[LLMNRQuery].an.rdata = '10.0.0.5'
							del mangled_request[IP].chksum
							if 'UDP' in mangled_request:
								del mangled_request[UDP].chksum
							mangled_request = mangled_request.__class__(bytes(mangled_request))
							#ls(mangled_request)
		########### fin LLMNR
						#print(ifaceToBeUsed)
						mangled_bytes = bytes(mangled_request)
						if ifaceToBeUsed == 'FENRIR':
							self.tap.write(mangled_bytes)
							remember_packet(mangled_bytes)
						else :
							#mangled_request.show2()
							###
							if 'IP' in mangled_request and 1 == 2:
								self.logger.debug("Fragmenting packet", verbosity_level=3, fragsize=500)
								frags = fragment(mangled_request, fragsize=500)
								self.logger.debug(f"Packet fragmented into {len(frags)} fragments", verbosity_level=3)
								for frag in frags:
									frag = frag.__class__(bytes(frag))
									frag_bytes = bytes(frag)
									remember_packet(frag_bytes)
									self.sendeth2(frag_bytes, ifaceToBeUsed)							
									#send(frag, iface=ifaceToBeUsed)
							else:
								if 'IP' in mangled_request:
									del mangled_request[IP].len
								#mangled_request = mangled_request.__class__(str(mangled_request))
								#if 'TCP' in mangled_request:
								#	new_mangled_request = self.MANGLE.changeSessID(mangled_request)
								#	mangled_request = new_mangled_request
								remember_packet(mangled_bytes)
								#if 'TCP' in mangled_request:
								#	#print("[[[")
								#	print(str(mangled_request[TCP].seq) + " : " + str(mangled_request[IP].len))
								#	print("]]]")
								self.sendeth2(mangled_bytes, ifaceToBeUsed)							
							###
#							last_mangled_request.add(bytes(mangled_request))
#							self.sendeth2(bytes(mangled_request), ifaceToBeUsed)
					else:
						# Paquet déjà traité depuis TAP
						epkt_bytes = bytes(epkt) if not isinstance(epkt, bytes) else epkt
						self.tap.write(epkt_bytes)
						forget_packet(buf_bytes)  # Retirer le buffer original
				else:
					error_msg = f"Unknown socket ready: {socketReady}"
					self.logger.error(error_msg, socket_type=type(socketReady).__name__)
					# Ne pas quitter, continuer le traitement
