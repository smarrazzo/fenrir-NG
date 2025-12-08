# coding=utf-8

import socket
import select
from scapy.all import Ether, IP, ARP
from logger import get_logger
from exceptions import FenrirInterfaceError, FenrirAutoconfError
from binascii import hexlify, unhexlify


class Autoconf :

	def __init__(self):
		self.hostmac = b""  # bytes pour cohérence
		self.hostip = ""
		self.conf = True
		self.ifaceHost = "em1"
		self.ifaceNetwork = "eth0"
		self.logger = get_logger('FENRIR.Autoconf', verbosity=1)
		self.sockHost = None
		self.sockNetwork = None
		
		try:
			self.sockHost = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
			self.sockNetwork = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
			self.sockHost.bind((self.ifaceHost, 0))
			self.sockNetwork.bind((self.ifaceNetwork, 0))
			self.logger.info("Network interfaces bound successfully",
			                 verbosity_level=1,
			                 iface_host=self.ifaceHost,
			                 iface_network=self.ifaceNetwork)
		except (OSError, socket.error) as e:
			error_msg = "Failed to bind to network interfaces. You need 2 physical network interfaces to use FENRIR!"
			self.logger.error(error_msg,
			                  exc_info=True,
			                  iface_host=self.ifaceHost,
			                  iface_network=self.ifaceNetwork,
			                  error=str(e))
			# Ne pas lever d'exception ici pour permettre la continuation
			# L'utilisateur sera averti mais le système peut continuer
		except Exception as e:
			error_msg = f"Unexpected error initializing network interfaces: {e}"
			self.logger.critical(error_msg, exc_info=True)
			raise FenrirInterfaceError(error_msg, details={
				'iface_host': self.ifaceHost,
				'iface_network': self.ifaceNetwork,
				'error': str(e)
			}) from e
		
		self.inputs = [s for s in [self.sockHost, self.sockNetwork] if s is not None]

	def startAutoconf(self):
		"""
		Démarre la détection automatique de l'IP et MAC de l'hôte.
		
		Returns:
			Tuple (hostip, hostmac) si détecté avec succès
			
		Raises:
			FenrirAutoconfError: Si la détection échoue
		"""
		if not self.inputs:
			error_msg = "No network interfaces available for autoconf"
			self.logger.error(error_msg)
			raise FenrirAutoconfError(error_msg)
		
		self.logger.info("Trying to detect @mac and @ip of spoofed host...", verbosity_level=1)
		
		while self.conf == True:
			try:
				inputready, outputready, exceptready = select.select(self.inputs, [], [], 1.0)
			except select.error as e:
				self.logger.error("Select error in autoconf", exc_info=True, error=str(e))
				break
			except socket.error as e:
				self.logger.error("Socket error in autoconf", exc_info=True, error=str(e))
				break
			except KeyboardInterrupt:
				self.logger.info("Autoconf interrupted by user")
				break
			except Exception as e:
				self.logger.critical("Unexpected error in autoconf", exc_info=True, error=str(e))
				raise FenrirAutoconfError(f"Unexpected error during autoconf: {e}", details={'error': str(e)}) from e
			
			for socketReady in inputready:
				try:
					# We check packets from iface1 and fwd them to iface2
					if socketReady == self.sockHost:
						try:
							packet = self.sockHost.recvfrom(1500)
						except (OSError, socket.error) as e:
							self.logger.warning("Error receiving from host interface", 
							                   verbosity_level=2, error=str(e))
							continue
						
						pkt = packet[0]
						try:
							dpkt = Ether(packet[0])
						except Exception as e:
							self.logger.debug("Failed to parse packet as Ether", 
							                 verbosity_level=3, error=str(e))
							continue
						
						if 'ARP' in dpkt:
							# Scapy retourne les MAC comme strings, convertir en bytes pour stockage
							mac_str = dpkt[Ether].src
							self.hostmac = unhexlify(mac_str.replace(':', '').encode('ascii'))
							self.logger.debug("Detected MAC from ARP", verbosity_level=2, mac=mac_str)
						elif 'IP' in dpkt:
							self.hostip = dpkt[IP].src
							# Scapy retourne les MAC comme strings, convertir en bytes pour stockage
							mac_str = dpkt[Ether].src
							self.hostmac = unhexlify(mac_str.replace(':', '').encode('ascii'))
							self.logger.debug("Detected IP and MAC from IP packet", 
							                 verbosity_level=2, ip=self.hostip, mac=mac_str)
						
						# We send the packet to the other interface
						if self.sockNetwork:
							try:
								if not isinstance(pkt, bytes):
									pkt = bytes(pkt)
								self.sockNetwork.send(pkt)
							except (OSError, socket.error) as e:
								self.logger.warning("Error forwarding packet to network interface",
								                   verbosity_level=2, error=str(e))
					
					# We forward packet from iface2 to iface1
					elif socketReady == self.sockNetwork:
						try:
							packet = self.sockNetwork.recvfrom(1500)
						except (OSError, socket.error) as e:
							self.logger.warning("Error receiving from network interface",
							                   verbosity_level=2, error=str(e))
							continue
						
						pkt = packet[0]
						if self.sockHost:
							try:
								if not isinstance(pkt, bytes):
									pkt = bytes(pkt)
								self.sockHost.send(pkt)
							except (OSError, socket.error) as e:
								self.logger.warning("Error forwarding packet to host interface",
								                   verbosity_level=2, error=str(e))
				except Exception as e:
					self.logger.warning("Error processing packet in autoconf",
					                   verbosity_level=2, error=str(e), exc_info=True)
					continue
			
			# Vérifier que hostmac est bytes et hostip est string
			if self.hostip and self.hostmac:
				# Convertir hostmac en string pour le retour (compatibilité)
				if isinstance(self.hostmac, bytes):
					hostmac_str = hexlify(self.hostmac).decode('ascii')
					hostmac_str = hostmac_str[:2] + ":" + hostmac_str[2:4] + ":" + hostmac_str[4:6] + ":" + hostmac_str[6:8] + ":" + hostmac_str[8:10] + ":" + hostmac_str[-2:]
				else:
					hostmac_str = self.hostmac
				self.logger.success(f"Autoconf successful: IP={self.hostip}, MAC={hostmac_str}",
				                   verbosity_level=1)
				return self.hostip, hostmac_str
		
		# Si on arrive ici sans avoir détecté IP et MAC
		if not (self.hostip and self.hostmac):
			error_msg = "Failed to detect host IP and MAC during autoconf"
			self.logger.error(error_msg)
			raise FenrirAutoconfError(error_msg)