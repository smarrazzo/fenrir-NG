# coding=utf-8
######################################################################
##|# ------ FenrirTail : Fenrir logging and output class ----- #|###
##|# -    It is responsible for printing error/debug/info    - #|###
##|# -                 messages to the user                  - #|###
######################################################################

from typing import Optional
from scapy.all import Ether, IP, ls
from scapy.packet import Packet as ScapyPacket
from sys import stdout
from logger import get_logger, FenrirLogger
from pathlib import Path


###########################################################################
### ---------------- Main component of FenrirTail ---------------- ####
###########################################################################
class FenrirTail :

	def __init__(self, debugLevel: int = 1, log_dir: Optional[str] = None) -> None:
		"""
		Initialise FenrirTail avec le système de logging structuré.
		
		Args:
			debugLevel: Niveau de verbosité (0-3)
			log_dir: Répertoire pour les fichiers de log (optionnel)
		"""
		self.debug: int = debugLevel
		self.threshold: int = 100
		
		# Initialiser le logger structuré
		log_file: Optional[str] = None
		if log_dir:
			log_dir_path = Path(log_dir)
			log_dir_path.mkdir(parents=True, exist_ok=True)
			log_file = str(log_dir_path / 'fenrir.log')
		
		self.logger: FenrirLogger = get_logger('FENRIR', debugLevel, log_file)
		
		# Fichier d'erreur pour les exceptions de mangle
		self.error_log_file: Path = Path('FENRIR.err')


	def packetCounter(self, pkt: ScapyPacket, pktNumber: int, PKTthread_number: int) -> None:
		"""Affiche un compteur de paquets (compatibilité API)."""
		self.logger.packet_counter(pktNumber)


	# Verbosity : 0 = no msg, 1 = normal, 2 = information (light), 3 = this damn tool won't stop printing stuff
	## Notify : main function for standard output ##
	def notify(self, msg: str, verbosityLevel: int, bold: int = 0) -> None:
		"""
		Notifie un message (compatibilité API).
		
		Args:
			msg: Message à afficher
			verbosityLevel: Niveau de verbosité requis
			bold: Si 1, affiche en gras
		"""
		if self.debug >= verbosityLevel:
			if bold == 1:
				# Message important
				self.logger.info(f"\033[1m{msg}\033[0m", verbosity_level=verbosityLevel)
			else:
				# Message normal
				self.logger.info(f"[-- {msg}", verbosity_level=verbosityLevel)


	## notifyGood : green color ##
	def notifyGood(self, msg: str, verbosityLevel: int, bold: int = 0) -> None:
		"""
		Affiche un message de succès (vert).
		
		Args:
			msg: Message à afficher
			verbosityLevel: Niveau de verbosité requis
			bold: Si 1, affiche en gras
		"""
		if self.debug >= verbosityLevel:
			if bold == 1:
				self.logger.success(f"\033[1m{msg}\033[0m", verbosity_level=verbosityLevel)
			else:
				self.logger.success(msg, verbosity_level=verbosityLevel)


	## notifyWarn : yellow color ##
	def notifyWarn(self, msg: str, verbosityLevel: int, bold: int = 0) -> None:
		"""
		Affiche un avertissement (jaune).
		
		Args:
			msg: Message à afficher
			verbosityLevel: Niveau de verbosité requis
			bold: Si 1, affiche en gras
		"""
		if self.debug >= verbosityLevel:
			if bold == 1:
				self.logger.warning(f"\033[1m{msg}\033[0m", verbosity_level=verbosityLevel)
			else:
				self.logger.warning(msg, verbosity_level=verbosityLevel)


	## notifyBad : red color ##
	def notifyBad(self, msg: str, verbosityLevel: int, bold: int = 0) -> None:
		"""
		Affiche un message d'erreur (rouge).
		
		Args:
			msg: Message à afficher
			verbosityLevel: Niveau de verbosité requis
			bold: Si 1, affiche en gras
		"""
		if self.debug >= verbosityLevel:
			if bold == 1:
				self.logger.error(f"\033[1m{msg}\033[0m")
			else:
				self.logger.error(msg)


	## mangleException : responsible for writing mangle exceptions logs to file ## 
	def mangleException(self, pkt: ScapyPacket, reason: str = '') -> None:
		"""
		Log une exception de mangle avec détails du paquet.
		
		Args:
			pkt: Paquet Scapy qui a causé l'erreur
			reason: Raison de l'erreur (optionnel)
		"""
		self.notifyBad('\nFENRIR PANIC : Process failed during MANGLING', 1, 1)
		if reason:
			self.notifyBad('Reason : ' + reason, 1)
		
		# Extraire les métadonnées du paquet de manière sécurisée
		try:
			metadata = {
				'packet_src_ip': pkt[IP].src if 'IP' in pkt else 'N/A',
				'packet_dst_ip': pkt[IP].dst if 'IP' in pkt else 'N/A',
				'packet_src_mac': pkt[Ether].src if 'Ether' in pkt else 'N/A',
				'packet_dst_mac': pkt[Ether].dst if 'Ether' in pkt else 'N/A',
				'reason': reason
			}
		except Exception as e:
			metadata = {'reason': reason, 'packet_parse_error': str(e)}
		
		self.logger.error("Mangle exception occurred", exc_info=True, **metadata)
		
		# Écrire aussi dans le fichier d'erreur (compatibilité)
		try:
			with open(self.error_log_file, 'a', encoding='utf-8') as logfd:
				logfd.write(
					'---DUMP BEGINS--------------------------------------------------------------------------------------\n')
				try:
					if 'IP' in pkt and 'Ether' in pkt:
						logfd.write(
							f"[*] Packet header SRC : {pkt[IP].src} ({pkt[Ether].src}) DST : {pkt[IP].dst} ({pkt[Ether].dst})\n")
					else:
						logfd.write("[*] Packet header information unavailable\n")
					logfd.write('Packet dump :\n')
					logfd.write(str(ls(pkt)) + '\n')
				except Exception as e:
					logfd.write(f"Error dumping packet: {e}\n")
				logfd.write(
					'---DUMP ENDS----------------------------------------------------------------------------------------\n')
		except (OSError, IOError) as e:
			self.logger.error(f"Failed to write to error log file: {e}", exc_info=True)
		except Exception as e:
			self.logger.error(f"Unexpected error writing to error log file: {e}", exc_info=True)


	## fenrirPanic : unrecoverable exception handling ##
	def fenrirPanic(self, msg: str, bold: int = 1, exitOnFailure: int = 1) -> None:
		"""
		Gère une panique FENRIR (erreur critique).
		
		Args:
			msg: Message d'erreur
			bold: Si 1, affiche en gras
			exitOnFailure: Si 1, quitte le programme
		"""
		formatted_msg = f'FENRIR PANIC : {msg}'
		if bold == 1:
			formatted_msg = f'\033[1m{formatted_msg}\033[0m'
		
		self.logger.critical(formatted_msg, exc_info=True)
		
		if exitOnFailure == 1:
			from sys import exit
			exit(formatted_msg)
