# coding=utf-8

from typing import List
from FenrirTail import FenrirTail
from scapy.packet import Packet as ScapyPacket

class FenrirFangs:

	def __init__(self, debugLevel: int = 1) -> None:
		self.debugLevel: int = debugLevel
		self.FenrirTail: FenrirTail = FenrirTail(debugLevel)
		self.userRules: List['FenrirRule'] = []
		self.ruleCount: int = 0
		#self.addRule(137, 'IP', 'multi')
		#self.addRule(5355, 'IP', 'multi')
		#self.addRule(80,'IP', 'multi')
		#self.addRule(445,'IP','unique')

	def addRule(self, pdst: int, proto: str = 'IP', ruleType: str = 'unique') -> None:
		userRule = FenrirRule(pdst, proto, ruleType)
		self.userRules.append(userRule)
		self.ruleCount = self.ruleCount + 1

	def checkRules(self, pkt: ScapyPacket) -> bool:
		for rule in self.userRules:
			if rule.pktMatch(pkt) == True:
				if rule.type == 'unique':
					self.userRules.remove(rule)
					self.ruleCount = self.ruleCount - 1
				return True
		#if 'IP' in pkt and pkt[IP].src == '10.0.0.69':
		#	print('DEDANS')
		#	return True
		return False

	def changeVerbosity(self, debugLevel: int) -> None:
		self.debugLevel = debugLevel





class FenrirRule:

	def __init__(self, pdst: int, proto: str = 'IP', ruleType: str = 'unique') -> None:
		self.dst_port: int = pdst
		self.proto: str = proto
		self.type: str = ruleType

	def pktMatch(self, pkt: ScapyPacket) -> bool:
		epkt = pkt
		try:
			if self.proto in epkt:
				if 'IP' in epkt and epkt['IP'].dport == self.dst_port:
					return True
				else:
					if epkt[self.proto].dport == self.dst_port:
						return True
					else:
						return False
			else:
				return False
		except:
			return False
