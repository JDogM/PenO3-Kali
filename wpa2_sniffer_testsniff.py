import sys
import os
import os.path
from scapy.all import *
import subprocess as sub
from binascii import *

class sniffer():
	def __init__(self):
		self.dfilepath = str(sub.run("pwd", capture_output=True).stdout)[2:-3]

		start = input("First time starting up? [Y/N]:")

		if start == "Y" or start == "y":
			# put everything in monitor mode when starting up
			print("Killing services")
			os.system("sudo airmon-ng check kill")
			print("Starting wlan1mon")
			os.system("sudo airmon-ng start wlan0 1")
			print("Done")

		print("Starting to sniff")

		self.mac_cl = '74:8f:3c:bd:d1:f2'
		self.sniff_packets()

	def filtersniff(self, packet):
		if packet is None:
			pass
		elif packet.haslayer(Raw):
			if (packet.src == self.mac_cl) or (packet.dst == self.mac_cl):
				return packet

	def sniff_packets(self):
		a = sniff(iface="wlan0", lfilter=self.filtersniff, count=3000)
		wrpcap('capfile.cap', a)

sniffer()
