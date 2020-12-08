import sys
import os
import os.path
from scapy.all import *
import subprocess as sub
import WPA2
from binascii import *
import Handshake
import Ccmp

class sniffer():
	def __init__(self):
		self.dfilepath = str(sub.run("pwd", capture_output=True).stdout)[2:-3]

		self.wifi = "groep2 "#input("Wifi name: ")
		self.get_master_key()

		print("Starting to read")
		self.sniff_packets()

	def get_master_key(self):
		self.master_key = "uncrackable"

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
		capfile = rdpcap(self.dfilepath + "/groep2.cap")
		handshakes = []

		for i in capfile:
			if i.haslayer(EAPOL):
				handshakes.append(i)

		anonce, snonce, mac_ap, mac_cl = Handshake.find_as_and_macs_nonce(handshakes)

		mac_ap = a2b_hex(self.condense_mac(mac_ap))
		mac_cl_bin = a2b_hex(self.condense_mac(mac_cl))
		anonce_bin = a2b_hex(anonce)
		snonce_bin = a2b_hex(snonce)

		self.mac_cl = mac_cl

		PKE = b'Pairwise key expansion'  # Standard Set Value so we don't know what it is
		PMK = Handshake.pmk_generation(password, ssid)
		key_data = min(mac_ap, mac_cl_bin) + max(mac_ap, mac_cl_bin) + min(anonce_bin, snonce_bin) + max(anonce_bin, snonce_bin)
		self.PTK = Handshake.ptk_generation(PMK, PKE, key_data)

		self.transient_key = WPA2.key_to_matrix(self.PTK)	#WPA2.key_to_matrix(self.test_transient_key[64:96])

		nb = len(self.master_key)

		self.rounds = 10

		if nb == 24:
			self.rounds = 12
		elif nb == 32:
			self.rounds = 14

		self.round_keys = WPA2.make_key_streams(self.transient_key, self.rounds)	#Dit werkt door import * in WPA2

	def decrypt(self, packet):
		encrypted_mess = WPA2.make_matrix(bytes_hex(packet.data))#.getlayer(Dot11CCMP).data))
		unencrypted_mess = WPA2.decrypt_wpa2_data(encrypted_mess, self.round_keys, self.rounds)

		print("---------------------------")
		print("Sender: ", packet.addr1, "\nReceiver: ", packet.addr2)
		print("Message: ")

		return self.filter_packets(unencrypted_mess)

	def filtersniff(self, packet):
		if packet is None:
			return None
		elif packet.haslayer(Dot11CCMP):
			if (packet.addr1 == self.mac_cl) or (packet.addr2 == self.mac_cl):				
				return packet
		else:
			return None

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

	def sniff_packets(self):
		a = rdpcap(self.dfilepath + "/groep.cap")

		c = 0

		for packet in a:
			c += 1

			p = self.filtersniff(packet)

			if p != None:
				if len(p) > 0:
					print("-----------packet_number-{}-----------".format(c))
					print(self.zever(p))

	def zever(self, packet):
		data = b2a_hex(packet.data)

		if len(data) % 32 == 0:
			nb_blocks = int(len(data) / 32)
		else:
			nb_blocks = int(len(data) / 32) + 1
		clear_text = str()

		for i in range(nb_blocks):
			block_string = ccmp.const_nonce(packet)

			while len(block_string) < 30:
				block_string += '00'

			if i + 1 <= 0x0f:
				block_string += '0' + hex(i + 1)[2:]
			else:
				block_string += hex(i + 1)[2:]

			block = WPA2.make_matrix(block_string)
			block_encrypted = WPA2.encrypt_wpa2_data(block, self.round_keys, self.rounds)

			if len(data) >= 32:
				stream = data.decode('utf-8')[:32]
				data = data[32:]
			else:
				stream = data.decode('utf-8')

			stream_matrix = WPA2.make_matrix(stream)
			cipher = WPA2.xor(block_encrypted, stream_matrix[0])
			text = WPA2.matrix_to_string(cipher)
			clear_text += text

		return clear_text

sniffer()
