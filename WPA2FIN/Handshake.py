from pbkdf2 import PBKDF2
from backports.pbkdf2 import pbkdf2_hmac
import hmac, hashlib
from random import randint
from binascii import *
from scapy.all import *

def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''

    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, msg=(A + chr(0x00).encode() + B + chr(i).encode()), digestmod=hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()

    return R[:blen]

def pmk_generation(password, SSID):
    PMK = pbkdf2_hmac('sha1', password.encode('ascii'), SSID.encode('ascii'), 4096, 32)

    return PMK

def ptk_generation(PMK, PKE, key_data):
    PTK = b2a_hex(customPRF512(PMK, PKE, key_data)).decode()

    return PTK[64:96]

def find_as_nonce(handshakes):
    anonce_checksum = '02008a'
    snonce_checksum = '02010a'

    anonce = ''
    snonce = ''
    client_mac = ''

    start = 26
    nonce_offset = 64

    for packet in handshakes:
        check = ''
        data_layer = b2a_hex(packet.getlayer(EAPOL).load).decode()

        for i in data_layer:
            check += i

            if check == anonce_checksum:
                anonce = data_layer[start:start + nonce_offset]
                client_mac = packet.addr2
            elif check == snonce_checksum:
                snonce = data_layer[start:start + nonce_offset]

    return anonce, snonce, client_mac

""" For pcap only """
def find_as_and_macs_nonce(handshakes):
    anonce_checksum = '02008a'
    snonce_checksum = '02010a'

    anonce = ''
    snonce = ''
    client_mac = ''
    ap_mac = ''

    start = 26
    nonce_offset = 64

    first = False

    for packet in handshakes:
        check = ''

        data_layer = b2a_hex(packet.getlayer(EAPOL).load).decode()

        for i in data_layer:
            check += i

            if check == anonce_checksum:
                anonce = data_layer[start:start + nonce_offset]
                client_mac = packet.addr2
                ap_mac = packet.addr1

                first = True
            elif check == snonce_checksum:
                snonce = data_layer[start:start + nonce_offset]

        if snonce != '':
            return anonce, snonce, ap_mac, client_mac if first else None  # Gewoon omdat er later nog dingen met de printer zijn ofzofrom pbkdf2 import PBKDF2
