from pbkdf2 import PBKDF2
import hmac, hashlib
from random import randint
from binascii import *
from scapy.all import *
from backports.pbkdf2 import pbkdf2_hmac

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

#    print("PMK: ", len(PMK), " ", b2a_hex(PMK).decode())
    
    return PMK

def ptk_generation(PMK, PKE, key_data):
    PTK = b2a_hex(customPRF512(PMK, PKE, key_data)).decode()

    print("\nOur PTKs:\n", PTK[0:32], "\n", PTK[32:64], "\n", PTK[64:96], "\n", PTK[96:128])
    print()
    
    return PTK[64:96]

""" Deprecated """
def handshake_sorter(handshakes):
    for i in range(len(handshakes)):
        load = bytes_hex(handshakes[i][Raw]).decode('utf-8')
        mic = load[154:186]
        
        if (mic == '0' * 32) and (i + 4 <= len(handshakes)):
            return [handshakes[i + k] for k in range(4)]
        
    return []

def find_as_nonce(handshakes):
    anonce_checksum = '02010a'
    snonce_checksum = '02008a'

    anonce = ''
    snonce = ''

    start = 26
    offset = 64

    for packet in handshakes:
        check = ''
        data_layer = b2a_hex(packet.getlayer(EAPOL).load).decode()

        for i in data_layer:
            check += i

            if check == anonce_checksum:
                anonce = data_layer[start:start+offset]
            elif check == snonce_checksum:
                snonce = data_layer[start:start+offset]

    return anonce, snonce
