from pbkdf2 import PBKDF2
import hmac, hmac, hashlib
from random import randint
from binascii import *
from scapy.all import *



def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = ''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, msg=(A + chr(0x00) + B + chr(i)).encode("utf-8"), digestmod=hashlib.sha1)
        i += 1
        R = R + str(hmacsha1.digest())
    return R[:blen]


def pmk_generation(password, SSID):
    PMK = PBKDF2(password, SSID, 4096).read(32)
    return PMK


def ptk_generation(PMK, PKE, key_data):
    PTK = customPRF512(PMK, PKE, key_data)
    return PTK[0:16]

def handshake_sorter(handshakes):
    for i in range(len(handshakes)):
        load = bytes_hex(handshakes[i][Raw]).decode('utf-8')
        mic = load[154:186]
        if (mic == '0' * 32) and (i + 4 <= len(handshakes)):
            return [handshakes[i + k] for k in range(4)]
    return []
