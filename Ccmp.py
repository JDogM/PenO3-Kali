from scapy.all import *
from binascii import *
import WPA2

def const_nonce(packet):
    priority_octet = '00'
    addr2 = strip(packet.addr2)
    pn = make_iv(packet)

#    DS = packet.FCfield & 0x3
#    toDS = str((DS & 0x01) >> 0)
#    fromDS = str((DS & 0x02) >> 1)
#
#    nonce = toDS + fromDS + priority_octet + addr2 + pn
    nonce = '01' + priority_octet + addr2 + pn

    return nonce

def make_iv(packet):
    pn_v = [hex(packet.PN5)[2:], hex(packet.PN4)[2:], hex(packet.PN3)[2:], hex(packet.PN2)[2:], hex(packet.PN1)[2:], hex(packet.PN0)[2:]]
    pn = ''

    for i in pn_v:
        if i == '0':
            pn += i * 2
        elif len(i) != 2:
            pn += '0' + i
        else:
            pn += i

    return pn

def strip(str):
    stripped_str = ''

    for i in str:
        if i != ':':
            stripped_str += i

    return stripped_str
