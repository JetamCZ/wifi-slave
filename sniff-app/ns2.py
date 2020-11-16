import socket
import struct
import os
from scapy.all import *
from radiotap import radiotap

# create Socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

interface = "wlan1"

os.system("ifconfig "+interface+" down")
os.system("iwconfig "+interface+" mode monitor")
os.system("ifconfig "+interface+" up")
s.bind((interface,0x0003))

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

# loop
while True:
    pkt, addr = s.recvfrom(2048)

    try:
        eth = Ether(pkt)
        eth.hide_defaults()
        rssi = radiotap.radiotap_parse(pkt)[1]["dbm_antsignal"]
        print(eth.src, rssi)
    except:
        pass
