#! /usr/local/bin/python3.5

import socket
import os
import struct
from radiotap import radiotap

def start_monitor(interface): 
  os.system("ifconfig "+interface+" down")
  os.system("iwconfig "+interface+" mode monitor")
  os.system("ifconfig "+interface+" up")


def main():
    start_monitor('wlan1')
    key = getserial()

    lastMac = ""

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dsc_mac, src_mac = ethernet_frame(raw_data)

        if(lastMac is not src_mac):
            print(src_mac, lastMac)
            lastMac = src_mac
        
            try:
                rssi = radiotap.radiotap_parse(raw_data)[1]["dbm_antsignal"]
                print(key, src_mac, dsc_mac, rssi)
            except Exception as e:
                pass

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac)

# Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#Get device unique identificator
def getserial():
  # Extract serial from cpuinfo file
  cpuserial = "0000000000000000"
  try:
    f = open('/proc/cpuinfo','r')
    for line in f:
      if line[0:6]=='Serial':
        cpuserial = line[10:26]
    f.close()
  except:
    cpuserial = "ERROR000000000"
 
  return cpuserial

main()