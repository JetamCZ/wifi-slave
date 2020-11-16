#https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer/blob/master/python-packet-sniffer.py
from dot11_frame import Dot11Frame
import os
import atexit
import time
import math
import requests
import threading
import pprint
import json
from scapy.all import *
import sys

#Start and Stop wificard
def start_monitor(interface): 
    os.system("ifconfig "+interface+" down")
    os.system("iwconfig "+interface+" mode monitor")
    os.system("ifconfig "+interface+" up")

def stop_monitor(interface): 
    os.system("ifconfig "+interface+" down")
    os.system("iwconfig "+interface+" mode managed")
    os.system("ifconfig "+interface+" up")

def network_monitoring_for_visualization_version(pkt):
    try:
        if(pkt.haslayer(Dot11)):
            frame = Dot11Frame(pkt, iface=interface)

            if(frame.src == "e0:d0:83:d6:2a:57"):
                print(pkt.summary())
                print(frame)
        

            if(frame.src is not None):
                if(frame.ssid is None):
                    setPacket(frame.src, frame.signal_strength, "")
                else:
                    setPacket(frame.src, frame.signal_strength, frame.ssid)

    except Exception as e:
        print(e)

def setPacket(mac, rssi, name):
    global devices
    
    rssiCOM = rssi
    rssiCOUNT = 1

    found = None
    
    if len(devices) > 0:
        for x in devices:
            if x['mac'] == str(mac):
                found = x
                break

    #if found = none tak smaz (ale nech v found)
    if found is not None:
        rssiCOM = found['rssiCom'] + rssiCOM
        rssiCOUNT = found['rssiCOUNT'] + rssiCOUNT
        try:
            devices.remove(found)
        except ValueError:
            pass

    #pushni data do devices
    obj = {"mac": mac, "rssi": math.floor(rssiCOM/rssiCOUNT), "realRssi": rssi, "rssiCom": rssiCOM, "rssiCOUNT": rssiCOUNT, "lastSaw": math.floor(time.time()), "name": name}
    devices.append(obj)

    #dev vypis data
    if(False):
        devices = sorted(devices, key=lambda x: x['mac'])
        os.system("clear")
        for dev in devices:
            print(dev)

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

def sendData():
    global devices

    print('send data', len(devices))

    try:
        new_data = {
            'devices': devices,
            'device_key': getserial()
        }

        data = json.dumps(new_data)

        devices = []
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        requests.post(url= "https://wifilocation.herokuapp.com/beacon", data = data, headers = headers)
    except Exception as e: 
        print(e)

def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t

def exit_handler():
    stop_monitor(interface)
    sendData()
    print("Exiting...stopping scan..")

def main():
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    sniff(iface=interface, prn=network_monitoring_for_visualization_version)

if __name__ == '__main__':
    interface = 'wlan1'
    devices = []

    set_interval(sendData, 3)
    atexit.register(exit_handler)
    start_monitor(interface)
    main()