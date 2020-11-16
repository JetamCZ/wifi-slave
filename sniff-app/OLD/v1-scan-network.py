import os
import atexit
import time
import math
import requests
import threading
from pprint import pprint
import json
from scapy.all import *

class deviceObj:
    def __init__(self, mac, rssi):  
        self.mac = mac  
        self.rssi = rssi 

#Start and Stop wificard
def start_monitor(interface): 
    os.system("ifconfig "+interface+" down")
    os.system("iwconfig "+interface+" mode monitor")
    os.system("ifconfig "+interface+" up")

def stop_monitor(interface): 
    os.system("ifconfig "+interface+" down")
    os.system("iwconfig "+interface+" mode managed")
    os.system("ifconfig "+interface+" up")

#processes
def process_packet(pkt):
    global devices

    try:        
        if pkt.haslayer(Dot11):
            radiotap = pkt.getlayer(RadioTap)
            rssi = radiotap.dBm_AntSignal

            layer = pkt.getlayer(Dot11)

            if pkt.haslayer(Dot11Beacon):
                essid = str(pkt.getlayer(Dot11Elt).info)
                setPacket(layer.addr1, 0, essid)
            setPacket(layer.addr2, rssi, "")
    except Exception as e:
        #pass
        print(e)

def setPacket(mac, rssi, name):
    global devices
    
    rssiCOM = rssi
    rssiCOUNT = 1
    if mac is not None:
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


#MainRun
def main():
    #check rights
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    #run
    start_monitor(interface)
    sniff(iface=interface, prn=process_packet, store=0)

def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t

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
    global api_key

    try:
        new_data = {
            'devices': devices,
            'api_key': api_key,
            'device_key': getserial()
        }

        data = json.dumps(new_data)
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        devices = []
        requests.post(url= "https://wifilocation.herokuapp.com/beacon", data = data, headers = headers)
    except: 
        pass

def exit_handler():
    stop_monitor(interface)

    sendData()

    print("Exiting...stopping scan..")


if __name__ == "__main__":
    print('Sniffer loading save pause... 5s to start')
    # time.sleep(5)
    print('Sniffer starts loading')

    #set props
    interface = "wlan1"

    #?
    devices = []
    api_key= "testing-app"

    set_interval(sendData, 3)

    atexit.register(exit_handler)
    main()