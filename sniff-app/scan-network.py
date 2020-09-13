import os
import atexit
import time
import math
import requests
import threading
from pprint import pprint
import json
import scapy.all as scapy

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

    name = ""
    try:
        if(len(pkt.info) < 20):
            name = str(pkt.info)
    except AttributeError: 
        pass

    if pkt.haslayer(scapy.Dot11):
        layer = pkt.getlayer(scapy.Dot11)
        
        extra = pkt.notdecoded
        rssi = -(256-ord(extra[-4:-3]))

        if(rssi < 0 and rssi > -256):
            setPacket(layer.addr2, rssi, name)

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
        if(mac == 'e0:d0:83:d6:2a:57'):
            print obj


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
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t

def sendData():
    global devices
    global api_key

    try:
        data = {
            'devices': devices,
            'api_key': api_key,
            'device_key': 'A1'
        }

        data = json.dumps(data)

        #pprint(data)

        devices = []
        requests.post(url= "http://boil.puhony.eu/rpi.php", data = data)
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
    interface = "wlan0"

    #?
    devices = []
    api_key= "testing-app"

    set_interval(sendData, 3)

    atexit.register(exit_handler)
    main()