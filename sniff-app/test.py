#https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer/blob/master/python-packet-sniffer.py
from scapy.all import *
import datetime
import os
import time
from dot11_frame import Dot11Frame
import pprint
import threading

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
            #time=datetime.datetime.now()
            frame = Dot11Frame(pkt, iface=interface)
            #print(frame)
    except Exception as e:
        print(e)

def sendData():
    print('send data')

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
    set_interval(sendData, 3)

if __name__ == '__main__':
    interface = 'wlan1'
    devices = []

    atexit.register(exit_handler)
    start_monitor(interface)
    main()