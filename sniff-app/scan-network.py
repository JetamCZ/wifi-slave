from sockets import Client
from dot11_frame import Dot11Frame
import os
import atexit
from scapy.all import *
import sys

sio = Client()

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

            if(frame.src is not None):
                if(frame.ssid is None):
                    sio.emit('data', {'mac': frame.src, 'rssi': frame.signal_strength, 'name': '', 'lastSaw': math.floor(time.time())})
                else:
                    sio.emit('data', {'mac': frame.src, 'rssi': frame.signal_strength, 'name': frame.ssid, 'lastSaw': math.floor(time.time())})
        else:
            print(pkt.summary())
    except Exception as e:
        print(e)

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

@sio.event
def connect():
    sio.emit('auth', {'deviceKey': getserial()})
    print('connected to server')
\
@sio.event
def connect_error():
    print("The connection failed!")

@sio.event
def disconnect():
    print("I'm disconnected!")

def exit_handler():
    stop_monitor(interface)
    print("Exiting...stopping scan..")

def main():
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    atexit.register(exit_handler)

    sio.connect('https://wifilocation.herokuapp.com/')

    start_monitor(interface)
    sniff(iface=interface, prn=network_monitoring_for_visualization_version, store=0)

if __name__ == '__main__':
    interface = 'wlan1'
    main()