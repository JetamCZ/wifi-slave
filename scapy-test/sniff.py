import os
from scapy.all import *
from dot11_frame import Dot11Frame

def doData(pkt): 
    try: 
        if(pkt.haslayer(Dot11)):
            frame = Dot11Frame(pkt, iface="wlan1")

            if(frame.src == "e0:d0:83:d6:2a:57" or rame.dst == "e0:d0:83:d6:2a:57")
                print(frame.src, frame.dst, frame.signal_strength, frame.ssid)
        
    except Exception as e:
        print(e)

def main():
    os.system("ifconfig wlan1 down")
    os.system("iwconfig wlan1 mode monitor")
    os.system("ifconfig wlan1 up")

    sniff(iface="wlan1", prn=doData)


if __name__ == '__main__':
    main()