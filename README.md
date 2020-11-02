# Lokalizace wifi zařízení

Tento projekt vzniká jako maturitní práce: Matěj Půhoný - 2020

### Instalace na RPI lite
1) nastavení wifi - sudo raspi-config
2) instalace git `sudo apt install git`
3) git clone https://github.com/JetamCZ/wifi.git
4) cd wifi

apt install python2 
pip install requests
pip install scapy
sudo apt install python-socketio


### AutoRun
sudo crontab -e
@reboot sudo python /home/pi/wifi/sniff-app/scan-network.py