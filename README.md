# Lokalizace wifi zařízení

Tento projekt vzniká jako maturitní práce: Matěj Půhoný - 2020

### Instalace na RPI lite
1 - nastavení RPI wifi sudo raspi-config (nastavení wifi a ssh), 
ze základu má rasbian přihlašovací údaje `user:pi passport:raspberry` (bacha na anglickou klávesnici)
```
sudo raspi-config
```

2 - Nainstalování driverů pro wifi anténu. (v docs souborech naleznete návod na instalaci pro TP Link TP-WN-722N)

3 - nainstalování potřebných dependencies
```
sudo apt install python python3-pandas python3-requests
```

4 - stažení 
`git clone https://github.com/JetamCZ/wifi.git`

4 - spuštění a majáku
```
sudo python3 ./wifi/sniff-app/sniffing.py -w wlan1
```

### AutoRun (cron)
```
# otevře cron nastavení
sudo crontab -e

#přidáme do nastavení spuštění majáku
@reboot sudo python3 /home/pi/wifi/sniff-app/sniffing.py -w wlan1
```