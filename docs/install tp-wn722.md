# Intallation of TP-WN-722N v2/v3 on RPIs

#### Stažení a samotná instalace

`sudo apt update && sudo apt upgrade`

*aktualizace a upgrade stávajících balíčků RPI*



`sudo apt install raspberrypi-kernel-headers aircrack-ng bc`

*instalace potřebných dependencies*



`git clone [https://github.com/aircrack-ng/rtl8188eus](https://github.com/aircrack-ng/rtl8188eus)`

*stažení ovladačů*



```bash
cd rtl8188eus
sudo -i
echo "blacklist r8188eu" > "/etc/modprobe.d/realtek.conf"
exit
make
sudo make install
```

*natažení ovladačů a zkompilování*



`sudo reboot`

*restart zařízení*



#### Zapnutí monitorovacího módu

```bash
sudo airmon-ng check kill
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
```





#### Test - scan zařízení v okolí

`sudo aireplay-ng -9 wlan1`


