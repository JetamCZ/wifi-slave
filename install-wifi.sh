sudo dpkg --configure -a
sudo apt update && sudo apt upgrade
sudo apt install raspberrypi-kernel-headers aircrack-ng bc
git clone https://github.com/aircrack-ng/rtl8188eus
cd rtl8188eus
sudo -i
echo "blacklist r8188eu" > "/etc/modprobe.d/realtek.conf"
exit
make
sudo make install
cd ..
rm -rf rtl8188eus
echo "Please Reboot"