#!/bin/bash

sudo cp qu1cksc0pe.py /usr/bin &>/dev/null
if [ $? -eq 0 ];then
   sudo chmod 755 /usr/bin/qu1cksc0pe.py
fi
sudo cp grepper.sh /usr/bin &>/dev/null
if [ $? -eq 0 ];then
   sudo chmod 755 /usr/bin/grepper.sh
fi
echo "[+] Installed."
