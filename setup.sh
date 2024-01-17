#!/bin/bash

# Colors
cyan='\e[96m'
red='\e[91m'
green='\e[92m'
default='\e[0m'
yellow='\e[93m'

# Legends
info="${cyan}[${yellow}*${cyan}]${default}"
success="${cyan}[${green}+${cyan}]${default}"
error="${cyan}[${red}!${cyan}]${default}"

# Detecting package manager
command_exists() {
  command -v "$1" >/dev/null 2>&1
}
if command_exists apt; then
  echo -en "${info} APT package manager detected.\n"
  package_manager="apt install"
fi
if command_exists pacman; then
  echo -en "${info} Pacman package manager detected.\n"
  package_manager="pacman -S"
fi

# Gather necessary python modules
if command -v pip3 &>/dev/null; then
    echo -en "${info} Installing python modules...\n"
    pip3 install -r requirements.txt
else
  echo -en "${error} pip3 is not installed on this system. Installing it for you..."
  sudo ${package_manager} python3-pip
  echo -en "${info} Installing python modules...\n"
  pip3 install -r requirements.txt
fi

# Setting up sc0pe_Base folder in /home/$user if its not exist
echo -en "${info} Setting up ${green}sc0pe_Base${default} folder in ${green}/home/$USER${default}...\n"
USER=$(whoami)
if [ ! -d "/home/$USER/sc0pe_Base" ]; then
    echo -en "${info} Creating ${green}sc0pe_Base${default} folder in ${green}/home/$USER${default}...\n"
    mkdir /home/$USER/sc0pe_Base
else
    echo -en "${info} ${green}sc0pe_Base${default} folder is already exist in ${green}/home/$USER${default}...\n"
fi

# Check for ADB command
if command -v adb &>/dev/null; then
    echo -en "${success} ${green}ADB${default} command is already exist!"
else
    echo -en "${error} ADB command is not installed on this system. Installing it for you..."
    sudo ${package_manager} adb
    echo -en "${success} Done!\n"
fi

# Downloading and setup Jadx from Github if its not exist in sc0pe_Base folder
if [ ! -d "/home/$USER/sc0pe_Base/jadx" ]; then
    echo -en "${info} Downloading Jadx...\n"
    wget "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip" -O jadx.zip
    echo -en "${info} Unzipping Jadx...\n"
    unzip -q jadx.zip -d jadx
    echo -en "${info} Removing junks...\n"
    rm -rf jadx.zip
    echo -en "${info} Setting up Jadx...\n"
    mv jadx/ /home/$USER/sc0pe_Base/
    echo -en "${info} Modifying Systems/Android/libScanner.conf...\n"
    sed -i "s|/usr/bin/jadx|/home/$USER/sc0pe_Base/jadx/bin/jadx|g" Systems/Android/libScanner.conf
    echo -en "${success} Done!\n"
else
    echo -en "${info} Jadx is already exist in ${green}/home/$USER/sc0pe_Base${default}...\n"
fi

# Check for strings command
if [ ! -f "/usr/bin/strings" ]; then
    echo -e "${error} Whoa there! ${green}strings${default} command is not exist in your system!"
    echo -en "${yellow}>>> ${default}I will install it for you, but you need to enter your password to continue...\n"
    sudo ${package_manager} binutils
    echo -en "${success} Done!\n"
else
    echo -en "${info} ${green}strings${default} command is already exist...\n"
fi

# Check for dos2unix
if [ ! -f "/usr/bin/dos2unix" ]; then
    echo -en "${info} Installing ${green}dos2unix${default} command...\n"
    sudo ${package_manager} dos2unix
    echo -en "${success} Done!\n"
fi

# Check for pyOneNote
if [ ! -f "/home/$USER/.local/bin/pyonenote" ]; then
    echo -en "${info} Cloning ${green}pyOneNote${default}...\n"
    pip install -U https://github.com/DissectMalware/pyOneNote/archive/master.zip --force
else
    echo -en "${info} ${green}pyOneNote${default} is already exist...\n"
fi

# Setting up "mono-complete"
echo -en "${info} Setting up mono-complete\n"
sudo ${package_manager} mono-complete

echo -en "\n${info} All done.\n"