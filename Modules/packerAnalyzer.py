#!/usr/bin/python3

import os
import sys
try:
    from prettytable import PrettyTable
except:
    print("Module: >prettytable< not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# File signatures
file_sigs = {'UPX': 'UPX0', 'AsPack': '.aspack', 'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0'}

# Getting file's all strings to analyze
try:
    command = f"strings --all {sys.argv[1]} > tempPack.txt"
    os.system(command)
except:
    os.system("if [ -e tempPack.txt ];then rm -f tempPack.txt; fi")

# Simple analyzer function
def Analyzer():
    packTable = PrettyTable()
    packTable.field_names = [f"{green}Extracted Strings{white}", f"{green}Packer Type{white}"]
    packed = 0
    allHex = open("tempPack.txt", "r").read()

    print(f"{infoS} Searching strings about common packers...")
    for pack in file_sigs:
        if file_sigs[pack] in allHex:
            packed += 1
            packTable.add_row([f"{red}{file_sigs[pack]}{white}", f"{red}{pack}{white}"])

    if packed == 0:
        print(f"{errorS} Nothing found.")
    else:
        print(f"{packTable}\n")

# Execute and clean up
try:
    Analyzer()
    os.system("if [ -e tempPack.txt ];then rm -f tempPack.txt; fi")
except:
    print(f"{errorS} Program terminated.")
    os.system("if [ -e tempPack.txt ];then rm -f tempPack.txt; fi")