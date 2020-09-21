#!/usr/bin/python3

import os,sys

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'

# File signatures
file_sigs = {'UPX': '55 50 58 21', 'Armadillo': '55 8B EC 6A',
             'Armadillo v1.xx - v2.xx': '55 8B EC 53', 'ASPack 2.xx Heuristic': '90 90 90 90',
             'ASProtect': '60 90 90 90', 'ASPack 1.02b or 1.08.03': '60 E8 00 00',
             'ASPack 1.05b by': '75 00 E9', 'ASPAck 1.061b': '90 90 75 00', 'ASPack 1.08': '90 90 90 75'}

# Getting file's hexcodes to analyze
try:
    command = "hexdump -C {} > hexcodes.txt".format(sys.argv[1])
    os.system(command)
except:
    os.system("if [ -e hexcodes.txt ];then rm -f hexcodes.txt; fi")

# Simple analyzer function
def Analyzer():
    packed = 0
    allHex = open("hexcodes.txt", "r").read()

    for pack in file_sigs:
        if file_sigs[pack] in allHex:
            packed += 1
            print(f"\n{cyan}[{red}+{cyan}]{white} This file might be packed with {green}{pack}\n")
    if packed == 0:
        print(f"{cyan}[{red}!{cyan}]{white} Nothing found.")

# Execute and clean up
try:
    Analyzer()
    os.system("rm hexcodes.txt")
except:
    print(f"{cyan}[{red}!{cyan}]{white} Program terminated.")
    os.system("if [ -e hexcodes.txt ];then rm -f hexcodes.txt; fi")