#!/usr/bin/python3

import os,sys

# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'

# File signatures
file_sigs = {'UPX0': '55 50 58 30', 'Armadillo v1.71': '55 8B EC 6A FF 68', 'Armadillo v1.72 - v1.73': '55 8B EC 6A FF 68 E8 C1',
             'Armadillo v1.xx - v2.xx': '55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6', 'ASPack 2.xx Heuristic': '90 90 90 90 68',
             'ASProtect': '60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9', 'ASPack 1.02b or 1.08.03': '60 E8 00 00 00 00 5D 81 ED',
             'ASPack 1.05b by': '75 00 E9', 'ASPAck 1.061b': '90 90 75 00 E9', 'ASPack 1.08': '90 90 90 75 01 90 E9'}

# Getting file's hexcodes to analyze
command = "hexdump -C {} > hexcodes.txt".format(sys.argv[1])
os.system(command)

# Simple analyzer function
def Analyzer():
    packed = 0
    allHex = open("hexcodes.txt", "r").read()

    for pack in file_sigs:
        if file_sigs[pack] in allHex:
            packed += 1
            print("{}[{}+{}]{} This file might be packed with {}{}".format(cyan,red,cyan,white,green,pack))
    if packed == 0:
        print("{}[{}!{}]{} Nothing found.".format(cyan,red,cyan,white))

# Execute and clean up
Analyzer()
os.system("rm hexcodes.txt")
