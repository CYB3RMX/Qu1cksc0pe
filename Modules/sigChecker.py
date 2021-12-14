#!/usr/bin/python3

import re
import sys
import json
import binascii

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
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

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

def SigChecker(targetFile):
    print(f"\n{infoS} Performing magic number analysis...")

    # Open targetFile in binary mode
    getbins = open(targetFile, "rb").read()

    # Get file signatures
    fsigs = json.load(open(f"{sc0pe_path}/Systems/Multiple/file_sigs.json"))

    # Create tables
    sigTable = PrettyTable()
    sigTable.field_names = ["File Type", "Pattern", "Count"]

    # Lets scan!
    for index in range(0, len(fsigs)):
        for categ in fsigs[index]:
            for sigs in fsigs[index][categ]:
                regex = re.findall(binascii.unhexlify(sigs), getbins)
                if regex != []:
                    sigTable.add_row([categ, str(binascii.unhexlify(sigs)), len(regex)])
    print(sigTable)

targetBin = sys.argv[1]
SigChecker(targetFile=targetBin)