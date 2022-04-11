#!/usr/bin/python3

import re
import sys
import json
import binascii

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
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
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

targetFile = sys.argv[1]

# Open targetFile in binary mode
getbins = open(targetFile, "rb")

def FileCarver(offset_array):
    for off in offset_array:
        print(f"\n{infoS} Carving executable file found on offset: [bold green]{off}")
        getbins.seek(int(off, 16)) # Locating executable file offset
        try:
            pfile = pf.PE(data=getbins.read()) # Using pefile for PE trim
        except:
            continue

        # Creating dump files
        try:
            dumpfile = open(f"sc0pe_carved-{off}.bin", "wb")
            buffer_to_write = pfile.trim()
            dumpfile.write(buffer_to_write)
            dumpfile.close()
            pfile.close()
            print(f"[bold magenta]>>>[white] Data saved into: [bold green]sc0pe_carved-{off}.bin")
        except:
            continue

def SigChecker(targetFile):
    print(f"\n{infoS} Performing magic number analysis...")

    # Get file signatures
    fsigs = json.load(open(f"{sc0pe_path}/Systems/Multiple/file_sigs.json"))

    # Create tables
    sigTable = Table()
    sigTable.add_column("File Type", justify="center")
    sigTable.add_column("Pattern", justify="center")
    sigTable.add_column("Offset", justify="center")

    # Lets scan!
    mz_offsets = []
    for index in range(0, len(fsigs)):
        for categ in fsigs[index]:
            for sigs in fsigs[index][categ]:
                try:
                    regex = re.finditer(binascii.unhexlify(sigs), getbins.read())
                    for position in regex:
                        sigTable.add_row(str(categ), f"[bold green]{str(binascii.unhexlify(sigs))}", str(hex(position.start())))
                        if sigs == "4D5A900003000000" and str(hex(position.start())) != "0x0":
                            mz_offsets.append(hex(position.start()))
                except:
                    continue
    print(sigTable)
    if mz_offsets != []:
        choice = str(input(f"{infoC} Do you want to extract executable files from target file[Y/n]?: "))
        if choice == "Y" or choice == "y":
            FileCarver(mz_offsets)

SigChecker(targetFile)