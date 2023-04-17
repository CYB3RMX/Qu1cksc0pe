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
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

targetFile = sys.argv[1]

# Open targetFile in binary mode
getbins_buffer = open(targetFile, "rb").read()
getbins = open(targetFile, "rb")

class SignatureChecker:
    def __init__(self, target_file):
        self.target_file = target_file

    def file_carver(self, offset_array):
        self.offset_array = offset_array

        for off in self.offset_array:
            print(f"\n{infoS} Carving executable file found on offset: [bold green]{off}")
            getbins.seek(off) # Locating executable file offset
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

    def signature_checker(self):
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
        valid_pattern_switch = 0
        for index in range(0, len(fsigs)):
            for categ in fsigs[index]:
                for sigs in fsigs[index][categ]:
                    try:
                        regex = re.finditer(binascii.unhexlify(sigs), getbins_buffer)
                        for position in regex:
                            sigTable.add_row(str(categ), f"[bold green]{str(binascii.unhexlify(sigs))}", str(hex(position.start())))
                            if sigs == "4D5A9000" and position.start() != 0:
                                mz_offsets.append(position.start())
                            valid_pattern_switch += 1
                    except:
                        continue
        if valid_pattern_switch == 0:
            print(f"{errorS} There is no valid pattern found!")
        else:
            print(sigTable)

        if mz_offsets != []:
            choice = str(input(f"{infoC} Do you want to extract executable files from target file[Y/n]?: "))
            if choice == "Y" or choice == "y":
                self.file_carver(mz_offsets)

    def search_possible_corrupt_mz_headers(self):
        print(f"\n{infoS} Looking for possible corrupted Windows executable patterns...")
        POSSIBLE_HEADER = "4D5A" # Possible because of false positives

        # Check for headers
        mz_offsets = []
        find = re.finditer(binascii.unhexlify(POSSIBLE_HEADER), getbins_buffer)
        for pos in find:
            if pos.start() % 512 == 0: # Check if the header is aligned
                mz_offsets.append(pos.start())

        # Check possible corrupted MZ headers
        corrupted = 0
        for offset in mz_offsets:
            if getbins_buffer[offset+2:offset+4] != b"\x90\x00":
                print(f"[bold magenta]>>>[white] Possible corrupted MZ header at: [bold green]{hex(offset)}[white]. Attempting to fix that!")
                new_buffer = getbins_buffer[:offset+2] + b"\x90\x00" + getbins_buffer[offset+4:]
                corrupted += 1

        if corrupted == 0:
            print(f"{errorS} There is no corrupted Windows executable pattern found!")
        else:
            with open("fixed_corrupted_headers.exe", "wb") as fx:
                fx.write(new_buffer)
            print(f"\n{infoS} Modified data saved into: [bold green]fixed_corrupted_headers.exe")

# Execution
sig_check = SignatureChecker(target_file=targetFile)
sig_check.signature_checker()
sig_check.search_possible_corrupt_mz_headers()