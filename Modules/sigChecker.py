#!/usr/bin/python3

import re
import sys
import json
import binascii

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

def SigChecker(targetFile):
    print(f"\n{infoS} Performing magic number analysis...")

    # Open targetFile in binary mode
    getbins = open(targetFile, "rb").read()

    # Get file signatures
    fsigs = json.load(open(f"{sc0pe_path}/Systems/Multiple/file_sigs.json"))

    # Create tables
    sigTable = Table()
    sigTable.add_column("File Type", justify="center")
    sigTable.add_column("Pattern", justify="center")
    sigTable.add_column("Count", justify="center")

    # Lets scan!
    for index in range(0, len(fsigs)):
        for categ in fsigs[index]:
            for sigs in fsigs[index][categ]:
                regex = re.findall(binascii.unhexlify(sigs), getbins)
                if regex != []:
                    sigTable.add_row(str(categ), f"[bold green]{str(binascii.unhexlify(sigs))}", str(len(regex)))
    print(sigTable)

targetBin = sys.argv[1]
SigChecker(targetFile=targetBin)