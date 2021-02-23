#!/usr/bin/python3

import os
import sys

# Checking for puremagic
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Checking for colorama
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< not found.")
    sys.exit(1)

# Checking for prettytable
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Checking for oletools
try:
    from oletools.olevba import VBA_Parser
    from oletools.crypto import is_encrypted
    from oletools.oleid import OleID
    from olefile import isOleFile
except:
    print("Error: >oletools< module not found.")
    print("Try 'sudo -H pip3 install -U oletools' command.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Target file
targetFile = str(sys.argv[1])

# A function that finds VBA Macros
def MacroHunter(targetFile):
    answerTable = PrettyTable()
    answerTable.field_names = [f"{green}Threat Levels{white}", f"{green}Macros{white}", f"{green}Descriptions{white}"]

    print(f"\n{infoS} Looking for VBA Macros...")
    try:
        fileData = open(targetFile, "rb").read()
        vbaparser = VBA_Parser(targetFile, fileData)
        macroList = list(vbaparser.analyze_macros())
        if vbaparser.contains_macros == True:
            for fi in range(0, len(macroList)):
                if macroList[fi][0] == 'Suspicious':
                    if "(use option --deobf to deobfuscate)" in macroList[fi][2]:
                        sanitized = f"{macroList[fi][2]}".replace("(use option --deobf to deobfuscate)", "")
                        answerTable.add_row([f"{yellow}{macroList[fi][0]}{white}", f"{macroList[fi][1]}", f"{sanitized}"])
                    elif "(option --decode to see all)" in macroList[fi][2]:
                        sanitized = f"{macroList[fi][2]}".replace("(option --decode to see all)", "")
                        answerTable.add_row([f"{yellow}{macroList[fi][0]}{white}", f"{macroList[fi][1]}", f"{sanitized}"])
                    else:
                        answerTable.add_row([f"{yellow}{macroList[fi][0]}{white}", f"{macroList[fi][1]}", f"{macroList[fi][2]}"])
                elif macroList[fi][0] == 'IOC':
                    answerTable.add_row([f"{magenta}{macroList[fi][0]}{white}", f"{macroList[fi][1]}", f"{macroList[fi][2]}"])
                elif macroList[fi][0] == 'AutoExec':
                    answerTable.add_row([f"{red}{macroList[fi][0]}{white}", f"{macroList[fi][1]}", f"{macroList[fi][2]}"])
                else:
                    answerTable.add_row([f"{macroList[fi][0]}", f"{macroList[fi][1]}", f"{macroList[fi][2]}"])
            print(f"{answerTable}\n")
        else:
            print(f"{errorS} Not any VBA macros found.")
    except:
        print(f"{errorS} An error occured while parsing that file for macro scan.")

# Gathering basic informations
def BasicInfoGa(targetFile):
    # Check for ole structures
    if isOleFile(targetFile) == True:
        print(f"{infoS} Ole File: {green}True{white}")
    else:
        print(f"{infoS} Ole File: {red}False{white}")

    # Check for encryption
    if is_encrypted(targetFile) == True:
        print(f"{infoS} Encrypted: {green}True{white}")
    else:
        print(f"{infoS} Encrypted: {red}False{white}")
    
    # VBA_MACRO scanner
    vbascan = OleID(targetFile)
    vbascan.check()
    # Sanitizing the array
    vba_params = []
    for vb in vbascan.indicators:
        vba_params.append(vb.id)

    if "vba_macros" in vba_params:
        for vb in vbascan.indicators:
            if vb.id == "vba_macros":
                if vb.value == True:
                    print(f"{infoS} VBA Macros: {green}Found{white}")
                    MacroHunter(targetFile)
                else:
                    print(f"{infoS} VBA Macros: {red}Not Found{white}")
    else:
        MacroHunter(targetFile)

# A function that handles file types, extensions etc.
def MagicParser(targetFile):
    # Defining table
    resTable = PrettyTable()

    # Magic byte parsing
    resCounter = 0
    resTable.field_names = [f"File Extension", "Names", "Byte Matches", "Confidence"]
    resourceList = list(pr.magic_file(targetFile))
    for res in range(0, len(resourceList)):
        extrExt = str(resourceList[res].extension)
        extrNam = str(resourceList[res].name)
        extrByt = str(resourceList[res].byte_match)
        if resourceList[res].confidence >= 0.8:
            resCounter += 1
            if extrExt == '':
                resTable.add_row([f"{red}No Extension{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
            else:
                resTable.add_row([f"{red}{extrExt}{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
    if len(resourceList) != 0:
        print(resTable)

# Execution area
try:
    BasicInfoGa(targetFile)
    print(f"\n{infoS} Performing magic number analysis...")
    MagicParser(targetFile)
except:
    print(f"{errorS} An error occured while analyzing that file.")
    sys.exit(1)
