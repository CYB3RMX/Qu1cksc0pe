#!/usr/bin/python3

import os
import sys
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX

# Legends
errorS = f"{cyan}[{red}!{cyan}]{white}"
infoS = f"{cyan}[{red}*{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Wordlists
allStrings = open("temp.txt", "r").read().split("\n")
allThings = open("elves.txt", "r").read()
sections = open(f"{sc0pe_path}/Systems/Linux/sections.txt", "r").read().split("\n")
segments = open(f"{sc0pe_path}/Systems/Linux/segments.txt", "r").read().split("\n")
networkz = open(f"{sc0pe_path}/Systems/Linux/Networking.txt", "r").read().split("\n")
filez = open(f"{sc0pe_path}/Systems/Linux/Files.txt", "r").read().split("\n")
procesz = open(f"{sc0pe_path}/Systems/Linux/Processes.txt", "r").read().split("\n")
memoryz = open(f"{sc0pe_path}/Systems/Linux/Memory.txt", "r").read().split("\n")
infogaz = open(f"{sc0pe_path}/Systems/Linux/Infoga.txt", "r").read().split("\n")
persisz = open(f"{sc0pe_path}/Systems/Linux/Persistence.txt", "r").read().split("\n")
cryptoz = open(f"{sc0pe_path}/Systems/Linux/Crypto.txt", "r").read().split("\n")
otherz = open(f"{sc0pe_path}/Systems/Linux/Others.txt", "r").read().split("\n")

# Categories
Networking = []
File = []
Process = []
Memory = []
Information_Gathering = []
System_Persistence = []
Cryptography = []
Other = []

# Scores
scoreDict = {
        "Networking": 0,
        "File": 0,
        "Process": 0,
        "Memory Management": 0,
        "Information Gathering": 0,
        "System/Persistence": 0,
        "Cryptography": 0,
        "Other/Unknown": 0
        }

# Dictionary of categories
Categs = {
        "Networking": Networking,
        "File": File,
        "Process": Process,
        "Memory Management": Memory,
        "Information Gathering": Information_Gathering,
        "System/Persistence": System_Persistence,
        "Cryptography": Cryptography,
        "Other/Unknown": Other
        }

# Dictionary of arrays
dictArr = {
        "Networking": networkz,
        "File": filez,
        "Process": procesz,
        "Memory Management": memoryz,
        "Information Gathering": infogaz,
        "System/Persistence": persisz,
        "Cryptography": cryptoz,
        "Other/Unknown": otherz
        }

# Defining function
def Analyzer():
    allFuncs = 0
    tables = PrettyTable()
    secTable = PrettyTable()
    segTable = PrettyTable()
    resTable = PrettyTable()
    statistics = PrettyTable()

    for key in dictArr:
        for elem in dictArr[key]:
            if elem in allStrings:
                if elem != "":
                    Categs[key].append(elem)
                    allFuncs +=1
    for key in Categs:
        if Categs[key] != []:
            if key == "Information Gathering" or key == "System/Persistence" or key == "Cryptography":
                print(f"\n{yellow}[{red}!{yellow}]__WARNING__[{red}!{yellow}]{white}")

            # Printing zone
            tables.field_names = [f"Functions or Strings about {green}{key}{white}"]
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    tables.add_row([f"{red}{i}{white}"])
                    # Threat score
                    if key == "Networking":
                        scoreDict[key] += 1
                    elif key == "File":
                        scoreDict[key] += 1
                    elif key == "Process":
                        scoreDict[key] += 1
                    elif key == "Memory Management":
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        scoreDict[key] += 1
                    elif key == "System/Persistence":
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        scoreDict[key] += 1
                    else:
                        pass
            print(tables)
            tables.clear_rows()

    # Gathering sections and segments
    secTable.field_names = [f"{green}Sections{white}"]
    segTable.field_names = [f"{green}Segments{white}"]

    # Sections
    sec_indicator = 0
    for se1 in sections:
        if se1 in allThings:
            if se1 != "":
                secTable.add_row([f"{red}{se1}{white}"])
                sec_indicator += 1
    if sec_indicator != 0:
        print(secTable)
    
    # Segments
    seg_indicator = 0
    for se2 in segments:
        if se2 in allThings:
            if se2 != "":
                segTable.add_row([f"{red}{se2}{white}"])
                seg_indicator += 1
    if seg_indicator != 0:
        print(segTable)

    # Resource scanner zone
    print(f"\n{infoS} Performing magic number analysis...")
    resCounter = 0
    resTable.field_names = [f"File Extensions", "Names", "Byte Matches", "Confidence"]
    resourceList = list(pr.magic_file(fileName))
    for res in range(0, len(resourceList)):
        extrExt = str(resourceList[res].extension)
        extrNam = str(resourceList[res].name)
        extrByt = str(resourceList[res].byte_match)
        if resourceList[res].confidence >= 0.4:
            resCounter += 1
            if extrExt == '':
                resTable.add_row([f"{red}No Extension{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
            else:
                resTable.add_row([f"{red}{extrExt}{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
    if len(resourceList) != 0:
        print(resTable)

    # Statistics zone
    print(f"\n{green}->{white} Statistics for: {green}{fileName}{white}")

    # Printing zone
    statistics.field_names = ["Categories", "Number of Functions"]
    statistics.add_row([f"{green}All Functions{white}", f"{green}{allFuncs}{white}"])
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                statistics.add_row([f"{yellow}{key}{white}", f"{red}{scoreDict[key]}{white}"])
            else:
                statistics.add_row([f"{white}{key}", f"{scoreDict[key]}{white}"])
    print(statistics)

    # Warning about obfuscated file
    if allFuncs < 10:
        print(f"\n{errorS} This file might be obfuscated or encrypted. Try {green}--packer{white} to scan this file for packers.\n")
        sys.exit(0)

# Execute
try:
    Analyzer()
    if os.path.exists("Modules/elves.txt"):
        os.remove("Modules/elves.txt")
except:
    pass
