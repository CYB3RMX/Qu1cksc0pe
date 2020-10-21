#!/usr/bin/python3

import os
import sys
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

try:
    import fleep as fl
except:
    print("Error: >fleep< module not found.")
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
thLevel = f"{cyan}[{red}Threat Level{cyan}]{white}"

# Wordlists
allStrings = open("temp.txt", "r").read().split("\n")
allThings = open("Modules/elves.txt", "r").read()
sections = open("Systems/Linux/sections.txt", "r").read().split("\n")
segments = open("Systems/Linux/segments.txt", "r").read().split("\n")
networkz = open("Systems/Linux/Networking.txt", "r").read().split("\n")
filez = open("Systems/Linux/Files.txt", "r").read().split("\n")
procesz = open("Systems/Linux/Processes.txt", "r").read().split("\n")
memoryz = open("Systems/Linux/Memory.txt", "r").read().split("\n")
infogaz = open("Systems/Linux/Infoga.txt", "r").read().split("\n")
persisz = open("Systems/Linux/Persistence.txt", "r").read().split("\n")
cryptoz = open("Systems/Linux/Crypto.txt", "r").read().split("\n")
otherz = open("Systems/Linux/Others.txt", "r").read().split("\n")

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
    threatScore = 0
    allFuncs = 0
    tables = PrettyTable()
    secTable = PrettyTable()
    segTable = PrettyTable()
    extTable = PrettyTable()
    mimeTable = PrettyTable()
    ftypeTable = PrettyTable()
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
                        threatScore += 10
                        scoreDict[key] += 1
                    elif key == "File":
                        threatScore += 10
                        scoreDict[key] += 1
                    elif key == "Process":
                        threatScore += 15
                        scoreDict[key] += 1
                    elif key == "Memory Management":
                        threatScore += 10
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        threatScore += 20
                        scoreDict[key] += 1
                    elif key == "System/Persistence":
                        threatScore += 20
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        threatScore += 25
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        threatScore += 5
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
    extTable.field_names = [f"Extracted {green}File Extensions{white}"]
    mimeTable.field_names = [f"Extracted {green}Mime Types{white}"]
    ftypeTable.field_names = [f"Extracted {green}File Types{white}"]

    with open(fileName, "rb") as targFile:
        extract = fl.get(targFile.read(128))

    extArr = list(extract.extension)
    mimeAr = list(extract.mime)
    ftypes = list(extract.type)

    if extArr != []:
        for ex in extArr:
            extTable.add_row([f"{red}{ex}{white}"])
        print(extTable)

    if mimeAr != []:
        for mt in mimeAr:
            mimeTable.add_row([f"{red}{mt}{white}"])
        print(mimeTable)

    if ftypes != []:
        for ft in ftypes:
            ftypeTable.add_row([f"{red}{ft}{white}"])
        print(ftypeTable)

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

    # score table
    print(f"\n{errorS} ATTENTION: There might be false positives in threat scaling system.")

    if threatScore < 100:
        print(f"{thLevel}: {green}Clean{white}.\n")
    elif threatScore >= 100 and threatScore <= 300:
        print(f"{errorS} Attention: Use {green}--vtFile{white} argument to scan that file with VirusTotal. Do not trust that file.")
        print(f"{thLevel}: {yellow}Suspicious{white}.\n")
    else:
        print(f"{thLevel}: {red}Potentially Malicious{white}.\n")

# Execute
try:
    Analyzer()
    if os.path.exists("Modules/elves.txt"):
        os.remove("Modules/elves.txt")
except:
    pass