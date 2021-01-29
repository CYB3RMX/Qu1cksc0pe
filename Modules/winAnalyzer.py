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

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
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
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Keywords for categorized scanning
allStrings = open("temp.txt", "r").read().split('\n')
regarr = open("Systems/Windows/Registry.txt", "r").read().split("\n")
filearr = open("Systems/Windows/File.txt", "r").read().split("\n")
netarr = open("Systems/Windows/Network.txt", "r").read().split("\n")
keyarr = open("Systems/Windows/Keyboard.txt", "r").read().split("\n")
procarr = open("Systems/Windows/Process.txt", "r").read().split("\n")
memoarr = open("Systems/Windows/Memoryz.txt", "r").read().split("\n")
dllarr = open("Systems/Windows/Resources.txt", "r").read().split("\n")
debugarr = open("Systems/Windows/Debugger.txt", "r").read().split("\n")
systarr = open("Systems/Windows/Syspersist.txt", "r").read().split("\n")
comarr = open("Systems/Windows/COMObject.txt", "r").read().split("\n")
cryptarr = open("Systems/Windows/Crypto.txt", "r").read().split("\n")
datarr = open("Systems/Windows/DataLeak.txt", "r").read().split("\n")
otharr = open("Systems/Windows/Other.txt", "r").read().split("\n")

# Category arrays
Registry = []
File = []
Network = []
Keyboard = []
Process = []
Memory = []
Dll = []
Evasion_Bypassing = []
SystemPersistence = []
COMObject = []
Cryptography = []
Info_Gathering = []
Other = []

# Dictionary of Categories
dictCateg = {
    "Registry": Registry,
    "File": File,
    "Networking/Web": Network,
    "Keyboard/Keylogging": Keyboard,
    "Process": Process,
    "Memory Management": Memory,
    "Dll/Resource Handling": Dll,
    "Evasion/Bypassing": Evasion_Bypassing,
    "System/Persistence": SystemPersistence,
    "COMObject": COMObject,
    "Cryptography": Cryptography,
    "Information Gathering": Info_Gathering,
    "Other/Unknown": Other
}

# score table for checking how many functions in that file
scoreDict = {
    "Registry": 0,
    "File": 0,
    "Networking/Web": 0,
    "Keyboard/Keylogging": 0,
    "Process": 0,
    "Memory Management": 0,
    "Dll/Resource Handling": 0,
    "Evasion/Bypassing": 0,
    "System/Persistence": 0,
    "COMObject": 0,
    "Cryptography": 0,
    "Information Gathering": 0,
    "Other/Unknown": 0
}

# Accessing categories
regdict = {
    "Registry": regarr, "File": filearr,
    "Networking/Web": netarr, "Keyboard/Keylogging": keyarr,
    "Process": procarr, "Memory Management": memoarr,
    "Dll/Resource Handling": dllarr, "Evasion/Bypassing": debugarr,
    "System/Persistence": systarr,
    "COMObject": comarr, "Cryptography": cryptarr,
    "Information Gathering": datarr, "Other/Unknown": otharr
}

# Defining function
def Analyzer():
    # Creating tables
    allFuncs = 0
    tables = PrettyTable()
    dllTable = PrettyTable()
    resTable = PrettyTable()
    statistics = PrettyTable()

    # Gathering information about sections
    pe = pf.PE(fileName)
    print(f"{infoS} Informations about Sections")
    print("-"*40)
    for sect in pe.sections:
        print(sect.Name.decode().rstrip('\x00') + "\n|\n|---- Virtual Size: " + hex(sect.Misc_VirtualSize) + "\n|\n|---- Virtual Address: " + hex(sect.VirtualAddress) + "\n|\n|---- Size of Raw Data: " + hex(sect.SizeOfRawData) + "\n|\n|---- Pointer to Raw Data: " + hex(sect.PointerToRawData) + "\n|\n|---- Characteristics: " + hex(sect.Characteristics) + "\n")
    print("-"*40)

    # categorizing extracted strings
    for key in regdict:
        for el in regdict[key]:
            if el in allStrings:
                if el != "":
                    dictCateg[key].append(el)
                    allFuncs += 1

    # printing categorized strings
    for key in dictCateg:
        if dictCateg[key] != []:

            # More important categories
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                print(f"\n{yellow}[{red}!{yellow}]__WARNING__[{red}!{yellow}]{white}")

            # Printing zone
            tables.field_names = [f"Functions or Strings about {green}{key}{white}"]
            for i in dictCateg[key]:
                if i == "":
                    pass
                else:
                    tables.add_row([f"{red}{i}{white}"])

                    # Logging for summary table
                    if key == "Registry":
                        scoreDict[key] += 1
                    elif key == "File":
                        scoreDict[key] += 1
                    elif key == "Networking/Web":
                        scoreDict[key] += 1
                    elif key == "Keyboard/Keylogging":
                        scoreDict[key] += 1
                    elif key == "Process":
                        scoreDict[key] += 1
                    elif key == "Memory Management":
                        scoreDict[key] += 1
                    elif key == "Dll/Resource Handling":
                        scoreDict[key] += 1
                    elif key == "Evasion/Bypassing":
                        scoreDict[key] += 1
                    elif key == "System/Persistence":
                        scoreDict[key] += 1
                    elif key == "COMObject":
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        scoreDict[key] += 1
                    else:
                        pass
            print(tables)
            tables.clear_rows()

    # gathering extracted dll files
    dllTable.field_names = [f"Linked {green}DLL{white} Files"]
    for items in pe.DIRECTORY_ENTRY_IMPORT:
        dlStr = str(items.dll.decode())
        dllTable.add_row([f"{red}{dlStr}{white}"])
    print(dllTable)

    # Resource scanner zone
    resCounter = 0
    resTable.field_names = [f"Extracted File Extensions", "Names", "Byte Matches", "Confidence"]
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

    # printing all function statistics
    statistics.field_names = ["Categories", "Number of Functions or Strings"]
    statistics.add_row([f"{green}All Functions{white}", f"{green}{allFuncs}{white}"])
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                statistics.add_row([f"{yellow}{key}{white}", f"{red}{scoreDict[key]}{white}"])
            else:
                statistics.add_row([f"{white}{key}", f"{scoreDict[key]}{white}"])
    print(statistics)

    # Warning about obfuscated file
    if allFuncs < 20:
        print(f"\n{errorS} This file might be obfuscated or encrypted. Try {green}--packer{white} to scan this file for packers.")
        print(f"{errorS} You can also use {green}--hashscan{white} to scan this file.\n")
        sys.exit(0)

# Execute
Analyzer()
