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
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"
thLevel = f"{cyan}[{red}Threat Level{cyan}]{white}"

# Keywords for categorized scanning
allStrings = open("temp.txt", "r").read().split('\n')
regarr = open("Systems/Windows/Registry.txt", "r").read().split("\n")
filearr = open("Systems/Windows/File.txt", "r").read().split("\n")
netarr = open("Systems/Windows/Network.txt", "r").read().split("\n")
keyarr = open("Systems/Windows/Keyboard.txt", "r").read().split("\n")
procarr = open("Systems/Windows/Process.txt", "r").read().split("\n")
memoarr = open("Systems/Windows/Memoryz.txt", "r").read().split("\n")
dllarr = open("Systems/Windows/DLL.txt", "r").read().split("\n")
debugarr = open("Systems/Windows/Debugger.txt", "r").read().split("\n")
systarr = open("Systems/Windows/Syspersist.txt", "r").read().split("\n")
comarr = open("Systems/Windows/COMObject.txt", "r").read().split("\n")
cryptarr = open("Systems/Windows/Crypto.txt", "r").read().split("\n")
datarr = open("Systems/Windows/DataLeak.txt", "r").read().split("\n")
otharr = open("Systems/Windows/Other.txt", "r").read().split("\n")
dllArray = open("Systems/Windows/DLLlist.txt", "r").read().split("\n")

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
    threatScore = 0
    allFuncs = 0
    tables = PrettyTable()
    dllTable = PrettyTable()
    extTable = PrettyTable()
    mimeTable = PrettyTable()
    ftypeTable = PrettyTable()
    statistics = PrettyTable()

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

                    # Calculating threat score
                    if key == "Registry":
                        threatScore += 4
                        scoreDict[key] += 1
                    elif key == "File":
                        threatScore += 4
                        scoreDict[key] += 1
                    elif key == "Networking/Web":
                        threatScore += 6
                        scoreDict[key] += 1
                    elif key == "Keyboard/Keylogging":
                        threatScore += 7
                        scoreDict[key] += 1
                    elif key == "Process":
                        threatScore += 5
                        scoreDict[key] += 1
                    elif key == "Memory Management":
                        threatScore += 5
                        scoreDict[key] += 1
                    elif key == "Dll/Resource Handling":
                        threatScore += 6
                        scoreDict[key] += 1
                    elif key == "Evasion/Bypassing":
                        threatScore += 9
                        scoreDict[key] += 1
                    elif key == "System/Persistence":
                        threatScore += 9
                        scoreDict[key] += 1
                    elif key == "COMObject":
                        threatScore += 4
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        threatScore += 9
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        threatScore += 7
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        threatScore += 1
                        scoreDict[key] += 1
                    else:
                        pass
            print(tables)
            tables.clear_rows()

    # printing extracted dll files
    dllTable.field_names = [f"Extracted {green}DLL{white} Strings"]
    for dl in allStrings:
        if dl in dllArray:
            if dl != "":
                dllTable.add_row([f"{red}{dl}{white}"])
    print(dllTable)

    # Resource scanner zone
    extTable.field_names = [f"Extracted {green}File Extensions{white}"]
    mimeTable.field_names = [f"Extracted {green}Mime Types{white}"]
    ftypeTable.field_names = [f"Extracted {green}File Types{white}"]

    with open(fileName, "rb") as targFile:
        extract = fl.get(targFile.read(128))
    # Defining arrays
    extArr = list(extract.extension)
    mimeAr = list(extract.mime)
    ftypes = list(extract.type)
    # For file extensions
    if extArr != []:
        for ex in extArr:
            extTable.add_row([f"{red}{ex}{white}"])
        print(extTable)
    # For mime types
    if mimeAr != []:
        for mt in mimeAr:
            mimeTable.add_row([f"{red}{mt}{white}"])
        print(mimeTable)
    # For file types
    if ftypes != []:
        for ft in ftypes:
            ftypeTable.add_row([f"{red}{ft}{white}"])
        print(ftypeTable)

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
    if allFuncs < 10:
        print(f"\n{errorS} This file might be obfuscated or encrypted. Try {green}--packer{white} to scan this file for packers.\n")
        sys.exit(0)

    # score table
    print(f"\n{errorS} ATTENTION: There might be false positives in threat scaling system.")

    # score conditions
    if threatScore < 30:
        print(f"{thLevel}: {green}Clean{white}.\n")
    elif threatScore >= 30 and threatScore <= 200:
        print(f"{errorS} Attention: Use {green}--vtFile{white} argument to scan that file with VirusTotal. Do not trust that file.")
        print(f"{thLevel}: {yellow}Suspicious{white}.\n")
    else:
        print(f"{thLevel}: {red}Potentially Malicious{white}.\n")

# Execute
Analyzer()