#!/usr/bin/python3

import os,sys
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

# Wordlists
allStrings = open("temp.txt","r").read().split("\n")
networkz = open("Systems/Linux/Networking.txt","r").read().split("\n")
filez = open("Systems/Linux/Files.txt","r").read().split("\n")
procesz = open("Systems/Linux/Processes.txt","r").read().split("\n")
memoryz = open("Systems/Linux/Memory.txt","r").read().split("\n")
infogaz = open("Systems/Linux/Infoga.txt","r").read().split("\n")
persisz = open("Systems/Linux/Persistence.txt","r").read().split("\n")
cryptoz = open("Systems/Linux/Crypto.txt","r").read().split("\n")
otherz = open("Systems/Linux/Others.txt","r").read().split("\n")

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
        "Information Gathering":0,
        "System/Persistence":0,
        "Cryptography":0,
        "Other/Unknown":0
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
                        threatScore +=10
                        scoreDict[key] +=1
                    elif key == "File":
                        threatScore += 10
                        scoreDict[key] +=1
                    elif key == "Process":
                        threatScore += 15
                        scoreDict[key] +=1
                    elif key == "Memory Management":
                        threatScore += 10
                        scoreDict[key] +=1
                    elif key == "Information Gathering":
                        threatScore += 20
                        scoreDict[key] +=1
                    elif key == "System/Persistence":
                        threatScore += 20
                        scoreDict[key] +=1
                    elif key == "Cryptography":
                        threatScore += 25
                        scoreDict[key] +=1
                    elif key == "Other/Unknown":
                        threatScore += 5
                        scoreDict[key] +=1
                    else:
                        pass
            print(tables)
            tables.clear_rows()
    # Part 2
    command = "./Modules/elfAnalyz.sh"
    os.system(command)

    # Statistics zone
    print(f"{green}->{white} Statistics for: {green}{fileName}{white}")

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
        print(f"\n{cyan}[{red}!{cyan}]{white} This file might be obfuscated or encrypted. Try {green}--packer{white} to scan this file for packers.\n")
        sys.exit(0)

    # score table
    print(f"\n{cyan}[{red}!{cyan}]{white} ATTENTION: There might be false positives in threat scaling system.")

    if threatScore < 100:
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {green}Clean{white}.\n")
    elif threatScore >= 100 and threatScore <= 300:
        print(f"{cyan}[{red}!{cyan}]{white} Attention: Use {green}--vtFile{white} argument to scan that file with VirusTotal. Do not trust that file.")
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {yellow}Suspicious{white}.\n")
    else:
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {red}Potentially Malicious{white}.\n")

# Execute
Analyzer()
