#!/usr/bin/python3

import os
import sys
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

# Getting filename for statistics
fileName = str(sys.argv[1])

# Colors
white = Style.RESET_ALL
red = Fore.LIGHTRED_EX
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
cyan = Fore.LIGHTCYAN_EX

# Keywords ;)
allStrings = open("temp.txt", "r").read().split('\n')
loadCommands = open("Systems/OSX/LoadCommands.txt", "r").read().split('\n')
fileHeaders = open("Systems/OSX/Headers.txt", "r").read().split('\n')
sharedLibs = open("Systems/OSX/SharedLibs.txt", "r").read().split('\n')
memoryz = open("Systems/OSX/Memory.txt", "r").read().split('\n')
procesz = open("Systems/OSX/Process.txt", "r").read().split('\n')
infogaz = open("Systems/OSX/Infoga.txt", "r").read().split('\n')
cryptoz = open("Systems/OSX/Cryptography.txt", "r").read().split('\n')
otherz = open("Systems/OSX/Other.txt", "r").read().split('\n')

# Arrayz
lCommands = []
fHeaders = []
shLibs = []

# Arrays for categorized scanning
Memory = []
Process = []
Infogath = []
Cryptography = []
Other = []

# Dictionaries for categories
dictCateg = {
    "Memory Management": Memory,
    "Process": Process,
    "Information Gathering": Infogath,
    "Cryptography": Cryptography,
    "Other/Unknown": Other
}

# Accessing categories
regdict = {
    "Memory Management": memoryz,
    "Process": procesz,
    "Information Gathering": infogaz,
    "Cryptography": cryptoz,
    "Other/Unknown": otherz
}

# Dictionary for statistics
scoreDict = {
    "Memory Management": 0,
    "Process": 0,
    "Information Gathering": 0,
    "Cryptography": 0,
    "Other/Unknown": 0
}

# Defining function
def Analyzer():
    # Creating tables
    lcom = PrettyTable()
    fhead = PrettyTable()
    shlib = PrettyTable()

    # Preparing tables
    lcom.field_names = [f"{green}Load Commands{white}"]
    fhead.field_names = [f"{green}File Headers{white}"]
    shlib.field_names = [f"{green}Shared Libraries{white}"]

    # Analyzing strings for load commands
    for lc in loadCommands:
        if lc in allStrings:
            if lc != "":
                lCommands.append(lc)

    # Analyzing strings for file headers
    for fh in fileHeaders:
        if fh in allStrings:
            if fh != "":
                fHeaders.append(fh)

    # Analyzing strings for shared libs
    for sl in sharedLibs:
        if sl in allStrings:
            if sl != "":
                shLibs.append(sl)

    # Print all
    if fHeaders != []:
        for i in fHeaders:
            fhead.add_row([i])
        print(fhead)

    if shLibs != []:
        for i in shLibs:
            shlib.add_row([i])
        print(shlib)

    if lCommands != []:
        for i in lCommands:
            lcom.add_row(i)
        print(lcom)

# Defining categorized scanning
def Categorized():
    # Necessary vars
    allFuncs = 0
    tables = PrettyTable()
    statistics = PrettyTable()

    # Categorizing extracted strings
    for key in regdict:
        for el in regdict[key]:
            if el in allStrings:
                if el != "":
                    dictCateg[key].append(el)
                    allFuncs += 1

    # Printing zone
    for key in dictCateg:
        if dictCateg[key] != []:

            # More important categories
            if key == "Cryptography" or key == "Information Gathering":
                print(f"\n{yellow}[{red}!{yellow}]__WARNING__[{red}!{yellow}]{white}")

            # Printing area
            tables.field_names = [f"Functions or Strings about {green}{key}{white}"]
            for i in dictCateg[key]:
                if i == "":
                    pass
                else:
                    tables.add_row([f"{red}{i}{white}"])
                    if key == "Memory Management":
                        scoreDict[key] += 1
                    elif key == "Process":
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        scoreDict[key] += 1
                    else:
                        pass
            print(tables)
            tables.clear_rows()

    # Statistics zone
    print(f"\n{green}->{white} Statistics for: {green}{fileName}{white}")
    statistics.field_names = ["Categories", "Number of Functions/Strings"]
    statistics.add_row([f"{green}All Functions{white}", f"{green}{allFuncs}{white}"])
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "Cryptography" or key == "Information Gathering":
                statistics.add_row([f"{yellow}{key}{white}", f"{red}{scoreDict[key]}{white}"])
            else:
                statistics.add_row([f"{white}{key}", f"{scoreDict[key]}{white}"])
    print(statistics)

# Execution
Analyzer()
Categorized()