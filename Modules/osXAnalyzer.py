#!/usr/bin/python3

import os
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Colors
white = '\u001b[0m'
red = '\u001b[1;91m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'
cyan = '\u001b[1;96m'

# Keywords ;)
allStrings = open("temp.txt", "r").read().split('\n')
loadCommands = open("Systems/OSX/LoadCommands.txt", "r").read().split('\n')
fileHeaders = open("Systems/OSX/Headers.txt", "r").read().split('\n')
sharedLibs = open("Systems/OSX/SharedLibs.txt", "r").read().split('\n')
funcStrings = open("Systems/OSX/Functions.txt", "r").read().split('\n')

# Arrayz
lCommands = []
fHeaders = []
shLibs = []
fStrings = []

# Defining function
def Analyzer():
    # Creating tables
    lcom = PrettyTable()
    fhead = PrettyTable()
    shlib = PrettyTable()
    fstri = PrettyTable()

    # Preparing tables
    lcom.field_names = [f"{green}Load Commands{white}"]
    fhead.field_names = [f"{green}File Headers{white}"]
    shlib.field_names = [f"{green}Shared Libraries{white}"]
    fstri.field_names = [f"{green}Extracted Function Strings{white}"]

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

    # Analyzing strings for valid functions
    for ff in funcStrings:
        if ff in allStrings:
            if ff != "":
                fStrings.append(ff)

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

    if fStrings != []:
        for i in fStrings:
            fstri.add_row([i])
        print(fstri)

# Execution
Analyzer()
