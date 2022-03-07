#!/usr/bin/python3

import sys

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Getting filename for statistics
fileName = str(sys.argv[1])

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Keywords ;)
allStrings = open("temp.txt", "r").read().split('\n')
loadCommands = open(f"{sc0pe_path}/Systems/OSX/LoadCommands.txt", "r").read().split('\n')
fileHeaders = open(f"{sc0pe_path}/Systems/OSX/Headers.txt", "r").read().split('\n')
sharedLibs = open(f"{sc0pe_path}/Systems/OSX/SharedLibs.txt", "r").read().split('\n')
memoryz = open(f"{sc0pe_path}/Systems/OSX/Memory.txt", "r").read().split('\n')
procesz = open(f"{sc0pe_path}/Systems/OSX/Process.txt", "r").read().split('\n')
infogaz = open(f"{sc0pe_path}/Systems/OSX/Infoga.txt", "r").read().split('\n')
cryptoz = open(f"{sc0pe_path}/Systems/OSX/Cryptography.txt", "r").read().split('\n')
otherz = open(f"{sc0pe_path}/Systems/OSX/Other.txt", "r").read().split('\n')

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
    lcom = Table()
    fhead = Table()
    shlib = Table()

    # Preparing tables
    lcom.add_column("[bold green]Load Commands", justify="center")
    fhead.add_column("[bold green]File Headers", justify="center")
    shlib.add_column("[bold green]Shared Libraries", justify="center")

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
            fhead.add_row(i)
        print(fhead)

    if shLibs != []:
        for i in shLibs:
            shlib.add_row(i)
        print(shlib)

    if lCommands != []:
        for i in lCommands:
            lcom.add_row(i)
        print(lcom)

# Defining categorized scanning
def Categorized():
    # Necessary vars
    allFuncs = 0

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
                tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
            else:
                tables = Table()

            # Printing area
            tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
            for i in dictCateg[key]:
                if i == "":
                    pass
                else:
                    tables.add_row(f"[bold red]{i}")
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

    # Statistics zone
    statistics = Table()
    print(f"\n[bold green]->[white] Statistics for: [bold green][i]{fileName}[/i]")
    statistics.add_column("Categories", justify="center")
    statistics.add_column("Number of Functions or Strings", justify="center")
    statistics.add_row("[bold green][i]All Functions[/i]", f"[bold green]{allFuncs}")
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "Cryptography" or key == "Information Gathering":
                statistics.add_row(f"[blink bold yellow]{key}", f"[blink bold red]{scoreDict[key]}")
            else:
                statistics.add_row(key, str(scoreDict[key]))
    print(statistics)

    # Warning about obfuscated file
    if allFuncs < 10:
        print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
        print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
        sys.exit(0)

# Execution
Analyzer()
Categorized()