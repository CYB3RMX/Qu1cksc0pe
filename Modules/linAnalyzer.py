#!/usr/bin/python3

import os
import sys
try:
    from rich.table import Table
    from rich.console import Console
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Rich console
r_console = Console()

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

    for key in dictArr:
        for elem in dictArr[key]:
            if elem in allStrings:
                if elem != "":
                    Categs[key].append(elem)
                    allFuncs +=1
    for key in Categs:
        if Categs[key] != []:
            if key == "Information Gathering" or key == "System/Persistence" or key == "Cryptography":
                tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
            else:
                tables = Table()

            # Printing zone
            tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    tables.add_row(f"[bold red]{i}")
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
            r_console.print(tables)

    # Gathering sections and segments
    secTable = Table()
    segTable = Table()
    secTable.add_column("[bold green]Sections")
    segTable.add_column("[bold green]Segments")

    # Sections
    sec_indicator = 0
    for se1 in sections:
        if se1 in allThings:
            if se1 != "":
                secTable.add_row(f"[bold red]{se1}")
                sec_indicator += 1
    if sec_indicator != 0:
        r_console.print(secTable)
    
    # Segments
    seg_indicator = 0
    for se2 in segments:
        if se2 in allThings:
            if se2 != "":
                segTable.add_row(f"[bold red]{se2}")
                seg_indicator += 1
    if seg_indicator != 0:
        r_console.print(segTable)

    # Statistics zone
    r_console.print(f"\n[bold green]->[white] Statistics for: [bold green][i]{fileName}[/i]")

    # Printing zone
    statistics = Table()
    statistics.add_column("Categories", justify="center")
    statistics.add_column("Number of Functions or Strings", justify="center")
    statistics.add_row("[bold green][i]All Functions[/i]", f"[bold green]{allFuncs}")
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                statistics.add_row(f"[blink bold yellow]{key}", f"[blink bold red]{scoreDict[key]}")
            else:
                statistics.add_row(key, str(scoreDict[key]))
    r_console.print(statistics)

    # Warning about obfuscated file
    if allFuncs < 10:
        r_console.print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
        r_console.print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
        sys.exit(0)

# Execute
try:
    Analyzer()
    if os.path.exists("Modules/elves.txt"):
        os.remove("Modules/elves.txt")
except:
    pass
