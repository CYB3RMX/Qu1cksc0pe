#!/usr/bin/python3

import sys

# Checking for puremagic
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< not found.")
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

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Target file
targetFile = str(sys.argv[1])

# A function that finds VBA Macros
def MacroHunter(targetFile):
    answerTable = Table()
    answerTable.add_column("[bold green]Threat Levels", justify="center")
    answerTable.add_column("[bold green]Macros", justify="center")
    answerTable.add_column("[bold green]Descriptions", justify="center")

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
                        answerTable.add_row(f"[bold yellow]{macroList[fi][0]}", f"{macroList[fi][1]}", f"{sanitized}")
                    elif "(option --decode to see all)" in macroList[fi][2]:
                        sanitized = f"{macroList[fi][2]}".replace("(option --decode to see all)", "")
                        answerTable.add_row(f"[bold yellow]{macroList[fi][0]}", f"{macroList[fi][1]}", f"{sanitized}")
                    else:
                        answerTable.add_row(f"[bold yellow]{macroList[fi][0]}", f"{macroList[fi][1]}", f"{macroList[fi][2]}")
                elif macroList[fi][0] == 'IOC':
                    answerTable.add_row(f"[bold magenta]{macroList[fi][0]}", f"{macroList[fi][1]}", f"{macroList[fi][2]}")
                elif macroList[fi][0] == 'AutoExec':
                    answerTable.add_row(f"[bold red]{macroList[fi][0]}", f"{macroList[fi][1]}", f"{macroList[fi][2]}")
                else:
                    answerTable.add_row(f"{macroList[fi][0]}", f"{macroList[fi][1]}", f"{macroList[fi][2]}")
            print(answerTable)
        else:
            print(f"{errorS} Not any VBA macros found.")
    except:
        print(f"{errorS} An error occured while parsing that file for macro scan.")

# Gathering basic informations
def BasicInfoGa(targetFile):
    # Check for ole structures
    if isOleFile(targetFile) == True:
        print(f"{infoS} Ole File: [bold green]True[white]")
    else:
        print(f"{infoS} Ole File: [bold red]False[white]")

    # Check for encryption
    if is_encrypted(targetFile) == True:
        print(f"{infoS} Encrypted: [bold green]True[white]")
    else:
        print(f"{infoS} Encrypted: [bold red]False[white]")
    
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
                    print(f"{infoS} VBA Macros: [bold green]Found[white]")
                    MacroHunter(targetFile)
                else:
                    print(f"{infoS} VBA Macros: [bold red]Not Found[white]")
    else:
        MacroHunter(targetFile)

# A function that handles file types, extensions etc.
def MagicParser(targetFile):
    # Defining table
    resTable = Table()
    resTable.add_column("File Extension", justify="center")
    resTable.add_column("Names", justify="center")
    resTable.add_column("Byte Matches", justify="center")
    resTable.add_column("Confidence", justify="center")

    # Magic byte parsing
    resCounter = 0
    resourceList = list(pr.magic_file(targetFile))
    for res in range(0, len(resourceList)):
        extrExt = str(resourceList[res].extension)
        extrNam = str(resourceList[res].name)
        extrByt = str(resourceList[res].byte_match)
        if resourceList[res].confidence >= 0.8:
            resCounter += 1
            if extrExt == '':
                resTable.add_row("[bold red]No Extension", f"[bold red]{extrNam}", f"[bold red]{extrByt}", f"[bold red]{resourceList[res].confidence}")
            else:
                resTable.add_row(f"[bold red]{extrExt}", f"[bold red]{extrNam}", f"[bold red]{extrByt}", f"[bold red]{resourceList[res].confidence}")
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
