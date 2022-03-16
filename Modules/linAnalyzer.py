#!/usr/bin/python3

import os
import sys
import json
import configparser
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import lief
except:
    print("Error: >lief< module not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Elf parsing
binary = lief.parse(fileName)

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Wordlists
networkz = open(f"{sc0pe_path}/Systems/Linux/Networking.txt", "r").read().split("\n")
filez = open(f"{sc0pe_path}/Systems/Linux/Files.txt", "r").read().split("\n")
procesz = open(f"{sc0pe_path}/Systems/Linux/Processes.txt", "r").read().split("\n")
memoryz = open(f"{sc0pe_path}/Systems/Linux/Memory.txt", "r").read().split("\n")
infogaz = open(f"{sc0pe_path}/Systems/Linux/Infoga.txt", "r").read().split("\n")
persisz = open(f"{sc0pe_path}/Systems/Linux/Persistence.txt", "r").read().split("\n")
cryptoz = open(f"{sc0pe_path}/Systems/Linux/Crypto.txt", "r").read().split("\n")
debuggz = open(f"{sc0pe_path}/Systems/Linux/Debug.txt", "r").read().split("\n")
otherz = open(f"{sc0pe_path}/Systems/Linux/Others.txt", "r").read().split("\n")

# Categories
Networking = []
File = []
Process = []
Memory = []
Information_Gathering = []
System_Persistence = []
Cryptography = []
Evasion = []
Other = []

# Report structure
linrep = {
    "filename": "",
    "machine_type": "",
    "binary_entrypoint": "",
    "number_of_sections": 0,
    "number_of_segments": 0,
    "categories": {},
    "sections": [],
    "segments": [],
    "libraries": [],
    "matched_rules": [],
    "security": {"NX": False, "PIE": False}
}

# Scores
scoreDict = {
    "Networking": 0,
    "File": 0,
    "Process": 0,
    "Memory Management": 0,
    "Information Gathering": 0,
    "System/Persistence": 0,
    "Cryptography": 0,
    "Evasion": 0,
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
    "Evasion": Evasion,
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
    "Evasion": debuggz,
    "Other/Unknown": otherz
}

# Get imported symbols from binary
allStrings = []
for ssym in binary.symbols:
    allStrings.append(ssym.name)

# Binary security checker
def SecCheck():
    chksec = Table(title_justify="center", title="* Security *", title_style="bold italic cyan")
    chksec.add_column("[bold yellow]NX", justify="center")
    chksec.add_column("[bold yellow]PIE", justify="center")
    # Checking NX
    if binary.has_nx is True:
        nxstr = "[bold red]True"
    else:
        nxstr = "[bold green]False"

    # Checking PIE
    if binary.is_pie is True:
        pistr = "[bold green]True"
    else:
        pistr = "[bold red]False"
    chksec.add_row(nxstr, pistr)
    print(chksec)
    linrep["security"]["NX"] = binary.has_nx
    linrep["security"]["PIE"] = binary.is_pie

def LinuxYara(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Linux/linux.conf")
    rule_path = conf["Rule_PATH"]["rulepath"]
    finalpath = f"{sc0pe_path}/{rule_path}"
    allRules = os.listdir(finalpath)

    # This array for holding and parsing easily matched rules
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{finalpath}{rul}")
            tempmatch = rules.match(target_file)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except:
            continue

    # Printing area
    if yara_matches != []:
        yara_match_indicator += 1
        for rul in yara_matches:
            yaraTable = Table()
            print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
            yaraTable.add_column("Offset", style="bold green", justify="center")
            yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
            linrep["matched_rules"].append(str(rul))
            for mm in rul.strings:
                yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
            print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        print(f"[blink bold white on red]Not any rules matched for {target_file}")

# General information
def GeneralInformation():
    print(f"{infoS} General Informations about [bold green]{fileName}")
    print(f"[bold red]>>>>[white] Machine Type: [bold green]{binary.header.machine_type.name}")
    print(f"[bold red]>>>>[white] Binary Entrypoint: [bold green]{hex(binary.entrypoint)}")
    print(f"[bold red]>>>>[white] Number of Sections: [bold green]{len(binary.sections)}")
    print(f"[bold red]>>>>[white] Number of Segments: [bold green]{len(binary.segments)}")
    linrep["machine_type"] = binary.header.machine_type.name
    linrep["binary_entrypoint"] = str(hex(binary.entrypoint))
    linrep["number_of_sections"] = len(binary.sections)
    linrep["number_of_segments"] = len(binary.segments)
    SecCheck()

# Gathering sections
def SectionParser():
    secTable = Table(title="* Informations About Sections *", title_justify="center", title_style="bold italic cyan")
    secTable.add_column("[bold green]Section Names", justify="center")
    secTable.add_column("[bold green]Size(bytes)", justify="center")
    secTable.add_column("[bold green]Offset", justify="center")
    secTable.add_column("[bold green]Virtual Address", justify="center")
    secTable.add_column("[bold green]Entropy", justify="center")
    for sec in binary.sections:
        if sec.name != "" and sec.name != " ":
            secTable.add_row(
                f"[bold red]{sec.name}", 
                str(sec.size),
                str(hex(sec.offset)),
                str(hex(sec.virtual_address)),
                str(sec.entropy)
            )
            linrep["sections"].append(
                {
                    "name": sec.name,
                    "size": sec.size,
                    "offset": str(hex(sec.offset)),
                    "virtual_address": str(hex(sec.virtual_address)),
                    "entropy": str(sec.entropy)
                }
            )
    print(secTable)

# Gathering segments
def SegmentParser():
    segTable = Table(title="* Informations About Segments *", title_justify="center", title_style="bold italic cyan")
    segTable.add_column("[bold green]Segments", justify="center")
    segTable.add_column("[bold green]Contained Sections", justify="center")
    for seg in binary.segments:
        ssec = []
        if seg.type.name != "" and seg.type.name != " ":
            for sgs in seg.sections:
                ssec.append(sgs.name)
            segTable.add_row(f"[bold red]{seg.type.name}", str(ssec))
            linrep["segments"].append(seg.type.name)
    print(segTable)

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
            if key == "Information Gathering" or key == "System/Persistence" or key == "Cryptography" or key == "Evasion":
                tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
            else:
                tables = Table()

            # Printing zone
            tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
            linrep["categories"].update({key: []})
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    tables.add_row(f"[bold red]{i}")
                    linrep["categories"][key].append(i)
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

    # Perform YARA scan
    print(f"\n{infoS} Performing YARA rule matching...")
    LinuxYara(fileName)

    # Get sections
    SectionParser()

    # Segments
    SegmentParser()

    # Used libraries
    libs = Table()
    libs.add_column("[bold green]Libraries", justify="center")
    if len(binary.libraries) > 0:
        for x in binary.libraries:
            libs.add_row(f"[bold red]{x}")
            linrep["libraries"].append(x)
        print(libs)

    # Statistics zone
    print(f"\n[bold green]->[white] Statistics for: [bold green][i]{fileName}[/i]")
    linrep["filename"] = fileName

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
    print(statistics)

    # Warning about obfuscated file
    if allFuncs < 10:
        print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
        print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
        sys.exit(0)

    # Print reports
    if sys.argv[2] == "True":
        with open("sc0pe_linux_report.json", "w") as rp_file:
            json.dump(linrep, rp_file, indent=4)
        print("\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_linux_report.json\n")

# Execute
try:
    GeneralInformation()
    Analyzer()
except:
    pass
