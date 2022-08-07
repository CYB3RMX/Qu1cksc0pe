#!/usr/bin/python3

import re
import os
import sys
import shutil
import configparser
from subprocess import Popen, PIPE

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
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

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Recursive file explorer
def FileExp(targetFolder):
    if os.path.exists(targetFolder):
        fnames = []
        for root, d_names, f_names in os.walk(targetFolder):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames

def DocumentYara(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Multiple/multiple.conf")
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
                        if matched not in yara_matches:
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
            for mm in rul.strings:
                yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
            print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        print(f"[blink bold white on red]Not any rules matched for {target_file}")

# Perform analysis against embedded binaries
def BinaryAnalysis(targetFile):
    print(f"{infoS} Analyzing: [bold red]{targetFile.replace('.sc0pe_Doc/', '')}")

    # Check if file is an JAR file (for .jar based attacks)
    bin_data = open(targetFile, "rb").read()
    if len(re.findall(r"JAR", str(bin_data))) > 1 or (len(re.findall(r".class", str(bin_data))) >= 2 and len(re.findall(r"META-INF", str(bin_data))) >= 1):
        print(f"[bold magenta]>>>[white] Binary Type: [bold green]JAR[white]")

# Function for perform file structure analysis
def Structure(targetFile):
    # We need to unzip the file and check for interesting files
    print(f"\n{infoS} Analyzing file structure...")
    unz = Popen(["unzip", targetFile, "-d", ".sc0pe_Doc"], stdout=PIPE, stderr=PIPE)
    unz.wait()
    if unz.returncode != 0:
        print(f"{errorS} Error: Unable to unzip file.")
    else:
        fconts = FileExp(".sc0pe_Doc/")
        bins = []
        # Parsing the files
        docTable = Table(title="* Document Structure *", title_style="bold italic cyan", title_justify="center")
        docTable.add_column("[bold green]File Name", justify="center")
        for df in fconts:
            if ".bin" in df:
                docTable.add_row(f"[bold red]{df.replace('.sc0pe_Doc/', '')}")
                bins.append(df)
            else:
                docTable.add_row(df.replace(".sc0pe_Doc/", ""))
        print(docTable)

        # Perform analysis against binaries
        print(f"\n{infoS} Analyzing binaries...")
        for b in bins:
            BinaryAnalysis(b)

# Macro parser function
def MacroParser(macroList):
    answerTable = Table()
    answerTable.add_column("[bold green]Threat Levels", justify="center")
    answerTable.add_column("[bold green]Macros", justify="center")
    answerTable.add_column("[bold green]Descriptions", justify="center")

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

# A function that finds VBA Macros
def MacroHunter(targetFile):
    print(f"\n{infoS} Looking for Macros...")
    try:
        fileData = open(targetFile, "rb").read()
        vbaparser = VBA_Parser(targetFile, fileData)
        macroList = list(vbaparser.analyze_macros())
        macro_state_vba = 0
        macro_state_xlm = 0
        # Checking vba macros
        if vbaparser.contains_vba_macros == True:
            print(f"[bold red]>>>[white] VBA MACRO: [bold green]Found.")
            if vbaparser.detect_vba_stomping() == True:
                print(f"[bold red]>>>[white] VBA Stomping: [bold green]Found.")

            else:
                print(f"[bold red]>>>[white] VBA Stomping: [bold red]Not found.")
            MacroParser(macroList)
            macro_state_vba += 1
        else:
            print(f"[bold red]>>>[white] VBA MACRO: [bold red]Not found.\n")

        # Checking for xlm macros
        if vbaparser.contains_xlm_macros == True:
            print(f"\n[bold red]>>>[white] XLM MACRO: [bold green]Found.")
            MacroParser(macroList)
            macro_state_xlm += 1
        else:
            print(f"\n[bold red]>>>[white] XLM MACRO: [bold red]Not found.")

        # If there is macro we can extract it!
        if macro_state_vba != 0 or macro_state_xlm != 0:
            choice = str(input("\n>>> Do you want to extract macros [Y/n]?: "))
            if choice == "Y" or choice == "y":
                print(f"{infoS} Attempting to extraction...\n")
                if macro_state_vba != 0:
                    for mac in vbaparser.extract_all_macros():
                        for xxx in mac:
                            print(xxx.strip("\r\n"))
                else:
                    for mac in vbaparser.xlm_macros:
                        print(mac)
                print(f"\n{infoS} Extraction completed.")

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

    # Perform file structure analysis
    Structure(targetFile)

    # Perform Yara scan
    print(f"\n{infoS} Performing YARA rule matching...")
    DocumentYara(targetFile)

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

# Execution area
try:
    BasicInfoGa(targetFile)
except:
    print(f"{errorS} An error occured while analyzing that file.")
    sys.exit(1)
