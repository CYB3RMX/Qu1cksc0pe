#!/usr/bin/python3

import os
import sys

from .utils import err_exit

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

# Module for progressbar
try:
    from tqdm import tqdm
except:
    err_exit("Module: >tqdm< not found.")

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Path variable
sc0pe_path = open(".path_handler", "r").read()

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Target file
targetFile = sys.argv[2]

# File signatures
file_sigs = {'UPX': 'UPX0', 'AsPack': '.aspack', 'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0',
            'UPX!': 'UPX!', 'Confuser v1.9.0.0': 'Confuser v1.9.0.0', 'PEtite': 'petite',
            'MPRESS_1': 'MPRESS1', 'MPRESS_2': 'MPRESS2H'}

# YARA rule based scanner
def YaraBased(target_file):
    # Indicator
    yara_match_indicator = 0

    # Gathering all rules
    allRules = os.listdir(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}Packer_Rules{path_seperator}")

    # Parsing rule matches
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}Packer_Rules{path_seperator}{rul}")
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
            yaraTable.add_column("[bold green]Offset", justify="center")
            yaraTable.add_column("[bold green]Matched String/Byte", justify="center")
            for matched_pattern in rul.strings:
                yaraTable.add_row(f"{hex(matched_pattern.instances[0].offset)}", f"{str(matched_pattern.instances[0].matched_data)}")
            print(yaraTable)
            print(" ")

    # If there is no match
    if yara_match_indicator == 0:
        print(f"[bold white on red]There is no rules matched for {target_file}")

# Simple analyzer function
def Analyzer():
    # Getting file's all strings to analyze
    try:
        if os.path.isfile(targetFile) == True:
            data = open(targetFile, "rb").read()
        else:
            pass
    except:
        err_exit("[bold white on red]An error occured while opening the file.")

    # Creating table
    packTable = Table()
    packTable.add_column("[bold green]Extracted Strings", justify="center")
    packTable.add_column("[bold green]Packer Type", justify="center")

    # Scanning zone
    packed = 0
    print("[bold magenta]>>>[white] Performing [bold green][blink]strings[/blink] [white]based scan...")
    for pack in file_sigs:
        if file_sigs[pack].encode() in data:
            packed += 1
            packTable.add_row(f"[bold red]{file_sigs[pack]}", f"[bold red]{pack}")
    # Printing all
    if packed == 0:
        print("\n[bold white on red]Nothing found.\n")
    else:
        print(packTable)

    print("\n[bold magenta]>>>[white] Performing [bold green][blink]YARA Rule[/blink] [white]based scan...")
    YaraBased(target_file=targetFile)

# Multiple analyzer function
def MultiAnalyzer():
    # Creating summary table
    answers = Table()
    answers.add_column("[bold green]File Names", justify="center")
    answers.add_column("[bold green]Extracted Strings", justify="center")
    answers.add_column("[bold green]Packer Type", justify="center")

    # Handling folders
    if os.path.isdir(targetFile) == True:
        allFiles = os.listdir(targetFile)
        # How many files in that folder?
        filNum = 0
        for _ in allFiles:
            filNum += 1
        # Lets scan them!!
        multipack = 0
        print("[bold red]>>>[white] Qu1cksc0pe scans everything under that folder for malicious things. [bold][blink]Please wait...[/blink]")
        for tf in tqdm(range(0, filNum), desc="Scanning..."):
            if allFiles[tf] != '':
                scanme = f"{targetFile}{path_seperator}{allFiles[tf]}"
                try:
                    if os.path.isfile(scanme) == True:
                        mulData = open(scanme, "rb").read()
                    else:
                        pass
                except:
                    err_exit("[bold white on red]An error occured while opening the file.")

                # Scanning!
                for pack in file_sigs:
                    if file_sigs[pack].encode() in mulData:
                        multipack += 1
                        answers.add_row(f"[bold red]{allFiles[tf]}", f"[bold red]{file_sigs[pack]}", f"[bold red]{pack}")
        # Print all
        if multipack == 0:
            print("\n[bold white on red]Nothing found.\n")
        else:
            print(answers)
            print(" ")

# Execute and clean up
if __name__ == '__main__':
    if str(sys.argv[1]) == '--single':
        try:
            Analyzer()
        except:
            print("\n[bold white on red]Program terminated!\n")
    elif str(sys.argv[1]) == '--multiscan':
        try:
            MultiAnalyzer()
        except:
            print("\n[bold white on red]Program terminated!\n")
    else:
        pass