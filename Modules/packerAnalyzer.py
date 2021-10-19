#!/usr/bin/python3

import os
import sys
try:
    from prettytable import PrettyTable
except:
    print("Module: >prettytable< not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Module for progressbar
try:
    from tqdm import tqdm
except:
    print("Module: >tqdm< not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
magenta = Fore.LIGHTMAGENTA_EX

# Path variable
sc0pe_path = open(".path_handler", "r").read()

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Target file
targetFile = str(sys.argv[1])

# File signatures
file_sigs = {'UPX': 'UPX0', 'AsPack': '.aspack', 'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0',
            'UPX!': 'UPX!', 'Confuser v1.9.0.0': 'Confuser v1.9.0.0', 'PEtite': 'petite',
            'MEW': 'MEW', 'MPRESS_1': 'MPRESS1', 'MPRESS_2': 'MPRESS2H'}

# YARA rule based scanner
def YaraBased(target_file):
    # Indicator
    yara_match_indicator = 0

    # Gathering all rules
    allRules = os.listdir(f"{sc0pe_path}/Systems/Multiple/Packer_Rules/")

    # Tables!!
    yaraTable = PrettyTable()

    # Parsing rule matches
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{sc0pe_path}/Systems/Multiple/Packer_Rules/{rul}")
            tempmatch = rules.match(target_file)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except:
            continue

    # Printing area
    if yara_matches != []:
        print(f"\n{foundS} Matched Rules for: {green}{target_file}{white}")
        yara_match_indicator += 1
        for rul in yara_matches:
            print(f"{magenta}>>>>{white} {rul}")
            yaraTable.field_names = [f"{green}Offset{white}", f"{green}Matched String/Byte{white}"]
            for mm in rul.strings:
                yaraTable.add_row([f"{hex(mm[0])}", f"{str(mm[2])}"])
            print(f"{yaraTable}\n")
            yaraTable.clear_rows()

    # If there is no match
    if yara_match_indicator == 0:
        print(f"{errorS} Not any rules matched for {green}{target_file}{white}.\n")

# Simple analyzer function
def Analyzer():
    # Getting file's all strings to analyze
    try:
        if os.path.isfile(targetFile) == True:
            data = open(targetFile, "rb").read()
        else:
            pass
    except:
        print(f"{errorS} An error occured while opening the file.")
        sys.exit(1)

    # Creating table
    packTable = PrettyTable()
    packTable.field_names = [f"{green}Extracted Strings{white}", f"{green}Packer Type{white}"]
    # Scanning zone
    packed = 0
    print(f"{infoS} Performing {green}strings{white} based scan...")
    for pack in file_sigs:
        if file_sigs[pack].encode() in data:
            packed += 1
            packTable.add_row([f"{red}{file_sigs[pack]}{white}", f"{red}{pack}{white}"])
    # Printing all
    if packed == 0:
        print(f"{errorS} Nothing found.\n")
    else:
        print(f"{packTable}\n")

    print(f"{infoS} Performing {green}YARA rule{white} based scan...")
    YaraBased(target_file=targetFile)

# Multiple analyzer function
def MultiAnalyzer():
    # Creating summary table
    answers = PrettyTable()
    answers.field_names = [f"{green}File Names{white}", f"{green}Extracted Strings{white}", f"{green}Packer Type{white}"]
    # Handling folders
    if os.path.isdir(targetFile) == True:
        allFiles = os.listdir(targetFile)
        # How many files in that folder?
        filNum = 0
        for _ in allFiles:
            filNum += 1
        # Lets scan them!!
        multipack = 0
        print(f"{infoS} Qu1cksc0pe scans that folder for packed files. Please wait...")
        for tf in tqdm(range(0, filNum), desc="Scanning..."):
            if allFiles[tf] != '':
                scanme = f"{targetFile}/{allFiles[tf]}"
                try:
                    if os.path.isfile(scanme) == True:
                        mulData = open(scanme, "rb").read()
                    else:
                        pass
                except:
                    print(f"{errorS} An error occured while opening the file.")
                    sys.exit(1)

                # Scanning!
                for pack in file_sigs:
                    if file_sigs[pack].encode() in mulData:
                        multipack += 1
                        answers.add_row([f"{red}{allFiles[tf]}{white}", f"{red}{file_sigs[pack]}{white}", f"{red}{pack}{white}"])
        # Print all
        if multipack == 0:
            print(f"\n{errorS} Nothing found.\n")
        else:
            print(f"\n{answers}\n")
# Execute and clean up
if __name__ == '__main__':
    if str(sys.argv[2]) == '--single':
        try:
            Analyzer()
        except:
            print(f"{errorS} Program terminated.")

    elif str(sys.argv[2]) == '--multiscan':
        try:
            MultiAnalyzer()
        except:
            print(f"{errorS} Program terminated.")

    else:
        pass