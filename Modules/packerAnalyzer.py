#!/usr/bin/python3

import os
import sys
try:
    from prettytable import PrettyTable
except:
    print("Module: >prettytable< not found.")
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

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Target file
targetFile = str(sys.argv[1])

# File signatures
file_sigs = {'UPX': 'UPX0', 'AsPack': '.aspack', 'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0',
            'UPX!': 'UPX!', 'Confuser v1.9.0.0': 'Confuser v1.9.0.0', 'PEtite': 'petite',
            'MEW': 'MEW', 'MPRESS_1': 'MPRESS1', 'MPRESS_2': 'MPRESS2H'}

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
    print(f"{infoS} Searching strings about common packers...")
    for pack in file_sigs:
        if file_sigs[pack].encode() in data:
            packed += 1
            packTable.add_row([f"{red}{file_sigs[pack]}{white}", f"{red}{pack}{white}"])
    # Printing all
    if packed == 0:
        print(f"{errorS} Nothing found.")
    else:
        print(f"{packTable}\n")

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