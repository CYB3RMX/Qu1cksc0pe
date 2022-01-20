#!/usr/bin/env python3

import os
import re
import sys

# Testing pyaxmlparser existence
try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Testing prettytable existence
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Testing colorama existence
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

def CheckOS(targFile):
    print(f"{infoS} Analyzing: {green}{targFile}{white}")
    fileType = str(pr.magic_file(targFile))
    # Android side
    if "PK" in fileType and "Java archive" in fileType:
        print(f"{infoS} Target OS: {green}Android{white}\n")
        return "Android"
    else:
        return None

def ParseAndroid(target):
    # Categories
    categs = {
        "Presence of Tor": [], "URLs": [], "IP Addresses": []
    }

    # Wordlists for analysis
    dictionary = {
        "Presence of Tor": [
            "obfs4",
            "iat-mode=",
            "meek_lite",
            "found_existing_tor_process",
            "newnym"
        ],
        "URLs": [
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        ],
        "IP Addresses": [
            r'[0-9]+(?:\.[0-9]+){3}:[0-9]+',
            "localhost"
        ]
    }

    # Tables!!
    resTable = PrettyTable()
    countTable = PrettyTable()
    fileTable = PrettyTable()
    resTable.field_names = ["Pattern", "File"]
    countTable.field_names = ["File Type", "Count"]
    fileTable.field_names = ["Interesting Files"]

    # Lets begin!
    print(f"{infoS} Parsing file contents...\n")
    apk = pyaxmlparser.APK(target)

    # Try to find something juicy
    empty = {}
    ftypes = apk.get_files_types()
    for typ in ftypes:
        if ftypes[typ] not in empty.keys():
            empty.update({ftypes[typ]: []})
    for fl in ftypes:
        empty[ftypes[fl]].append(fl)

    # Count file types
    for fl in empty:
        if "image" in fl: # Just get rid of them
            pass
        elif "Dalvik" in fl or "C++ source" in fl or "C source" in fl or "ELF" in fl or "Bourne-Again shell" in fl or "executable" in fl or "JAR" in fl: # Worth to write on the table
            countTable.add_row([f"{red}{fl}{white}", f"{red}{len(empty[fl])}{white}"])
        elif "data" in fl:
            countTable.add_row([f"{yellow}{fl}{white}", f"{yellow}{len(empty[fl])}{white}"])
        else:
            countTable.add_row([fl, len(empty[fl])])
    print(f"{countTable}\n")

    # Finding .json .bin .dex files
    for fff in apk.get_files():
        if ".json" in fff:
            fileTable.add_row([f"{yellow}{fff}{white}"])
        elif ".dex" in fff:
            fileTable.add_row([f"{red}{fff}{white}"])
        elif ".bin" in fff:
            fileTable.add_row([f"{cyan}{fff}{white}"])
        else:
            pass
    print(f"{fileTable}\n")

    # Analyzing all files
    for key in empty:
        try:
            for kfile in empty[key]:
                fcontent = apk.get_file(kfile)
                for ddd in dictionary:
                    for regex in dictionary[ddd]:
                        matches = re.findall(regex, fcontent.decode())
                        if matches != []:
                            categs[ddd].append([matches[0], kfile])
        except:
            continue

    # Output
    counter = 0
    for key in categs:
        if categs[key] != []:
            print(f"{red}>>>{white} Data Type: {green}{key}{white}")
            for elements in categs[key]:
                resTable.add_row([f"{yellow}{elements[0]}{white}", f"{cyan}{elements[1]}{white}"])
            print(f"{resTable}\n")
            counter += 1
            resTable.clear_rows()
    if counter == 0:
        print(f"{errorS} There is no interesting things found.")

# Execution zone
targFile = sys.argv[1]
if os.path.isfile(targFile):
    ostype = CheckOS(targFile)
    if ostype == "Android":
        ParseAndroid(targFile)
    else:
        print(f"{errorS} Target OS couldn\'t detected.")
else:
    print(f"{errorS} Target file not found.")