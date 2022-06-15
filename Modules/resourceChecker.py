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

# Testing rich existence
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

def CheckOS(targFile):
    print(f"{infoS} Analyzing: [bold green]{targFile}[white]")
    fileType = str(pr.magic_file(targFile))
    # Android side
    if "PK" in fileType and "Java archive" in fileType:
        print(f"{infoS} Target OS: [bold green]Android[white]\n")
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
    countTable = Table()
    countTable.add_column("File Type", justify="center")
    countTable.add_column("File Name", justify="center")
    #
    fileTable = Table()
    fileTable.add_column("Interesting Files", justify="center")

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
            for fname in empty[fl]:
                countTable.add_row(f"[bold blink red]{fl}", f"[bold blink red]{fname}")
        elif "data" in fl:
            for fname in empty[fl]:
                countTable.add_row(f"[bold yellow]{fl}", f"[bold yellow]{fname}")
        else:
            for fname in empty[fl]:
                countTable.add_row(str(fl), str(fname))
    print(countTable)

    # Finding .json .bin .dex files
    for fff in apk.get_files():
        if ".json" in fff:
            fileTable.add_row(f"[bold yellow]{fff}")
        elif ".dex" in fff:
            fileTable.add_row(f"[bold blink red]{fff}")
        elif ".bin" in fff:
            fileTable.add_row(f"[bold blink cyan]{fff}")
        else:
            pass
    print(fileTable)

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
            resTable = Table(title=f"* {key} *", title_style="bold green", title_justify="center")
            resTable.add_column("Pattern", justify="center")
            resTable.add_column("File", justify="center")
            for elements in categs[key]:
                resTable.add_row(f"[bold yellow]{elements[0]}", f"[bold cyan]{elements[1]}")
            print(resTable)
            counter += 1
    if counter == 0:
        print("\n[bold white on red]There is no interesting things found!\n")

# Execution zone
targFile = sys.argv[1]
if os.path.isfile(targFile):
    ostype = CheckOS(targFile)
    if ostype == "Android":
        ParseAndroid(targFile)
    else:
        print("\n[bold white on red]Target OS couldn\'t detected!\n")
else:
    print("\n[bold white on red]Target file not found!\n")