#!/usr/bin/python3

import os
import sys
import configparser

try:
    from rich.table import Table
    from rich.console import Console
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

#--------------------------------------------- Getting name of the file for statistics
fileName = str(sys.argv[1])

#--------------------------------------------- Rich console
r_console = Console()

#--------------------------------------------- Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

#--------------------------------------------- Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

#--------------------------------------------- Gathering all function imports from binary
allStrings = []
try:
    binaryfile = pf.PE(fileName)
    for imps in binaryfile.DIRECTORY_ENTRY_IMPORT:
        try:
            for im in imps.imports:
                allStrings.append([im.name.decode("ascii"), hex(im.address)])
        except:
            continue
except:
    r_console.print("[blink bold white on red]Couldn\'t locate import entries. Quitting...")
    sys.exit(1)

#--------------------------------------------------------------------- Keywords for categorized scanning
regarr = open(f"{sc0pe_path}/Systems/Windows/Registry.txt", "r").read().split("\n")
filearr = open(f"{sc0pe_path}/Systems/Windows/File.txt", "r").read().split("\n")
netarr = open(f"{sc0pe_path}/Systems/Windows/Network.txt", "r").read().split("\n")
keyarr = open(f"{sc0pe_path}/Systems/Windows/Keyboard.txt", "r").read().split("\n")
procarr = open(f"{sc0pe_path}/Systems/Windows/Process.txt", "r").read().split("\n")
memoarr = open(f"{sc0pe_path}/Systems/Windows/Memoryz.txt", "r").read().split("\n")
dllarr = open(f"{sc0pe_path}/Systems/Windows/Resources.txt", "r").read().split("\n")
debugarr = open(f"{sc0pe_path}/Systems/Windows/Debugger.txt", "r").read().split("\n")
systarr = open(f"{sc0pe_path}/Systems/Windows/Syspersist.txt", "r").read().split("\n")
comarr = open(f"{sc0pe_path}/Systems/Windows/COMObject.txt", "r").read().split("\n")
cryptarr = open(f"{sc0pe_path}/Systems/Windows/Crypto.txt", "r").read().split("\n")
datarr = open(f"{sc0pe_path}/Systems/Windows/DataLeak.txt", "r").read().split("\n")
otharr = open(f"{sc0pe_path}/Systems/Windows/Other.txt", "r").read().split("\n")

#------------------------------------------- Category arrays
Registry = []
File = []
Network = []
Keyboard = []
Process = []
Memory = []
Dll = []
Evasion_Bypassing = []
SystemPersistence = []
COMObject = []
Cryptography = []
Info_Gathering = []
Other = []

#--------------------------------------------- Dictionary of Categories
dictCateg = {
    "Registry": Registry,
    "File": File,
    "Networking/Web": Network,
    "Keyboard/Keylogging": Keyboard,
    "Process": Process,
    "Memory Management": Memory,
    "Dll/Resource Handling": Dll,
    "Evasion/Bypassing": Evasion_Bypassing,
    "System/Persistence": SystemPersistence,
    "COMObject": COMObject,
    "Cryptography": Cryptography,
    "Information Gathering": Info_Gathering,
    "Other/Unknown": Other
}

#---------------------------------------- Score table for checking how many functions in that file
scoreDict = {
    "Registry": 0,
    "File": 0,
    "Networking/Web": 0,
    "Keyboard/Keylogging": 0,
    "Process": 0,
    "Memory Management": 0,
    "Dll/Resource Handling": 0,
    "Evasion/Bypassing": 0,
    "System/Persistence": 0,
    "COMObject": 0,
    "Cryptography": 0,
    "Information Gathering": 0,
    "Other/Unknown": 0
}

#---------------------------------------------------- Accessing categories
regdict = {
    "Registry": regarr, "File": filearr,
    "Networking/Web": netarr, "Keyboard/Keylogging": keyarr,
    "Process": procarr, "Memory Management": memoarr,
    "Dll/Resource Handling": dllarr, "Evasion/Bypassing": debugarr,
    "System/Persistence": systarr,
    "COMObject": comarr, "Cryptography": cryptarr,
    "Information Gathering": datarr, "Other/Unknown": otharr
}

#------------------------------------ Yara rule matcher
def WindowsYara(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Windows/windows.conf")
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
            r_console.print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
            yaraTable.add_column("Offset", style="bold green", justify="center")
            yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
            for mm in rul.strings:
                yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
            r_console.print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        r_console.print(f"[blink bold white on red]Not any rules matched for {target_file}")

#------------------------------------ Defining function
def Analyzer():
    # Creating tables
    allFuncs = 0

    # categorizing extracted strings
    for win_api in allStrings:
        for key in regdict:
            if win_api[0] in regdict[key]:
                if win_api[0] != "":
                    dictCateg[key].append(win_api)
                    allFuncs += 1

    # printing categorized strings
    import_indicator = 0
    for key in dictCateg:
        if dictCateg[key] != []:

            # More important categories
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
            else:
                tables = Table()

            # Printing zone
            tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
            tables.add_column("Address", justify="center")
            for func in dictCateg[key]:
                if func[0] == "":
                    pass
                else:
                    tables.add_row(f"[bold red]{func[0]}", f"[bold red]{func[1]}")
                    import_indicator += 1

                    # Logging for summary table
                    if key == "Registry":
                        scoreDict[key] += 1
                    elif key == "File":
                        scoreDict[key] += 1
                    elif key == "Networking/Web":
                        scoreDict[key] += 1
                    elif key == "Keyboard/Keylogging":
                        scoreDict[key] += 1
                    elif key == "Process":
                        scoreDict[key] += 1
                    elif key == "Memory Management":
                        scoreDict[key] += 1
                    elif key == "Dll/Resource Handling":
                        scoreDict[key] += 1
                    elif key == "Evasion/Bypassing":
                        scoreDict[key] += 1
                    elif key == "System/Persistence":
                        scoreDict[key] += 1
                    elif key == "COMObject":
                        scoreDict[key] += 1
                    elif key == "Cryptography":
                        scoreDict[key] += 1
                    elif key == "Information Gathering":
                        scoreDict[key] += 1
                    elif key == "Other/Unknown":
                        scoreDict[key] += 1
                    else:
                        pass
            r_console.print(tables)

    # If there is no function imported in target executable
    if import_indicator == 0:
        r_console.print("[blink bold white on red]There is no function/API imports found.")
        r_console.print("[magenta]>>[white] Try [bold green][i]--packer[/i] [white]or [bold green][i]--lang[/i] [white]to see additional info about target file.\n")

    # gathering extracted dll files
    try:
        dllTable = Table()
        dllTable.add_column("Linked DLL Files", style="bold green")
        for items in binaryfile.DIRECTORY_ENTRY_IMPORT:
            dlStr = str(items.dll.decode())
            dllTable.add_row(f"{dlStr}", style="bold red")
        r_console.print(dllTable)
    except:
        pass

    # Yara rule match
    print(f"\n{infoS} Performing YARA rule matching...")
    WindowsYara(target_file=fileName)

    # Gathering information about sections
    peStatistics = Table(title="* Informations About Sections *", title_style="bold italic cyan", title_justify="center")
    peStatistics.add_column("Section Name", justify="center")
    peStatistics.add_column("Virtual Size", justify="center")
    peStatistics.add_column("Virtual Address", justify="center")
    peStatistics.add_column("Size Of Raw Data", justify="center")
    peStatistics.add_column("Pointer to Raw Data", justify="center")
    peStatistics.add_column("Entropy", justify="center")
    pe = pf.PE(fileName)

    # Parsing timedatestamp data
    mydict = pe.dump_dict()
    tempstr = mydict["FILE_HEADER"]["TimeDateStamp"]["Value"][11:].replace("[", "")
    datestamp = tempstr.replace("]", "")

    # Parsing sections
    for sect in pe.sections:
        if sect.get_entropy() >= 7:
            peStatistics.add_row(
                str(sect.Name.decode().rstrip('\x00')),
                f"{hex(sect.Misc_VirtualSize)}",
                f"{hex(sect.VirtualAddress)}",
                f"{hex(sect.SizeOfRawData)}",
                f"{hex(sect.PointerToRawData)}",
                f"[bold red]{sect.get_entropy()} [blink][i]Possible obfuscation!![/i][/blink]"
            )
        else:
            peStatistics.add_row(
                str(sect.Name.decode().rstrip('\x00')),
                f"{hex(sect.Misc_VirtualSize)}",
                f"{hex(sect.VirtualAddress)}",
                f"{hex(sect.SizeOfRawData)}",
                f"{hex(sect.PointerToRawData)}",
                str(sect.get_entropy())
            )
    r_console.print(peStatistics)

    # Statistics zone
    r_console.print(f"\n[bold green]-> [white]Statistics for: [bold green][i]{fileName}[/i]")
    r_console.print(f"[bold magenta]>>[white] Time Date Stamp: [bold green][i]{datestamp}[/i]")

    # printing all function statistics
    statistics = Table()
    statistics.add_column("Categories", justify="center")
    statistics.add_column("Number of Functions or Strings", justify="center")
    statistics.add_row("[bold green][i]All Functions[/i]", f"[bold green]{allFuncs}")
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                statistics.add_row(f"[blink bold yellow]{key}", f"[blink bold red]{scoreDict[key]}")
            else:
                statistics.add_row(key, str(scoreDict[key]))
    r_console.print(statistics)

    # Warning about obfuscated file
    if allFuncs < 20:
        r_console.print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
        r_console.print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
        sys.exit(0)

# Execute
Analyzer()
