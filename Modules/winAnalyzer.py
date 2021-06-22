#!/usr/bin/python3

import os
import sys
import json
import configparser
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
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
    from capstone import *
    from capstone.x86 import *
except:
    print("Error: >capstone< module not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

#--------------------------------------------- Getting name of the file for statistics
fileName = str(sys.argv[1])

#--------------------------------------------- Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

#--------------------------------------------- Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

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
    print(f"{errorS} Couldn\'t locate import entries. Quitting...")
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

#--------------------------------------- A function that locates entry point of base code address
def GetMainCode(sections, base_of_code):
    '''
    Parameter 1: Sections of a program
    Parameter 2: Address of the first instruction of the program
    '''
    addresses = []
    
    # Extracting all sections from the target executable
    for section in sections:
        addresses.append(section.VirtualAddress)
    
    # Locating and parsing address of base_of_code
    if base_of_code in addresses:
        return sections[addresses.index(base_of_code)]
    else:
        addresses.append(base_of_code)
        addresses.sort()
        if addresses.index(base_of_code) != 0:
            return sections[addresses.index(base_of_code)-1]
        else:
            return None

#------------------------------------- A function that disassembles binary's base code address and locates possible function calls
def Disassembler(executable):
    fcalls = 0

    assemblyTable_func_calls = PrettyTable()
    assemblyTable_func_calls.field_names = ["Address", "Mnemonic", "Operands"]
    # Gathering address of main code section
    main_code = GetMainCode(executable.sections, executable.OPTIONAL_HEADER.BaseOfCode)
    
    # Configurating disassembler options
    mode = Cs(CS_ARCH_X86, CS_MODE_32)
    mode.detail = True
    last_address = 0
    last_size = 0
    
    # Specifying beginning and ending addresses
    begin = main_code.PointerToRawData
    end = begin+main_code.SizeOfRawData
    
    # Disassembling and locating possible function calls
    while True:
        data = executable.get_memory_mapped_image()[begin:end]
        for ind in mode.disasm(data, begin):
            if "call" in ind.mnemonic or "jmp" in ind.mnemonic:
                fcalls += 1
                assemblyTable_func_calls.add_row([hex(ind.address), ind.mnemonic, ind.op_str])
            last_address = int(ind.address)
            last_size = int(ind.size)
        begin = max(int(last_address), begin)+last_size+1
        if begin >= end:
            break
    print(f"{red}>!>{white} Assembly output is saved into '{green}assembly_output.txt{white}'.\n")
    savestat = open(f"assembly_output.txt", "w")
    savestat.writelines(str(assemblyTable_func_calls))
    return fcalls

#------------------------------------ Yara rule matcher
def WindowsYara(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Windows/windows.conf")
    rule_path = conf["Rule_PATH"]["rulepath"]
    finalpath = f"{sc0pe_path}/{rule_path}"
    allRules = os.listdir(finalpath)

    # Summary table
    yaraTable = PrettyTable()

    # This array for holding and parsing easily matched rules
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{finalpath}{rul}")
            tempmatch = rules.match(target_file)
            if tempmatch != []:
                yara_matches.append(tempmatch[0])
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

    if yara_match_indicator == 0:
        print(f"{errorS} Not any rules matched for {green}{target_file}{white}.\n")

#------------------------------------ Defining function
def Analyzer():
    # Creating tables
    allFuncs = 0
    tables = PrettyTable()
    peStatistics = PrettyTable()
    dllTable = PrettyTable()
    resTable = PrettyTable()
    statistics = PrettyTable()

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
                print(f"\n{yellow}[{red}!{yellow}]__WARNING__[{red}!{yellow}]{white}")

            # Printing zone
            tables.field_names = [f"Functions or Strings about {green}{key}{white}", "Address"]
            for func in dictCateg[key]:
                if func[0] == "":
                    pass
                else:
                    tables.add_row([f"{red}{func[0]}{white}", f"{red}{func[1]}{white}"])
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
            print(tables)
            tables.clear_rows()

    # If there is no function imported in target executable
    if import_indicator == 0:
        print(f"{errorS} There is no function/API imports found.")
        print(f"{magenta}>>{white} Try '{green}--packer{white}' or '{green}--lang{white}' to see additional info about target file.\n")

    # gathering extracted dll files
    try:
        dllTable.field_names = [f"Linked {green}DLL{white} Files"]
        for items in binaryfile.DIRECTORY_ENTRY_IMPORT:
            dlStr = str(items.dll.decode())
            dllTable.add_row([f"{red}{dlStr}{white}"])
        print(dllTable)
    except:
        pass

    # Yara rule match
    print(f"\n{infoS} Performing YARA rule matching...")
    WindowsYara(target_file=fileName)

    # MWCFG zone
    print(f"\n{infoS} Searching for configs from {green}mwcfg.info{white}...")
    try:
        os.system(f"curl -s -X POST --upload-file {fileName} https://mwcfg.info/ > mwcfg.json")
        if os.path.exists("mwcfg.json"):
            mwcfg_data = open("mwcfg.json")
            mwcfg = json.loads(mwcfg_data.read())
            if mwcfg["configs"] != []:
                print(mwcfg["configs"])
            else:
                print(f"{errorS} There is no data for {green}{fileName}{white}")
            os.remove("mwcfg.json")
        else:
            print(f"{errorS} An error occured while querying the file. Skipping...")
    except:
        print(f"{errorS} An error occured while querying the file. Skipping...")
        os.remove("mwcfg.json")

    # Resource scanner zone
    print(f"\n{infoS} Performing magic number analysis...")
    resCounter = 0
    resTable.field_names = [f"File Extensions", "Names", "Byte Matches", "Confidence"]
    resourceList = list(pr.magic_file(fileName))
    for res in range(0, len(resourceList)):
        extrExt = str(resourceList[res].extension)
        extrNam = str(resourceList[res].name)
        extrByt = str(resourceList[res].byte_match)
        if resourceList[res].confidence >= 0.4:
            resCounter += 1
            if extrExt == '':
                resTable.add_row([f"{red}No Extension{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
            else:
                resTable.add_row([f"{red}{extrExt}{white}", f"{red}{extrNam}{white}", f"{red}{extrByt}{white}", f"{red}{resourceList[res].confidence}{white}"])
    if len(resourceList) != 0:
        print(resTable)

    # Assembly and pe structure analysis zone
    print(f"\n{infoS} Performing PE file structure and assembly code analysis...\n")
    
    # Gathering information about sections
    peStatistics.field_names = ["Section Name", "Virtual Size", "Virtual Address", "Size Of Raw Data", "Pointer to Raw Data", "Entropy"]

    pe = pf.PE(fileName)

    # Parsing timedatestamp data
    mydict = pe.dump_dict()
    tempstr = mydict["FILE_HEADER"]["TimeDateStamp"]["Value"][11:].replace("[", "")
    datestamp = tempstr.replace("]", "")

    # Parsing sections
    for sect in pe.sections:
        if sect.get_entropy() >= 7:
            peStatistics.add_row([sect.Name.decode().rstrip('\x00'), hex(sect.Misc_VirtualSize), hex(sect.VirtualAddress), hex(sect.SizeOfRawData), hex(sect.PointerToRawData), f"{red}{sect.get_entropy()}{white} (Possible obfuscation!!)"])
        else:
            peStatistics.add_row([sect.Name.decode().rstrip('\x00'), hex(sect.Misc_VirtualSize), hex(sect.VirtualAddress), hex(sect.SizeOfRawData), hex(sect.PointerToRawData), sect.get_entropy()])
    assembly = Disassembler(pe)
    print(f"{magenta}>>{white} Time Date Stamp: {green}{datestamp}{white}")
    print(f"{magenta}>>{white} Number of possible function calls in base of code: {green}{assembly}{white}")
    print(peStatistics)

    # Statistics zone
    print(f"\n{green}->{white} Statistics for: {green}{fileName}{white}")

    # printing all function statistics
    statistics.field_names = ["Categories", "Number of Functions or Strings"]
    statistics.add_row([f"{green}All Functions{white}", f"{green}{allFuncs}{white}"])
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                statistics.add_row([f"{yellow}{key}{white}", f"{red}{scoreDict[key]}{white}"])
            else:
                statistics.add_row([f"{white}{key}", f"{scoreDict[key]}{white}"])
    print(statistics)

    # Warning about obfuscated file
    if allFuncs < 20:
        print(f"\n{errorS} This file might be obfuscated or encrypted. Try {green}--packer{white} to scan this file for packers.")
        print(f"{errorS} You can also use {green}--hashscan{white} to scan this file.\n")
        sys.exit(0)

# Execute
Analyzer()
