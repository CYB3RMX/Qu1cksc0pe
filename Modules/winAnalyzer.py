#!/usr/bin/python3

import os
import sys
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

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Keywords for categorized scanning
allStrings = open("temp.txt", "r").read().split('\n')
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

# Category arrays
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

# Dictionary of Categories
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

# score table for checking how many functions in that file
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

# Accessing categories
regdict = {
    "Registry": regarr, "File": filearr,
    "Networking/Web": netarr, "Keyboard/Keylogging": keyarr,
    "Process": procarr, "Memory Management": memoarr,
    "Dll/Resource Handling": dllarr, "Evasion/Bypassing": debugarr,
    "System/Persistence": systarr,
    "COMObject": comarr, "Cryptography": cryptarr,
    "Information Gathering": datarr, "Other/Unknown": otharr
}

# A function that locates entry point of base code address
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

# A function that disassembles binary's base code address and locates possible function calls
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

# Defining function
def Analyzer():
    # Creating tables
    allFuncs = 0
    tables = PrettyTable()
    peStatistics = PrettyTable()
    dllTable = PrettyTable()
    resTable = PrettyTable()
    statistics = PrettyTable()

    # categorizing extracted strings
    for key in regdict:
        for el in regdict[key]:
            if el in allStrings:
                if el != "":
                    dictCateg[key].append(el)
                    allFuncs += 1

    # printing categorized strings
    for key in dictCateg:
        if dictCateg[key] != []:

            # More important categories
            if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                print(f"\n{yellow}[{red}!{yellow}]__WARNING__[{red}!{yellow}]{white}")

            # Printing zone
            tables.field_names = [f"Functions or Strings about {green}{key}{white}"]
            for i in dictCateg[key]:
                if i == "":
                    pass
                else:
                    tables.add_row([f"{red}{i}{white}"])

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

    # gathering extracted dll files
    try:
        dllTable.field_names = [f"Linked {green}DLL{white} Files"]
        for items in pe.DIRECTORY_ENTRY_IMPORT:
            dlStr = str(items.dll.decode())
            dllTable.add_row([f"{red}{dlStr}{white}"])
        print(dllTable)
    except:
        pass

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
        if sect.get_entropy() >= 6:
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
