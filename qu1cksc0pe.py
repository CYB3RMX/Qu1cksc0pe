#!/usr/bin/env python3

import os,sys,argparse
# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'

args = []
def scope():
    # Category arrays 
    Registry = []
    File = []
    Network = []
    Web = [] 
    Keyboard = []
    Process = []
    Dll = []
    Evasion_Bypassing = []
    SystemPersistence = []
    COMObject = []
    DataRecon_Info_Gathering = []
    Other = []
    
    # Dictionary of Categories
    dictCateg = {
        "Registry": Registry,
        "File": File,
        "Network": Network,
        "Web": Web,
        "Keyboard": Keyboard,
        "Process": Process,
        "Dll": Dll,
        "Evasion_Bypassing": Evasion_Bypassing,
        "SystemPersistence": SystemPersistence,
        "COMObject": COMObject,
        "DataRecon_Info_Gathering": DataRecon_Info_Gathering,
        "Other": Other
    }

    # Argument crating and parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file",required=False,help="Select a suspicious file.")
    parser.add_argument("-s", "--scan",required=False,help="Scan the file.",action="store_true")
    parser.add_argument("--metadata",required=False,help="Get exif/metadata information.",action="store_true")
    parser.add_argument("--vtscan",required=False,help="Scan with VirusTotal api.",action="store_true")
    parser.add_argument("--dll",required=False,help="Look for used DLL files.",action="store_true")
    parser.add_argument("--apk",required=False,help="Analyze apk files.",action="store_true")
    parser.add_argument("--elf",required=False,help="Analyze elf files.",action="store_true")
    parser.add_argument("--key_init",required=False,help="Enter your VirusTotal api key.",action="store_true")
    args = parser.parse_args()
    
    # Keywords for categorized scanning
    regarr = open("categories/Registry.txt", "r").read().split("\n")
    filearr = open("categories/File.txt", "r").read().split("\n")
    netarr = open("categories/Network.txt", "r").read().split("\n")
    webarr = open("categories/Web.txt", "r").read().split("\n")
    keyarr = open("categories/Keyboard.txt", "r").read().split("\n")
    procarr = open("categories/Process.txt").read().split("\n")
    dllarr = open("categories/DLL.txt", "r").read().split("\n")
    debugarr = open("categories/Debugger.txt", "r").read().split("\n")
    systarr = open("categories/Syspersist.txt", "r").read().split("\n")
    comarr = open("categories/COMObject.txt", "r").read().split("\n")
    datarr = open("categories/DataLeak.txt", "r").read().split("\n")
    otharr = open("categories/Other.txt", "r").read().split("\n")
    
    # Keywords for dll scanning
    dllArray = open("categories/DLLlist.txt", "r").read().split("\n")

    regdict={
        "Registry": regarr, "File": filearr, "Network": netarr, "Web": webarr, "Keyboard": keyarr,
        "Process": procarr, "Dll": dllarr, "Evasion_Bypassing": debugarr, "SystemPersistence": systarr,
        "COMObject": comarr, "DataRecon_Info_Gathering": datarr, "Other": otharr
    }
    # Getting all strings from the file
    if args.file:
        command = "strings {} > temp.txt".format(args.file)
        os.system(command)
        allStrings = open("temp.txt", "r").read().split('\n')
    
    if args.scan:
        for key in regdict:
            for el in regdict[key]:
                if el in allStrings:
                    if el != "":
                        dictCateg[key].append(el)
        for key in dictCateg:
            if dictCateg[key] != []:
                print("{}[{}+{}]{} {} Functions".format(cyan,red,cyan,white,key))
                print("+","-"*20,"+")
                for i in dictCateg[key]:
                    if i == "":
                        pass
                    else:
                        print("{}=> {}{}".format(red,white,i))
                print("+","-"*20,"+\n")

    # Configuring the arguments
    if args.metadata:
        print("{}[{}+{}]{} Exif/Metadata information".format(cyan,red,cyan,white))
        command = "exiftool {}".format(args.file)
        print("+","-"*50,"+")
        os.system(command)
        print("+","-"*50,"+")

    if args.vtscan:
        try:
            apik = open(".apikey.txt", "r").read().split("\n")
        except:
            print("{}[{}!{}]{} Use --key_init to enter your key.".format(cyan,red,cyan,white))
            sys.exit(1)
        if apik[0] == '' or apik[0] == None or len(apik[0]) != 64:
            print("{}[{}!{}]{} Please get your API key from -> {}https://www.virustotal.com/{}".format(cyan,red,cyan,white,green,white))
            sys.exit(1)
        else: 
            print("\n{}[{}+{}]{} VirusTotal Scan".format(cyan,red,cyan,white))
            print("+","-"*50,"+")
            command = "python3 VTwrapper.py {} {}".format(apik[0], args.file)
            os.system(command)
            print("+","-"*50,"+")
    if args.apk:
        command = "bash analyzer.sh --apk {}".format(args.file)
        os.system(command)
    if args.elf:
        command = "bash analyzer.sh --elf {}".format(args.file)
        os.system(command)
    if args.key_init:
        apikey = str(input("{}[{}+{}]{} Enter your VirusTotal api key: ".format(cyan,red,cyan,white)))
        command = "echo '{}' > .apikey.txt".format(apikey)
        os.system(command)
        print("{}[{}+{}]{} Your VirusTotal api key saved.".format(cyan,red,cyan,white))
    if args.dll:
        print("{}[{}+{}]{} Used DLL files".format(cyan,red,cyan,white))
        print("+","-"*20,"+")
        for dl in allStrings:
            if dl in dllArray:
                if dl != "":
                    print("{}=> {}{}".format(red,white,dl))
        print("+","-"*20,"+\n")
# Exectuion area
if __name__ == '__main__':
    os.system("bash banner.sh")
    try:
        scope()
        os.system("rm -rf temp.txt")
    except:
        os.system("rm -rf temp.txt")
