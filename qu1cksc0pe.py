#!/usr/bin/env python3

import os,sys,argparse
# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'
yellow = '\u001b[93m'

args = []
def scope():
    # Category arrays 
    Registry = []
    File = []
    Network = []
    Keyboard = []
    Process = []
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
        "Keyboard": Keyboard,
        "Process": Process,
        "Dll": Dll,
        "Evasion/Bypassing": Evasion_Bypassing,
        "System/Persistence": SystemPersistence,
        "COMObject": COMObject,
        "Cryptography": Cryptography,
        "Information Gathering": Info_Gathering,
        "Other": Other
    }
    
    # Scores
    scoreDict = {
            "Registry": 0,
            "File": 0,
            "Networking/Web": 0,
            "Keyboard": 0,
            "Process": 0,
            "Dll": 0,
            "Evasion/Bypassing": 0,
            "System/Persistence": 0,
            "COMObject": 0,
            "Cryptography": 0,
            "Information Gathering": 0,
            "Other": 0
            }

    # Argument crating and parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("--file",required=False,help="Select a suspicious file.")
    parser.add_argument("--windows",required=False,help="Analyze Windows files.",action="store_true")
    parser.add_argument("--linux",required=False,help="Analyze Linux files.",action="store_true")
    parser.add_argument("--vtFile",required=False,help="Scan your file with VirusTotal api.",action="store_true")
    parser.add_argument("--vtUrl",required=False,help="Scan your URL with VirusTotal api.",action="store_true")
    parser.add_argument("--metadata",required=False,help="Get exif/metadata information.",action="store_true")
    parser.add_argument("--url",required=False,help="Extract URLs from file.",action="store_true")
    parser.add_argument("--packer",required=False,help="Check if your file is packed with common packers.",action="store_true")
    parser.add_argument("--key_init",required=False,help="Enter your VirusTotal api key.",action="store_true")
    args = parser.parse_args()
    
    # Keywords for categorized scanning
    regarr = open("Systems/Windows/Registry.txt", "r").read().split("\n")
    filearr = open("Systems/Windows/File.txt", "r").read().split("\n")
    netarr = open("Systems/Windows/Network.txt", "r").read().split("\n")
    keyarr = open("Systems/Windows/Keyboard.txt", "r").read().split("\n")
    procarr = open("Systems/Windows/Process.txt").read().split("\n")
    dllarr = open("Systems/Windows/DLL.txt", "r").read().split("\n")
    debugarr = open("Systems/Windows/Debugger.txt", "r").read().split("\n")
    systarr = open("Systems/Windows/Syspersist.txt", "r").read().split("\n")
    comarr = open("Systems/Windows/COMObject.txt", "r").read().split("\n")
    cryptarr = open("Systems/Windows/Crypto.txt","r").read().split("\n")
    datarr = open("Systems/Windows/DataLeak.txt", "r").read().split("\n")
    otharr = open("Systems/Windows/Other.txt", "r").read().split("\n")
    dllArray = open("Systems/Windows/DLLlist.txt", "r").read().split("\n")

    regdict={
        "Registry": regarr, "File": filearr, "Networking/Web": netarr, "Keyboard": keyarr,
        "Process": procarr, "Dll": dllarr, "Evasion/Bypassing": debugarr, "System/Persistence": systarr,
        "COMObject": comarr, "Cryptography": cryptarr,"Information Gathering": datarr, "Other": otharr
    }
    # Getting all strings from the file
    if args.file:
        command = "strings {} > temp.txt".format(args.file)
        os.system(command)
        allStrings = open("temp.txt", "r").read().split('\n')
    
    if args.windows:
        threatScore = 0
        allFuncs = 0
        for key in regdict:
            for el in regdict[key]:
                if el in allStrings:
                    if el != "":
                        dictCateg[key].append(el)
                        allFuncs +=1
        for key in dictCateg:
            if dictCateg[key] != []:
                if key == "Keyboard" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                    print("\n{}[{}!{}]__WARNING__[{}!{}]".format(yellow,red,yellow,red,yellow))
                print("{}[{}+{}]{} {} Functions".format(cyan,red,cyan,white,key))
                print("+","-"*30,"+")
                for i in dictCateg[key]:
                    if i == "":
                        pass
                    else:
                        print("{}=> {}{}".format(red,white,i))
                        # Threat score
                        if key == "Registry":
                            threatScore +=10
                            scoreDict[key] +=1
                        elif key == "File":
                            threatScore += 10
                            scoreDict[key] +=1
                        elif key == "Networking/Web":
                            threatScore += 15
                            scoreDict[key] +=1
                        elif key == "Keyboard":
                            threatScore += 20
                            scoreDict[key] +=1
                        elif key == "Process":
                            threatScore += 15
                            scoreDict[key] +=1
                        elif key == "Dll":
                            threatScore += 15
                            scoreDict[key] +=1
                        elif key == "Evasion/Bypassing":
                            threatScore += 25
                            scoreDict[key] +=1
                        elif key == "System/Persistence":
                            threatScore += 20
                            scoreDict[key] +=1
                        elif key == "COMObject":
                            threatScore += 10
                            scoreDict[key] +=1
                        elif key == "Cryptography":
                            threatScore += 25
                            scoreDict[key] +=1
                        elif key == "Information Gathering":
                            threatScore += 20
                            scoreDict[key] +=1
                        elif key == "Other":
                            threatScore += 5
                            scoreDict[key] +=1
                        else:
                            pass
                print("+","-"*30,"+\n")
        print("{}[{}+{}]{} Used DLL files".format(cyan,red,cyan,white))
        print("+","-"*20,"+")
        for dl in allStrings:
            if dl in dllArray:
                if dl != "":
                    print("{}=> {}{}".format(red,white,dl))
        print("+","-"*20,"+")

        # Statistics zone
        print("\n{}->{} Statistics for: {}{}{}".format(green,white,green,args.file,white))
        print("=","+"*30,"=")
        print("{}()>{} All Functions: {}{}".format(red,white,green,allFuncs))
        for key in scoreDict:
            if scoreDict[key] == 0:
                pass
            else:
                print("{}()> {}{}: {}{}{}".format(green,white,key,green,scoreDict[key],white))
        print("=","+"*30,"=")
        if threatScore < 100:
            print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> clean{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,white))
        elif threatScore <= 500 and threatScore > 100:
            print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> {}suspicious{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,yellow,white))
        else:
            print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> {}malicious{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,red,white))

    # Configuring the arguments
    if args.metadata:
        print("{}[{}+{}]{} Exif/Metadata information".format(cyan,red,cyan,white))
        command = "exiftool {}".format(args.file)
        print("+","-"*50,"+")
        os.system(command)
        print("+","-"*50,"+")

    if args.vtFile:
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
            command = "python3 VTwrapper.py {} --vtFile {}".format(apik[0],args.file)
            os.system(command)
            print("+","-"*50,"+")
    if args.vtUrl:
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
            command = "python3 VTwrapper.py {} --vtUrl".format(apik[0])
            os.system(command)
            print("+","-"*50,"+")
    if args.packer:
        command = "bash packerDetect.sh {}".format(args.file)
        os.system(command)
    if args.linux:
        command = "readelf -a {} > elves.txt".format(args.file)
        os.system(command)
        command = "python3 elfAnalyzer.py {}".format(args.file)
        os.system(command)
    if args.url:
        command = "bash urlCatcher.sh {}".format(args.file)
        os.system(command)
    if args.key_init:
        apikey = str(input("{}[{}+{}]{} Enter your VirusTotal API key: ".format(cyan,red,cyan,white)))
        command = "echo '{}' > .apikey.txt".format(apikey)
        os.system(command)
        print("{}[{}+{}]{} Your VirusTotal API key saved.".format(cyan,red,cyan,white))

# Exectuion area
os.system("bash .startUp.sh")
try:
    scope()
    os.system("rm -rf temp.txt elves.txt")
except:
    os.system("rm -rf temp.txt elves.txt")
