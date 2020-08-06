#!/usr/bin/python3

import os,sys

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'
yellow = '\u001b[93m'

# Keywords for categorized scanning
allStrings = open("temp.txt", "r").read().split('\n')
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
    "Dll/Resource Handling": Dll,
    "Evasion/Bypassing": Evasion_Bypassing,
    "System/Persistence": SystemPersistence,
    "COMObject": COMObject,
    "Cryptography": Cryptography,
    "Information Gathering": Info_Gathering,
    "Other": Other
}
    
# score table for checking how many functions in that file
scoreDict = {
    "Registry": 0,
    "File": 0,
    "Networking/Web": 0,
    "Keyboard": 0,
    "Process": 0,
    "Dll/Resource Handling": 0,
    "Evasion/Bypassing": 0,
    "System/Persistence": 0,
    "COMObject": 0,
    "Cryptography": 0,
    "Information Gathering": 0,
    "Other": 0
}

# Accessing categories
regdict={
    "Registry": regarr, "File": filearr, "Networking/Web": netarr, "Keyboard": keyarr,
    "Process": procarr, "Dll/Resource Handling": dllarr, "Evasion/Bypassing": debugarr, "System/Persistence": systarr,
    "COMObject": comarr, "Cryptography": cryptarr,"Information Gathering": datarr, "Other": otharr
}

# Defining function
def Analyzer():
    threatScore = 0
    allFuncs = 0
    
    # categorizing extracted strings
    for key in regdict:
        for el in regdict[key]:
            if el in allStrings:
                if el != "":
                    dictCateg[key].append(el)
                    allFuncs +=1

    # printing categorized strings
    for key in dictCateg:
        if dictCateg[key] != []:
            
            # More important categories
            if key == "Keyboard" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                print("\n{}[{}!{}]__WARNING__[{}!{}]".format(yellow,red,yellow,red,yellow))
            
            # Printing zone
            print("{}[{}+{}]{} Functions/Strings about {}".format(cyan,red,cyan,white,key))
            print("+","-"*35,"+")
            for i in dictCateg[key]:
                if i == "":
                    pass
                else:
                    print("{}=> {}{}".format(red,white,i))

                    # Calculating threat score
                    if key == "Registry":
                        threatScore += 4
                        scoreDict[key] +=1
                    elif key == "File":
                        threatScore += 4
                        scoreDict[key] +=1
                    elif key == "Networking/Web":
                        threatScore += 5
                        scoreDict[key] +=1
                    elif key == "Keyboard":
                        threatScore += 6
                        scoreDict[key] +=1
                    elif key == "Process":
                        threatScore += 5
                        scoreDict[key] +=1
                    elif key == "Dll/Resource Handling":
                        threatScore += 5
                        scoreDict[key] +=1
                    elif key == "Evasion/Bypassing":
                        threatScore += 9
                        scoreDict[key] +=1
                    elif key == "System/Persistence":
                        threatScore += 9
                        scoreDict[key] +=1
                    elif key == "COMObject":
                        threatScore += 4
                        scoreDict[key] +=1
                    elif key == "Cryptography":
                        threatScore += 9
                        scoreDict[key] +=1
                    elif key == "Information Gathering":
                        threatScore += 7
                        scoreDict[key] +=1
                    elif key == "Other":
                        threatScore += 1
                        scoreDict[key] +=1
                    else:
                        pass
            print("+","-"*35,"+\n")

    # printing extracted dll files
    print("{}[{}+{}]{} Extracted DLL Strings".format(cyan,red,cyan,white))
    print("+","-"*20,"+")
    for dl in allStrings:
        if dl in dllArray:
            if dl != "":
                print("{}=> {}{}".format(red,white,dl))
    print("+","-"*20,"+")

    # Statistics zone
    print("\n{}->{} Statistics for: {}{}{}".format(green,white,green,fileName,white))
    print("=","+"*30,"=")
    print("{}()>{} All Functions: {}{}".format(red,white,green,allFuncs))
    if allFuncs < 10:
        print("\n{}[{}!{}]{} This file might be obfuscated or encrypted.\n".format(cyan,red,cyan,white))
        sys.exit(0)

    # printing all function statistics
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            print("{}()> {}{}: {}{}{}".format(green,white,key,green,scoreDict[key],white))
    print("=","+"*30,"=")

    # score table
    print("\n{}[{}!{}]{} ATTENTION: There might be false positives in scores.".format(cyan,red,cyan,white))
    print("+-------------------------+")
    print("|    Threat Score Table   |")
    print("|-------------------------|")
    print("| Point    |  State       |")
    print("|-------------------------|")
    print("| 0-30     | {}Clean{}        |".format(green,white))
    print("| 30-200   | {}Suspicious{}   |".format(yellow,white))
    print("| 200+     | {}Malicious{}    |".format(red,white))
    print("+-------------------------+")

    # score conditions
    if threatScore < 30:
        print("{}[{}Threat Score{}]{}: {}{}\n".format(cyan,red,cyan,white,green,threatScore))
    elif threatScore >= 30 and threatScore <= 200:
        print("{}[{}!{}]{} Attention{}: Use {}--vtFile{} argument to scan that file with VirusTotal. Do not trust that file.".format(cyan,red,cyan,red,white,green,white))
        print("{}[{}Threat Score{}]{}: {}{}\n".format(cyan,red,cyan,white,yellow,threatScore))
    else:
        print("{}[{}Threat Score{}]{}: {}{}\n".format(cyan,red,cyan,white,red,threatScore))

# Execute
Analyzer()
