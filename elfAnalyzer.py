#!/usr/bin/python

import os,sys

# Getting name of the file for statistics
fileName = str(sys.argv[1])

# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'
yellow = '\u001b[93m'

# Wordlists
allStrings = open("temp.txt","r").read().split("\n")
networkz = open("Systems/Linux/Networking.txt","r").read().split("\n")
filez = open("Systems/Linux/Files.txt","r").read().split("\n")
procesz = open("Systems/Linux/Processes.txt","r").read().split("\n")
infogaz = open("Systems/Linux/Infoga.txt","r").read().split("\n")
persisz = open("Systems/Linux/Persistence.txt","r").read().split("\n")
cryptoz = open("Systems/Linux/Crypto.txt","r").read().split("\n")
otherz = open("Systems/Linux/Others.txt","r").read().split("\n")

# Categories
Networking = []
File = []
Process = []
Information_Gathering = []
System_Persistence = []
Cryptography = []
Other = []

# Scores
scoreDict = {
        "Networking": 0,
        "File": 0,
        "Process": 0,
        "Information Gathering":0,
        "System/Persistence":0,
        "Cryptography":0,
        "Other":0
        }

# Dictionary of categories
Categs = {
        "Networking": Networking,
        "File": File,
        "Process": Process,
        "Information Gathering": Information_Gathering,
        "System/Persistence": System_Persistence,
        "Cryptography": Cryptography,
        "Other": Other
        }

# Dictionary of arrays
dictArr = {
        "Networking": networkz,
        "File": filez,
        "Process": procesz,
        "Information Gathering": infogaz,
        "System/Persistence": persisz,
        "Cryptography": cryptoz,
        "Other": otherz
        }

# Defining function
def Analyzer():
    threatScore = 0
    allFuncs = 0
    for key in dictArr:
        for elem in dictArr[key]:
            if elem in allStrings:
                if elem != "":
                    Categs[key].append(elem)
                    allFuncs +=1
    for key in Categs:
        if Categs[key] != []:
            if key == "Information Gathering" or key == "System/Persistence" or key == "Cryptography":
                print("\n{}[{}!{}]__WARNING__[{}!{}]".format(yellow,red,yellow,red,yellow))
            print("{}[{}+{}]{} Functions/Symbols about {}".format(cyan,red,cyan,white,key))
            print("+","-"*30,"+")
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    print("{}=> {}{}".format(red,white,i))
                    # Threat score
                    if key == "Networking":
                        threatScore +=10
                        scoreDict[key] +=1
                    elif key == "File":
                        threatScore += 10
                        scoreDict[key] +=1
                    elif key == "Process":
                        threatScore += 15
                        scoreDict[key] +=1
                    elif key == "Information Gathering":
                        threatScore += 20
                        scoreDict[key] +=1
                    elif key == "System/Persistence":
                        threatScore += 20
                        scoreDict[key] +=1
                    elif key == "Cryptography":
                        threatScore += 25
                        scoreDict[key] +=1
                    elif key == "Other":
                        threatScore += 5
                        scoreDict[key] +=1
                    else:
                        pass
            print("+","-"*30,"+\n")
    # Part 2
    command = "bash elfAnalyz.sh"
    os.system(command)
    
    # Statistics zone
    print("{}->{} Statistics for: {}{}{}".format(green,white,green,fileName,white))
    print("=","+"*30,"=")
    print("{}()>{} All Functions: {}{}".format(red,white,green,allFuncs))
    for key in scoreDict:
        if scoreDict[key] == 0:
            pass
        else:
            print("{}()> {}{}: {}{}{}".format(green,white,key,green,scoreDict[key],white))
    print("=","+"*30,"=")
    if threatScore <= 100:
        print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> clean{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,white))
    elif threatScore <= 200 and threatScore > 100:
        print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> {}suspicious{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,yellow,white))
    else:
        print("\n{}[{}Threat Score{}]{}: {} {}<-{}state{}-> {}malicious{}\n".format(cyan,red,cyan,white,threatScore,green,red,green,red,white))

# Execute
Analyzer()
