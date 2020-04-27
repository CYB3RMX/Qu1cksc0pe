#!/usr/bin/python

import os

# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'

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
    allFuncs = 0
    for key in dictArr:
        for elem in dictArr[key]:
            if elem in allStrings:
                if elem != "":
                    Categs[key].append(elem)
                    allFuncs +=1
    for key in Categs:
        myFuncs = 0
        if Categs[key] != []:
            print("{}[{}+{}]{} Functions/Symbols about {}".format(cyan,red,cyan,white,key))
            print("+","-"*30,"+")
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    print("{}=> {}{}".format(red,white,i))
                    myFuncs +=1
            print("+","-"*30,"+")
            print("{}->{} Statistics for {}: {}{}/{}\n\n".format(green,white,key,green,myFuncs,allFuncs))

# Execute
Analyzer()
