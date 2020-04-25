#!/usr/bin/python

import os

# Colors
red = '\u001b[91m'
cyan = '\u001b[96m'
white = '\u001b[0m'
green = '\u001b[92m'

# Wordlists
allStrings = open("temp.txt","r").read().split("\n")
sectionz = open("Systems/Linux/sections.txt","r").read().split("\n")
segmentz = open("Systems/Linux/segments.txt","r").read().split("\n")
networkz = open("Systems/Linux/Networking.txt","r").read().split("\n")
filez = open("Systems/Linux/Files.txt","r").read().split("\n")
procesz = open("Systems/Linux/Processes.txt","r").read().split("\n")
infogaz = open("Systems/Linux/Infoga.txt","r").read().split("\n")
otherz = open("Systems/Linux/Others.txt","r").read().split("\n")

# Categories
Networking = []
File = []
Process = []
Information_Gathering = []
Other = []

# Dictionary of categories
Categs = {
        "Networking": Networking,
        "File": File,
        "Process": Process,
        "Information_Gathering": Information_Gathering,
        "Other": Other
        }

# Dictionary of arrays
dictArr = {
        "Networking": networkz,
        "File": filez,
        "Process": procesz,
        "Information_Gathering": infogaz,
        "Other": otherz
        }

# Defining function
def Analyzer():
    for key in dictArr:
        for elem in dictArr[key]:
            if elem in allStrings:
                if elem != "":
                    Categs[key].append(elem)
    for key in Categs:
        if Categs[key] != []:
            print("{}[{}+{}]{} Functions/Symbols about {}".format(cyan,red,cyan,white,key))
            print("+","-"*30,"+")
            for i in Categs[key]:
                if i == "":
                    pass
                else:
                    print("{}=> {}{}".format(red,white,i))
            print("+","-"*30,"+\n")

def LookForOthers():
    tempArr = []
    print("{}[{}+{}]{} Sections".format(cyan,red,cyan,white))
    print("+","-"*30,"+")
    for elem in sectionz:
        if elem != "":
            try:
                com = "cat elves.txt | grep -o {} &>/dev/null".format(elem)
                os.system(com)
                com = 'if [ $? -eq 0 ];then echo -en "{}=> {}{}\n"; fi'.format(red,white,elem)
                os.system(com)
            except:
                continue
    print("+","-"*30,"+")

    del tempArr[:]
    print("\n{}[{}+{}]{} Segments".format(cyan,red,cyan,white))
    print("+","-"*30,"+")
    for elem in segmentz:
        if elem != "":
            try:
                com = "cat elves.txt | grep -o {} &>/dev/null".format(elem)
                os.system(com)
                com = 'if [ $? -eq 0 ];then echo -en "{}=> {}{}\n"; fi'.format(red,white,elem)
                os.system(com)
            except:
                continue
    print("+","-"*30,"+")

# Execute
Analyzer()
LookForOthers()
