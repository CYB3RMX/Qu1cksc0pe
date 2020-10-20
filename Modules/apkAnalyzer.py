#!/usr/bin/python3

import json
import sys
import os
import threading
import queue

# Module handling
try:
    from androguard.core.bytecodes.apk import APK
except:
    print("Error: >androguard< module not found.")
    sys.exit(1)

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

try:
    import spacy
except:
    print("Error: >spacy< module not found.")
    sys.exit(1)

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

# necessary variables
danger = 0
normal = 0

# Gathering all strings from file
allStrings = open("temp.txt", "r").read().split('\n')

 # Lets get all suspicious strings
susStrings = open("Systems/Android/suspicious.txt", "r").read().split('\n')

# Permission analyzer
def Analyzer(parsed):
    global danger
    global normal
    statistics = PrettyTable()

    # Getting blacklisted permissions
    with open("Systems/Android/perms.json", "r") as f:
        permissions = json.load(f)

    apkPerms = parsed.get_permissions()
    permArr = []

    # Getting target APK file's permissions
    for p in range(len(permissions)):
        permArr.append(permissions[p]["permission"])

    # Parsing permissions
    statistics.field_names = [f"{green}Permissions{white}", f"{green}State{white}"]
    for pp in apkPerms:
        if pp.split(".")[-1] in permArr:
            statistics.add_row([f"{pp}", f"{red}Risky{white}"])
            danger += 1
        else:
            statistics.add_row([f"{pp}", f"{yellow}Info{white}"])
            normal += 1

    # If there is no permission:
    if danger == 0 and normal == 0:
        print(f"{errorS} Not any permissions found.")
    else:
        print(statistics)

# Analyzing more deeply
def DeepScan(parsed):
    # Getting features
    featStat = PrettyTable()
    featStat.field_names = [f"{green}Features{white}"]
    features = parsed.get_features()
    if features != []:
        for ff in features:
            featStat.add_row([ff])
        print(featStat)
    else:
        pass

    # Activities
    activeStat = PrettyTable()
    activeStat.field_names = [f"{green}Activities{white}"]
    actos = parsed.get_activities()
    if actos != []:
        for aa in actos:
            activeStat.add_row([aa])
        print(activeStat)
    else:
        pass

    # Services
    servStat = PrettyTable()
    servStat.field_names = [f"{green}Services{white}"]
    servv = parsed.get_services()
    if servv != []:
        for ss in servv:
            servStat.add_row([ss])
        print(servStat)
    else:
        pass

    # Receivers
    recvStat = PrettyTable()
    recvStat.field_names = [f"{green}Receivers{white}"]
    receive = parsed.get_receivers()
    if receive != []:
        for rr in receive:
            recvStat.add_row([rr])
        print(recvStat)
    else:
        pass

    # Providers
    provStat = PrettyTable()
    provStat.field_names = [f"{green}Providers{white}"]
    provids = parsed.get_providers()
    if provids != []:
        for pp in provids:
            provStat.add_row([pp])
        print(provStat)
    else:
        pass

# Handling language package
def LangNotFound():
   print(f"{errorS} Language package not found. Without this u wont be able to analyze strings.")
   choose = str(input("=> Should I install it for you [Y/n]?: "))
   if choose == 'Y' or choose == 'y':
      try:
         os.system("python3 -m spacy download en")
         print(f"{infoS} Language package downloaded.")
         sys.exit(0)
      except:
         print(f"{errorS} Program encountered an error.")
         sys.exit(1)
   else:
      print(f"{errorS} Without language package this module is wont work.")
      sys.exit(1)

# APK string analyzer with NLP
def Detailed(q):
    # Our sample string to analyze
    while not q.empty():
        targetString = q.get()
        try:
            nlp = spacy.load("en")
            sample = nlp(targetString)
        except:
            LangNotFound()

        # Lets analyze!!
        for apkstr in allStrings:
            # Parsing and calculating
            testme = nlp(apkstr)
            if testme.similarity(sample) >= 0.6:
                print(f"{cyan}({magenta}{targetString}{cyan})->{white} {apkstr}")

# Execution
if __name__ == '__main__':
    try:
        # Getting and parsing target APK
        targetAPK = str(sys.argv[1])
        parsed = APK(targetAPK)

        # Permissions side
        Analyzer(parsed)

        # Deep scanner
        DeepScan(parsed)

        # Strings side
        print(f"{infoS} Analyzing extracted strings from that file. Please wait...\n")

        # Queue object

        q = queue.Queue()
        
        #Thread Number
        
        threadNumber = 0 

        for sus in susStrings:
            q.put(sus)
            threadNumber += 1

        ts = []
        for i in range(0,threadNumber):
            try:
                t = threading.Thread(target=Detailed, args=q)
                ts.append(t)
                t.start()
            except Exception as e:
                print(e)
        for t in ts:
            t.join()
        
    except:
        print(f"{errorS} An error occured.")