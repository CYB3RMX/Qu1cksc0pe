#!/usr/bin/python3

import json
import sys
import os
import threading
import queue
import warnings

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

# Gathering apkid tools output
apkid_output = open("apkid.json", "r")
data = json.load(apkid_output)

# Lets get all suspicious strings
susStrings = open("Systems/Android/suspicious.txt", "r").read().split('\n')

# Ignoring spacy's warnings
warnings.filterwarnings("ignore")

# Queue
global q
q = queue.Queue()

# Function for parsing apkid tool's output
def ApkidParser(apkid_output):
    # Fetching and parsing anti virtualization
    for index in range(0, 2):
        if "anti_vm" in data["files"][index]["matches"].keys():
            antivm = PrettyTable()
            antivm.field_names = [f"{green}Anti Virtualization Codes{white}"]
            if data["files"][index]["matches"]["anti_vm"] != []:
                for avm in data["files"][index]["matches"]["anti_vm"]:
                    antivm.add_row([avm])
                print(antivm)
            else:
                pass
            break
        else:
            pass
    
    # Fetching and parsing anti debug codes
    for index in range(0, 2):
        if "anti_debug" in data["files"][index]["matches"].keys():
            antidbg = PrettyTable()
            antidbg.field_names = [f"{green}Anti Debug Codes{white}"]
            if data["files"][index]["matches"]["anti_debug"] != []:
                for adb in data["files"][index]["matches"]["anti_debug"]:
                    antidbg.add_row([adb])
                print(antidbg)
            else:
                pass
            break
        else:
            pass

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
         os.system("python3 -m spacy download en_core_web_sm")
         print(f"{infoS} Language package downloaded.")
         sys.exit(0)
      except:
         sys.exit(0)
   else:
      print(f"\n{infoS} Continuing without string analysis...\n")

# Checking for language package existence if there is no package ask for user to install
try:
    test = spacy.load("en_core_web_sm")
except:
    LangNotFound()

# APK string analyzer with NLP
def Detailed():
    # Our sample string to analyze
    while not q.empty():
        targetString = q.get()
        try:
            nlp = spacy.load("en_core_web_sm")
            sample = nlp(targetString)
        except:
            LangNotFound()

        # Lets analyze!!
        for apkstr in allStrings:
            # Parsing and calculating
            testme = nlp(apkstr)
            if testme.similarity(sample) > 0.8:
                for token in testme:
                    if token.pos_ == "PUNCT":
                        pass
                    else:
                        print(f"{cyan}({magenta}*{cyan})->{white} {apkstr}")

# Execution
if __name__ == '__main__':
    try:
        # Fetching compiler information
        compiler = data["files"][0]["matches"]["compiler"][0]
        print(f"{infoS} Compiler Information: {green}{compiler}{white}\n")

        # Getting and parsing target APK
        targetAPK = str(sys.argv[1])
        parsed = APK(targetAPK)

        # Permissions side
        Analyzer(parsed)

        # Deep scanner
        DeepScan(parsed)

        # APKID scanner
        ApkidParser(apkid_output)

        # Strings side
        check = str(input(f"\n{infoS} Do you want to perform string analysis? It will take a while [Y/N]: "))
        if check == "Y" or check == "y":
            # Testing for language package existence
            try:
                nlpTest = spacy.load("en_core_web_sm")
            except:
                print(f"{errorS} Language package not found. Quitting!!")
                sys.exit(1)

            # Beginning for string analysis
            print(f"{infoS} Analyzing interesting strings. It will take a while...\n")

            #Thread Number
            threadNumber = 0

            # Create threads for every word in suspicious.txt
            for sus in susStrings:
                q.put(sus)
                threadNumber += 1

            # Lets scan!!
            ts = []
            for i in range(0,threadNumber):
                try:
                    t = threading.Thread(target=Detailed)
                    ts.append(t)
                    t.start()
                except:
                    print(f"{errorS} Program terminated.")
                    sys.exit(1)

            # Calling threads
            for t in ts:
                t.join()
        else:
            print(f"{infoS} Goodbye..")
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"{errorS} An error occured. Press CTRL+C to exit.")