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

try:
    import apkid
except:
    print("Error: >apkid< module not found.")
    sys.exit(1)

try:
    from quark.forensic import Forensic
except:
    print("Error: >quark-engine< module not found.")
    sys.exit(1)

try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

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
    print(f"\n{infoS} Performing APKID analysis...")
    for index in range(0, len(data["files"])):
        print(f"{red}====>{white} File Name: {green}{data['files'][index]['filename']}{white}")

        # Fetching compiler information
        try:
            compiler = data["files"][index]["matches"]["compiler"][0]
            print(f"{red}==>{white} Compiler Information: {green}{compiler}{white}\n")
        except KeyError:
            print(f"{errorS} There is no information about compiler.\n")

        # Fetching and parsing anti virtualization
        if "anti_vm" in data["files"][index]["matches"].keys():
            print(f"{green}--->{magenta} Anti Virtualization Codes{white}")
            if data["files"][index]["matches"]["anti_vm"] != []:
                for avm in data["files"][index]["matches"]["anti_vm"]:
                    print(f">> {avm}")
                print(" ")
        
        # Fetching and parsing anti debug codes
        if "anti_debug" in data["files"][index]["matches"].keys():
            print(f"{green}--->{magenta} Anti Debug Codes{white}")
            if data["files"][index]["matches"]["anti_debug"] != []:
                for adb in data["files"][index]["matches"]["anti_debug"]:
                    print(f">> {adb}")
                print(" ")
        
        # Fetching and parsing anti disassembly
        if "anti_disassembly" in data["files"][index]["matches"].keys():
            print(f"{green}--->{magenta} Anti Disassembly{white}")
            if data["files"][index]["matches"]["anti_disassembly"] != []:
                for disas in data["files"][index]["matches"]["anti_disassembly"]:
                    print(f">> {disas}")
                print(" ")

        # Fetching and parsing obfuscators
        if "obfuscator" in data["files"][index]["matches"].keys():
            print(f"{green}--->{magenta} Obfuscation{white}")
            if data["files"][index]["matches"]["obfuscator"] != []:
                for obf in data["files"][index]["matches"]["obfuscator"]:
                    print(f">> {obf}")
                print(" ")

# Scan files with quark-engine
def Quarked(targetAPK):
    print(f"{infoS} Extracting IP addresses and URLs. Please wait...")
    # Parsing phase
    forensic = Forensic(targetAPK)

    # Extract ip addresses from file
    ipTables = PrettyTable()
    ipTables.field_names = [f"{green}Extracted IP Addresses{white}"]
    if len(forensic.get_ip()) != 0:
        for ips in forensic.get_ip():
            ipTables.add_row([ips])
        print(ipTables)
    
    # Extract domains from file
    domainTable = PrettyTable()
    domainTable.field_names = [f"{green}Extracted URL\'s{white}"]
    if len(forensic.get_url()) != 0:
        for urls in forensic.get_url():
            domainTable.add_row([urls])
        print(domainTable)

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
      return False

# Checking for language package existence if there is no package ask for user to install
try:
    test = spacy.load("en_core_web_sm")
except:
    anlyzed = LangNotFound()

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

def GeneralInformation(targetAPK):
    print(f"{infoS} General Informations about {green}{targetAPK}{white}")

    # Parsing target apk file
    axmlTime = pyaxmlparser.APK(targetAPK)

    # Lets print!!
    print(f"{red}>>>>{white} App Name: {green}{axmlTime.get_app_name()}{white}")
    print(f"{red}>>>>{white} Package Name: {green}{axmlTime.get_package()}{white}")
    print(f"{red}>>>>{white} SDK Version: {green}{axmlTime.get_effective_target_sdk_version()}{white}")
    print(f"{red}>>>>{white} Main Activity: {green}{axmlTime.get_main_activity()}{white}")
    try:
        if axmlTime.get_libraries() != []:
            print(f"{red}>>>>{white} Libraries:")
            for libs in axmlTime.get_libraries():
                print(f"{magenta}>>{white} {libs}")
            print(" ")

        if axmlTime.get_signature_names() != []:
            print(f"{red}>>>>{white} Signatures:")
            for sigs in axmlTime.get_signature_names():
                print(f"{magenta}>>{white} {sigs}")
            print(" ")
    except:
        pass

# Execution
if __name__ == '__main__':
    try:
        # Getting target APK
        targetAPK = str(sys.argv[1])

        # General informations
        GeneralInformation(targetAPK)

        # Parsing target apk for androguard
        parsed = APK(targetAPK)

        # Permissions side
        Analyzer(parsed)

        # Deep scanner
        DeepScan(parsed)

        # APKID scanner
        ApkidParser(apkid_output)

        # Quark scanner
        Quarked(targetAPK)

        # Strings side
        if anlyzed != False:
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