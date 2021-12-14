#!/usr/bin/python3

import json
import sys
import re
import os
import configparser
import requests

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
    from quark.forensic import Forensic
except:
    print("Error: >quark-engine< module not found.")
    sys.exit(1)

try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
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
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# necessary variables
danger = 0
normal = 0

# Gathering all strings from file
allStrings = open("temp.txt", "r").read().split('\n')

# Gathering apkid tools output
apkid_output = open("apkid.json", "r")
data = json.load(apkid_output)

# Categories
categs = {"Banker": [], "SMS Bot": [], "Base64": [],
          "Information Gathering": [], "Database": [], "File Operations": [],
          "Persistence/Managing": [], "Network/Internet": [], "SSL Pining/Certificate Handling": [],
          "Dynamic Class/Dex Loading": [], "Java Reflection": [], "Root Detection": [],
          "Cryptography": [], "Command Execution": []}

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

# Library Hunter
def AndroLibScanner(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
    rule_path = conf["Rule_PATH"]["rulepath"]
    allRules = os.listdir(rule_path)

    # Summary table
    yaraTable = PrettyTable()

    # This array for holding and parsing easily matched rules
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{rule_path}{rul}")
            tempmatch = rules.match(target_file)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except:
            continue

    # Printing area
    if yara_matches != []:
        print(f"{foundS} Matched Rules for: {green}{target_file}{white}\n")
        yara_match_indicator += 1
        for rul in yara_matches:
            print(f"{magenta}>>>>{white} {rul}")
            yaraTable.field_names = [f"{green}Offset{white}", f"{green}Matched String/Byte{white}"]
            for mm in rul.strings:
                yaraTable.add_row([f"{hex(mm[0])}", f"{str(mm[2])}"])
            print(f"{yaraTable}\n")
            yaraTable.clear_rows()

    if yara_match_indicator == 0:
        print(f"{errorS} Not any rules matched for {green}{target_file}{white}.\n")
def MultiYaraScanner(targetAPK):
    lib_files_indicator = 0
    # Configurating decompiler...
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
    decompiler_path = conf["Decompiler"]["decompiler"]

    # Check if the decompiler exist on system
    if os.path.exists(decompiler_path):
        # Executing decompiler...
        print(f"{infoS} Decompiling target APK file...")
        os.system(f"{decompiler_path} -q -d TargetAPK {targetAPK}")

        # Scan for library files and analyze them
        path = "TargetAPK/resources/"
        fnames = []
        for root, d_names, f_names in os.walk(path):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        if fnames != []:
            for extens in fnames:
                if os.path.splitext(extens)[1] == ".so":
                    lib_files_indicator += 1
                    AndroLibScanner(target_file=extens)

        if lib_files_indicator == 0:
            print(f"{errorS} Not any library files found for analysis.")
    else:
        print(f"{errorS} Decompiler({green}JADX{white}) not found. Skipping...")

# Source code analysis TODO: look for better algorithm!!
def ScanSource(targetAPK):
    # Parsing main activity
    fhandler = pyaxmlparser.APK(targetAPK)
    parsed_package = fhandler.get_package().split(".")

    # Tables
    sanalTable = PrettyTable()
    sanalTable.field_names = ["Code/Pattern", "File"]

    # Gathering code patterns
    pattern_file = json.load(open(f"{sc0pe_path}/Systems/Android/detections.json"))

    # Check for decompiled source
    if os.path.exists("TargetAPK/"):
        path = "TargetAPK/sources/"
        fnames = []
        for root, d_names, f_names in os.walk(path):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        if fnames != []:
            question = input(f"{infoS} Do you want to analyze all packages [Y/n]?: ")
            for sources in fnames:
                for index in range(0, len(pattern_file)):
                    for elem in pattern_file[index]:
                        for item in pattern_file[index][elem]:
                            regx = re.findall(item, open(sources, "r").read())
                            if question == "Y" or question == "y":
                                if regx != [] and '' not in regx:
                                    categs[elem].append([str(item), sources.replace('TargetAPK/sources/', '')])
                            else:
                                if regx != [] and '' not in regx and parsed_package[1] in sources.replace('TargetAPK/sources/', ''):
                                    categs[elem].append([str(item), sources.replace('TargetAPK/sources/', '')])
                                
    else:
        print(f"{errorS} Couldn\'t locate source codes. Did target file decompiled correctly?")
        print(f"{infoS} {green}Hint{white}: Don\'t forget to specify decompiler path in Systems/Android/libScanner.conf")

    # Printing report
    for cat in categs:
        if categs[cat] != []:
            print(f"{red}>>>{white} Category: {green}{cat}{white}")
            for element in categs[cat]:
                sanalTable.add_row([f"{yellow}{element[0]}{white}", f"{cyan}{element[1]}{white}"])
            print(f"{sanalTable}\n")
            sanalTable.clear_rows()
        
# Analyzer for malware family detection
def CheckFamily(targetApk):
    # Scores
    scoreDict = {
        "Hydra": 0,
        "FluBot": 0
    }

    # Parsing target apk file
    checktarg = pyaxmlparser.APK(targetApk)
    content = checktarg.get_activities()
    content += checktarg.get_services()
    content += checktarg.get_receivers()

    # Gathering data
    fam_data = json.load(open(f"{sc0pe_path}/Systems/Android/family.json"))

    # Family: Hydra
    for key in fam_data:
        try:
            for act_key in fam_data[key]:
                for dat in fam_data[key][act_key]:
                    actreg = re.findall(dat, str(content))
                    if actreg != []:
                        scoreDict[key] += 1
        except:
            continue

    # Family: FluBot
        # Checking activity name patterns
    act = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_activities()))
    if len(act) == len(checktarg.get_activities()):
        scoreDict["FluBot"] += 1
        # Checking service name patterns
    ser = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_services()))
    if len(ser) == len(checktarg.get_services()):
        scoreDict["FluBot"] += 1
        # Checking receiver name patterns
    rec = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_receivers()))
    if len(rec) == len(checktarg.get_receivers()):
        scoreDict["FluBot"] += 1

    # Checking statistics
    for fam in scoreDict:
        if scoreDict[fam] != 0:
            print(f"{red}>>>{white} Possible Malware Family: {green}{fam}{white}")

# Scan files with quark-engine
def Quarked(targetAPK):
    not_found_indicator = 0
    print(f"{infoS} Extracting IP addresses and URLs. Please wait...")
    # Parsing phase
    forensic = Forensic(targetAPK)

    # Extract ip addresses from file
    ipTables = PrettyTable()
    ipTables.field_names = [f"{green}IP Address{white}", 
                            f"{green}Country{white}", 
                            f"{green}City{white}", 
                            f"{green}Region{white}", 
                            f"{green}ISP{white}", 
                            f"{green}Proxy{white}",
                            f"{green}Hosting{white}"
                            ]
    if len(forensic.get_ip()) != 0:
        for ips in forensic.get_ip():
            if ips[0] != '0':
                data = requests.get(f"http://ip-api.com/json/{ips}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting")
                if data.json()['status'] != 'fail':
                    ipTables.add_row(
                        [
                            ips, data.json()['country'], 
                            data.json()['city'], 
                            data.json()['regionName'], 
                            data.json()['isp'],
                            data.json()['proxy'],
                            data.json()['hosting']
                        ]
                    )
        print(ipTables)
    else:
        not_found_indicator += 1
    
    # Extract domains from file
    domainTable = PrettyTable()
    domainTable.field_names = [f"{green}Extracted URL\'s{white}"]
    if len(forensic.get_url()) != 0:
        for urls in forensic.get_url():
            domainTable.add_row([urls])
        print(domainTable)
    else:
        not_found_indicator += 1

    if not_found_indicator == 2:
        print(f"{errorS} Not any Email or IP string found in target file.")

# Permission analyzer
def Analyzer(parsed):
    global danger
    global normal
    statistics = PrettyTable()

    # Getting blacklisted permissions
    with open(f"{sc0pe_path}/Systems/Android/perms.json", "r") as f:
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

def GeneralInformation(targetAPK):
    print(f"\n{infoS} General Informations about {green}{targetAPK}{white}")

    # Parsing target apk file
    axmlTime = pyaxmlparser.APK(targetAPK)

    # Lets print!!
    print(f"{red}>>>>{white} App Name: {green}{axmlTime.get_app_name()}{white}")
    print(f"{red}>>>>{white} Package Name: {green}{axmlTime.get_package()}{white}")

    # Gathering play store information
    try:
        playinf = requests.get(f"https://play.google.com/store/apps/details?id={axmlTime.get_package()}")
        if playinf.status_code == 200:
            print(f"{red}>>>>{white} Google Play Store: {green}Found{white}")
        else:
            print(f"{red}>>>>{white} Google Play Store: {red}Not Found{white}")
    except:
        print(f"{errorS} An error occured while querying to play store.")

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

        # Malware family detection
        print(f"\n{infoS} Performing malware family detection...")
        CheckFamily(targetApk=targetAPK)

        # Yara matches
        print(f"\n{infoS} Performing YARA rule matching...")
        AndroLibScanner(target_file=targetAPK)

        # Decompiling and scanning libraries
        print(f"\n{infoS} Performing library analysis...")
        try:
            MultiYaraScanner(targetAPK)
        except:
            print(f"{errorS} An error occured while decompiling the file. Please check configuration file and modify the {green}Decompiler{white} option.")
            print(f"{infoS} Configuration file path: {green}{sc0pe_path}/Systems/Android/libScanner.conf{white}")

        # Source code analysis zone
        print(f"\n{infoS} Performing source code analysis...")
        ScanSource(targetAPK)

        # APKID scanner
        ApkidParser(apkid_output)

        # Quark scanner
        Quarked(targetAPK)
    except KeyboardInterrupt:
        print(f"{errorS} An error occured. Press CTRL+C to exit.")