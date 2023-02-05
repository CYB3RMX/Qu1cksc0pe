#!/usr/bin/python3

import json
import sys
import re
import os
import getpass
import configparser
import requests
from datetime import date

# Module handling
try:
    from androguard.core.bytecodes.apk import APK
except:
    print("Error: >androguard< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
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

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# necessary variables
danger = 0
normal = 0

# Gathering all strings from file
allStrings = open("temp.txt", "r").read().split('\n')

# Gathering apkid tools output
if sys.argv[3] != "JAR":
    apkid_output = open("apkid.json", "r")
    data = json.load(apkid_output)

# Categories
categs = {
    "Banker": [], "SMS Bot": [], "Base64": [], "VNC Implementation": [], "Keylogging": [],
    "Camera": [], "Phone Calls": [], "Microphone Interaction": [],
    "Information Gathering/Stealing": [], "Database": [], "File Operations": [],
    "Windows Operations": [],
    "Persistence/Managing": [], "Network/Internet": [], "SSL Pining/Certificate Handling": [],
    "Dynamic Class/Dex Loading": [], "Java Reflection": [], "Root Detection": [],
    "Cryptography": [], "Command Execution": []
}

# Scores
scoreDict = {
    "Hydra": 0,
    "FluBot": 0,
    "MoqHao": 0,
    "SharkBot": 0
}

# Parsing date
today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Gathering username
username = getpass.getuser()

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}/Systems/Android/detections.json"))

# Creating report structure
reportz = {
    "target_file": "",
    "app_name": "",
    "package_name": "",
    "play_store": False,
    "sdk_version": "",
    "main_activity": "",
    "features": [],
    "activities": [],
    "services": [],
    "receivers": [],
    "providers": [],
    "libraries": [],
    "signatures": [],
    "permissions": [],
    "malware_family": "",
    "compiler_info": "",
    "anti_vm": [],
    "anti_debug": [],
    "anti_disassembly": [],
    "obfuscation": [],
    "matched_rules": [],
    "user": username,
    "date": dformat,
}

def RecursiveDirScan(targetDir):
    fnames = []
    for root, d_names, f_names in os.walk(targetDir):
        for ff in f_names:
            fnames.append(os.path.join(root, ff))
    return fnames

# Function for parsing apkid tool's output
def ApkidParser(apkid_output):
    print(f"\n{infoS} Performing APKID analysis...")
    for index in range(0, len(data["files"])):
        print(f"[bold red]---->[white] File Name: [bold green]{data['files'][index]['filename']}")

        # Fetching compiler information
        try:
            compiler = data["files"][index]["matches"]["compiler"][0]
            print(f"[bold red]-->[white] Compiler Information: [bold green]{compiler}\n")
            reportz["compiler_info"] = compiler
        except KeyError:
            print("[bold white on red]There is no information about compiler!\n")

        # Fetching and parsing anti virtualization
        if "anti_vm" in data["files"][index]["matches"].keys():
            print("[bold green]--->[magenta] Anti Virtualization Codes")
            if data["files"][index]["matches"]["anti_vm"] != []:
                for avm in data["files"][index]["matches"]["anti_vm"]:
                    print(f"[bold green]>>[white] {avm}")
                    reportz["anti_vm"].append(avm)
                print(" ")
        
        # Fetching and parsing anti debug codes
        if "anti_debug" in data["files"][index]["matches"].keys():
            print("[bold green]--->[magenta] Anti Debug Codes")
            if data["files"][index]["matches"]["anti_debug"] != []:
                for adb in data["files"][index]["matches"]["anti_debug"]:
                    print(f"[bold green]>>[white] {adb}")
                    reportz["anti_debug"].append(adb)
                print(" ")
        
        # Fetching and parsing anti disassembly
        if "anti_disassembly" in data["files"][index]["matches"].keys():
            print("[bold green]--->[magenta] Anti Disassembly")
            if data["files"][index]["matches"]["anti_disassembly"] != []:
                for disas in data["files"][index]["matches"]["anti_disassembly"]:
                    print(f"[bold green]>>[white] {disas}")
                    reportz["anti_disassembly"].append(disas)
                print(" ")

        # Fetching and parsing obfuscators
        if "obfuscator" in data["files"][index]["matches"].keys():
            print("[bold green]--->[magenta] Obfuscation")
            if data["files"][index]["matches"]["obfuscator"] != []:
                for obf in data["files"][index]["matches"]["obfuscator"]:
                    print(f"[bold green]>>[white] {obf}")
                    reportz["obfuscation"].append(obf)
                print(" ")

# Library Hunter
def AndroLibScanner(target_file):
    yara_match_indicator = 0
    # Parsing config file to get rule path
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
    rule_path = conf["Rule_PATH"]["rulepath"]
    allRules = os.listdir(rule_path)

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
        print(f"[bold magenta]>>>>[white] Matched Rules for: [bold green]{target_file}\n")
        print(f"{foundS} Matched Rules for: [bold green]{target_file}[white]\n")
        yara_match_indicator += 1
        for rul in yara_matches:
            yaraTable = Table(title=f"{rul}", title_justify="center", title_style="bold magenta")
            yaraTable.add_column("[bold green]Offset", justify="center")
            yaraTable.add_column("[bold green]Matched String/Byte", justify="center")
            reportz["matched_rules"].append(rul)
            for mm in rul.strings:
                yaraTable.add_row(str(hex(mm[0])), str(mm[2]))
            print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        print(f"\n[bold white on red]Not any rules matched for [blink]{target_file}[/blink]\n")
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
        fnames = RecursiveDirScan(path)
        if fnames != []:
            for extens in fnames:
                if os.path.splitext(extens)[1] == ".so":
                    lib_files_indicator += 1
                    AndroLibScanner(target_file=extens)

        if lib_files_indicator == 0:
            print("\n[bold white on red]Not any library files found for analysis!\n")
    else:
        print("[blink]Decompiler([bold green]JADX[white])[/blink] [white]not found. Skipping...")

def PrintCategs():
    # Table for statistics about categories and components
    statTable = Table(title="* Statistics About Categories and Components *", title_style="bold magenta", title_justify="center")
    statTable.add_column("[bold red]Category", justify="center")
    statTable.add_column("[bold red]Number of Found Patterns", justify="center")
    statTable.add_column("[bold red]Number of Files", justify="center")

    # Parsing area
    for cat in categs:
        if categs[cat] != []:
            file_holder = []
            sanalTable = Table(title=f"* {cat} *", title_style="bold green", title_justify="center")
            sanalTable.add_column("Code/Pattern", justify="center")
            sanalTable.add_column("File", justify="center")
            for element in categs[cat]:
                sanalTable.add_row(f"[bold yellow]{element[0]}", f"[bold cyan]{element[1]}")
                if element[1] not in file_holder:
                    file_holder.append(element[1])
            print(sanalTable)
            statTable.add_row(cat, str(len(categs[cat])), str(len(file_holder)))
            print(" ")

    # Print statistics table
    print(statTable)

# Source code analysis TODO: look for better algorithm!!
def ScanSource(targetAPK):
    # Parsing main activity
    fhandler = pyaxmlparser.APK(targetAPK)
    parsed_package = fhandler.get_package().split(".")

    # Check for decompiled source
    if os.path.exists("TargetAPK/"):
        path = "TargetAPK/sources/"
        fnames = RecursiveDirScan(path)
        if fnames != []:
            question = input(f"{infoC} Do you want to analyze all packages [Y/n]?: ")
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
        print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
        print(">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems/Android/libScanner.conf")

    # Printing report
    PrintCategs()

# Following function will perform JAR file analysis
def PerformJAR(targetAPK):
    # First we need to check if there is a META-INF file
    fbuf = open(targetAPK, "rb").read()
    chek = re.findall("META-INF", str(fbuf))
    if chek != []:
        print(f"{infoS} File Type: [bold green]JAR")
        chek = re.findall(".class", str(fbuf))
        if chek != []:
            # Configurating decompiler...
            conf = configparser.ConfigParser()
            conf.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
            decompiler_path = conf["Decompiler"]["decompiler"]

            # Check if the decompiler exist on system
            if os.path.exists(decompiler_path):
                # Executing decompiler...
                print(f"{infoS} Decompiling target file...")
                os.system(f"{decompiler_path} -q -d TargetSource {targetAPK}")

                # If we successfully decompiled the target file
                if os.path.exists("TargetSource"):
                    # Reading MANIFEST file
                    print(f"\n{infoS} MANIFEST file found. Fetching data...")
                    data = open("TargetSource/resources/META-INF/MANIFEST.MF").read()
                    print(data)
                    fnames = RecursiveDirScan("TargetSource/sources/")
                    for sources in fnames:
                        for index in range(0, len(pattern_file)):
                            for elem in pattern_file[index]:
                                for item in pattern_file[index][elem]:
                                    regx = re.findall(item, open(sources, "r").read())
                                    if regx != [] and '' not in regx:
                                        sanit1 = sources.replace('TargetSource/sources/', '')
                                        if "defpackage/" in sanit1:
                                            sanit2 = sanit1.replace("defpackage/", "")
                                            categs[elem].append([str(item), sanit2])
                                        else:
                                            categs[elem].append([str(item), sanit1])
                else:
                    print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
                    print(">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems/Android/libScanner.conf")

            # Print area
            PrintCategs()

def ParseFlu(arrayz):
    counter = 0
    for el in arrayz:
        if el[0:2] == ".p" and len(el) == 10:
            counter += 1
    return counter

# Analyzer for malware family detection
def CheckFamily(targetApk):
    # Parsing target apk file
    checktarg = pyaxmlparser.APK(targetApk)
    content = checktarg.get_activities()
    content += checktarg.get_services()
    content += checktarg.get_receivers()

    # Gathering data
    fam_data = json.load(open(f"{sc0pe_path}/Systems/Android/family.json"))

    # Family: Hydra, MoqHao, SharkBot
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
    if ParseFlu(act) != 0 and ParseFlu(act) == len(checktarg.get_activities()):
        scoreDict["FluBot"] += 1
        # Checking service name patterns
    ser = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_services()))
    if ParseFlu(ser) != 0 and ParseFlu(ser) == len(checktarg.get_services()):
        scoreDict["FluBot"] += 1
        # Checking receiver name patterns
    rec = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_receivers()))
    if ParseFlu(rec) != 0 and ParseFlu(rec) == len(checktarg.get_receivers()):
        scoreDict["FluBot"] += 1

    # Checking statistics
    sort_score = sorted(scoreDict.items(), key=lambda ff: ff[1], reverse=True)
    if sort_score[0][1] != 0:
        print(f"[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
        reportz["malware_family"] = sort_score[0][0]
    else:
        print(f"{errorS} Couldn\'t detect malware family.")

# Scan files with quark-engine
def Quarked(targetAPK):
    not_found_indicator = 0
    print(f"{infoS} Extracting IP addresses and URLs. Please wait...")
    # Parsing phase
    forensic = Forensic(targetAPK)

    # Extract ip addresses from file
    ipTables = Table()
    ipTables.add_column("[bold green]IP Address", justify="center")
    ipTables.add_column("[bold green]Country", justify="center")
    ipTables.add_column("[bold green]City", justify="center")
    ipTables.add_column("[bold green]Region", justify="center")
    ipTables.add_column("[bold green]ISP", justify="center")
    ipTables.add_column("[bold green]Proxy", justify="center")
    ipTables.add_column("[bold green]Hosting", justify="center")
    if len(forensic.get_ip()) != 0:
        for ips in forensic.get_ip():
            if ips[0] != '0':
                data = requests.get(f"http://ip-api.com/json/{ips}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting")
                if data.json()['status'] != 'fail':
                    ipTables.add_row(
                        str(ips), str(data.json()['country']), 
                        str(data.json()['city']), 
                        str(data.json()['regionName']), 
                        str(data.json()['isp']),
                        str(data.json()['proxy']),
                        str(data.json()['hosting'])
                    )
        print(ipTables)
    else:
        not_found_indicator += 1
    
    # Extract domains from file
    domainTable = Table()
    domainTable.add_column("[bold green]Extracted URL\'s", justify="center")
    if len(forensic.get_url()) != 0:
        for urls in forensic.get_url():
            domainTable.add_row(str(urls))
        print(domainTable)
    else:
        not_found_indicator += 1

    if not_found_indicator == 2:
        print("\n[bold white on red]Not any Email or IP string found in target file!\n")

# Permission analyzer
def Analyzer(parsed):
    global danger
    global normal
    statistics = Table()
    statistics.add_column("[bold green]Permissions", justify="center")
    statistics.add_column("[bold green]State", justify="center")

    # Getting blacklisted permissions
    with open(f"{sc0pe_path}/Systems/Android/perms.json", "r") as f:
        permissions = json.load(f)

    apkPerms = parsed.get_permissions()
    permArr = []

    # Getting target APK file's permissions
    for p in range(len(permissions)):
        permArr.append(permissions[p]["permission"])

    # Parsing permissions
    for pp in apkPerms:
        if pp.split(".")[-1] in permArr:
            statistics.add_row(str(pp), "[bold red]Risky")
            reportz["permissions"].append({str(pp): "Risky"})
            danger += 1
        else:
            statistics.add_row(str(pp), "[bold yellow]Info")
            reportz["permissions"].append({str(pp): "Info"})
            normal += 1

    # If there is no permission:
    if danger == 0 and normal == 0:
        print("\n[bold white on red]Not any permissions found!\n")
    else:
        print(statistics)

# Analyzing more deeply
def DeepScan(parsed):
    # Getting features
    featStat = Table()
    featStat.add_column("[bold green]Features", justify="center")
    features = parsed.get_features()
    if features != []:
        for ff in features:
            featStat.add_row(str(ff))
            reportz["features"].append(ff)
        print(featStat)
    else:
        pass

    # Activities
    activeStat = Table()
    activeStat.add_column("[bold green]Activities", justify="center")
    actos = parsed.get_activities()
    if actos != []:
        for aa in actos:
            activeStat.add_row(str(aa))
            reportz["activities"].append(aa)
        print(activeStat)
    else:
        pass

    # Services
    servStat = Table()
    servStat.add_column("[bold green]Services", justify="center")
    servv = parsed.get_services()
    if servv != []:
        for ss in servv:
            servStat.add_row(str(ss))
            reportz["services"].append(ss)
        print(servStat)
    else:
        pass

    # Receivers
    recvStat = Table()
    recvStat.add_column("[bold green]Receivers", justify="center")
    receive = parsed.get_receivers()
    if receive != []:
        for rr in receive:
            recvStat.add_row(str(rr))
            reportz["receivers"].append(rr)
        print(recvStat)
    else:
        pass

    # Providers
    provStat = Table()
    provStat.add_column("[bold green]Providers", justify="center")
    provids = parsed.get_providers()
    if provids != []:
        for pp in provids:
            provStat.add_row(str(pp))
            reportz["providers"].append(pp)
        print(provStat)
    else:
        pass

def GeneralInformation(targetAPK):
    print(f"\n{infoS} General Informations about [bold green]{targetAPK}[white]")
    reportz["target_file"] = targetAPK

    # Parsing target apk file
    axmlTime = pyaxmlparser.APK(targetAPK)

    # Lets print!!
    print(f"[bold red]>>>>[white] App Name: [bold green]{axmlTime.get_app_name()}")
    print(f"[bold red]>>>>[white] Package Name: [bold green]{axmlTime.get_package()}")
    reportz["app_name"] = axmlTime.get_app_name()
    reportz["package_name"] = axmlTime.get_package()

    # Gathering play store information
    print(f"\n{infoS} Sending query to Google Play Store about target application.")
    try:
        playinf = requests.get(f"https://play.google.com/store/apps/details?id={axmlTime.get_package()}")
        if playinf.ok:
            print("[bold red]>>>>[white] Google Play Store: [bold green]Found\n")
            reportz["play_store"] = True
        else:
            print("[bold red]>>>>[white] Google Play Store: [bold red]Not Found\n")
    except:
        print("\n[bold white on red]An error occured while querying to Google Play Store!\n")

    print(f"[bold red]>>>>[white] SDK Version: [bold green]{axmlTime.get_effective_target_sdk_version()}")
    print(f"[bold red]>>>>[white] Main Activity: [bold green]{axmlTime.get_main_activity()}")
    reportz["sdk_version"] = axmlTime.get_effective_target_sdk_version()
    reportz["main_activity"] = axmlTime.get_main_activity()
    try:
        if axmlTime.get_libraries() != []:
            print("[bold red]>>>>[white] Libraries:")
            for libs in axmlTime.get_libraries():
                print(f"[bold magenta]>>[white] {libs}")
                reportz["libraries"].append(libs)
            print(" ")

        if axmlTime.get_signature_names() != []:
            print("[bold red]>>>>[white] Signatures:")
            for sigs in axmlTime.get_signature_names():
                print(f"[bold magenta]>>[white] {sigs}")
                reportz["signatures"].append(sigs)
            print(" ")
    except:
        pass

# Execution
if __name__ == '__main__':
    try:
        # Getting target APK
        targetAPK = str(sys.argv[1])

        # Check for JAR file
        if sys.argv[3] == "JAR":
            PerformJAR(targetAPK)
            sys.exit(0)

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
            print("\n[bold white on red]An error occured while decompiling the file. Please check configuration file and modify the [blink]Decompiler[/blink] option.")
            print(f"[bold white]>>> Configuration file path: [bold green]{sc0pe_path}/Systems/Android/libScanner.conf")

        # Source code analysis zone
        print(f"\n{infoS} Performing source code analysis...")
        ScanSource(targetAPK)

        # APKID scanner
        ApkidParser(apkid_output)

        # Quark scanner
        Quarked(targetAPK)

        # Print reports
        if sys.argv[2] == "True":
            with open("sc0pe_android_report.json", "w") as rp_file:
                json.dump(reportz, rp_file, indent=4)
            print("\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_android_report.json\n")
    except KeyboardInterrupt:
        print("\n[bold white on red]An error occured. Press [blink]CTRL+C[/blink] to exit.\n")