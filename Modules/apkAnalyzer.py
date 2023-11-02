#!/usr/bin/python3

import json
import sys
import re
import os
import getpass
import configparser
import requests
import distutils.spawn
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
    from rich.progress import track
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
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

# Get python binary
if distutils.spawn.find_executable("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Compatibility
homeD = os.path.expanduser("~")
py_version = sys.version_info[1]
sc0pe_helper_path = "/usr/lib/python3/dist-packages/sc0pe_helper.py"
path_seperator = "/"
setup_scr = "setup.sh"
if sys.platform == "win32":
    sc0pe_helper_path = f"{homeD}\\appdata\\local\\programs\\python\\python3{py_version}\\lib\\site-packages\\sc0pe_helper.py"
    path_seperator = "\\"
    setup_scr = "setup.ps1"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
# Using helper library
if os.path.exists(sc0pe_helper_path):
    from sc0pe_helper import Sc0peHelper
    sc0pehelper = Sc0peHelper(sc0pe_path)
else:
    print(f"{errorS} [bold green]sc0pe_helper[white] library not installed. You need to execute [bold green]{setup_scr}[white] script!")
    sys.exit(1)

# necessary variables
danger = 0
normal = 0

# Gathering all strings from file
allStrings = open("temp.txt", "r").read().split('\n')

# Categories
categs = {
    "Banker": [], "SMS Bot": [], "Base64": [], "VNC Implementation": [], "Keylogging": [],
    "Camera": [], "Phone Calls": [], "Microphone Interaction": [],
    "Information Gathering/Stealing": [], "Database": [], "File Operations": [],
    "Windows Operations": [],
    "Persistence/Managing": [], "Network/Internet": [], "SSL Pining/Certificate Handling": [],
    "Dynamic Class/Dex Loading": [], "Java Reflection": [], "Root Detection": [],
    "Cryptography": [], "Command Execution": [], "Anti-VM/Anti-Debug": [], "BOT Activity": []
}

# Parsing date
today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Gathering username
username = getpass.getuser()

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}detections.json"))

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
    "matched_rules": [],
    "user": username,
    "date": dformat,
}

def MultiYaraScanner(targetAPK):
    lib_files_indicator = 0
    # Configurating decompiler...
    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf")
    decompiler_path = conf["Decompiler"]["decompiler"]

    # Check if the decompiler exist on system
    if os.path.exists(decompiler_path):
        # Executing decompiler...
        print(f"{infoS} Decompiling target APK file...")
        full_path_file = r"{}".format(os.path.abspath(targetAPK))
        os.system(f"{decompiler_path} -q -d TargetAPK \"{full_path_file}\"")

        # Scan for library files and analyze them
        path = f"TargetAPK{path_seperator}resources{path_seperator}"
        fnames = sc0pehelper.recursive_dir_scan(path)
        if fnames != []:
            for extens in fnames:
                if os.path.splitext(extens)[1] == ".so":
                    lib_files_indicator += 1
                    sc0pehelper.yara_rule_scanner("android", extens, config_path=f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf", report_object=reportz)

        if lib_files_indicator == 0:
            print("\n[bold white on red]There is no library files found for analysis!\n")
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

# Source code analysis
def ScanSource(targetAPK):
    # Parsing main activity
    fhandler = pyaxmlparser.APK(targetAPK)
    parsed_package = fhandler.get_package().split(".")

    # Check for decompiled source
    if os.path.exists(f"TargetAPK{path_seperator}"):
        path = f"TargetAPK{path_seperator}sources{path_seperator}"
        fnames = sc0pehelper.recursive_dir_scan(path)
        if fnames != []:
            question = input(f"{infoC} Do you want to analyze all packages [Y/n]?: ")
            print(f"{infoS} Preparing source files...")
            target_source_files = []
            for sources in track(range(len(fnames)), description="Processing files..."):
                if question == "Y" or question == "y" or question == "yes" or question == "Yes":
                    target_source_files.append(fnames[sources].replace(f'TargetAPK{path_seperator}sources{path_seperator}', ''))
                else:
                    if parsed_package[-1] in fnames[sources].replace(f'TargetAPK{path_seperator}sources{path_seperator}', ''):
                        target_source_files.append(fnames[sources].replace(f'TargetAPK{path_seperator}sources{path_seperator}', ''))

            if target_source_files != [] and len(target_source_files) > 1:
                print(f"\n{infoS} Analyzing source codes. Please wait...")
                for scode in track(range(len(target_source_files)), description="Analyzing..."):
                    try:
                        scode_buffer = open(f"TargetAPK{path_seperator}sources{path_seperator}{target_source_files[scode]}", "r").read()
                        for code_key in pattern_file:
                            for code_val in pattern_file[code_key]["patterns"]:
                                try:
                                    regx = re.findall(code_val, scode_buffer)
                                    if regx != [] and '' not in regx:
                                        categs[code_key].append([str(code_val), target_source_files[scode]])
                                except:
                                    continue
                    except:
                        continue
                # Printing report
                PrintCategs()
            else:
                print(f"\n{errorS} Looks like there is nothing to scan or maybe there is an [bold green]Anti-Analysis[white] technique implemented!")
                print(f"{infoS} You need to select \"[bold green]yes[white]\" option in [bold yellow]Analyze All Packages[white]")
    else:
        print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
        print(f">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

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
            conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf")
            decompiler_path = conf["Decompiler"]["decompiler"]

            # Check if the decompiler exist on system
            if os.path.exists(decompiler_path):
                # Executing decompiler...
                print(f"{infoS} Decompiling target file...")
                full_path_file = r"{}".format(os.path.abspath(targetAPK))
                os.system(f"{decompiler_path} -q -d TargetSource \"{full_path_file}\"")

                # If we successfully decompiled the target file
                if os.path.exists("TargetSource"):
                    # Reading MANIFEST file
                    print(f"\n{infoS} MANIFEST file found. Fetching data...")
                    data = open(f"TargetSource{path_seperator}resources{path_seperator}META-INF{path_seperator}MANIFEST.MF").read()
                    print(data)
                    fnames = sc0pehelper.recursive_dir_scan(target_directory=f"TargetSource{path_seperator}sources{path_seperator}")
                    print(f"{infoS} Preparing source files...")
                    target_source_files = []
                    for sources in track(range(len(fnames)), description="Processing files..."):
                        target_source_files.append(fnames[sources].replace(f'TargetSource{path_seperator}sources{path_seperator}', ''))

                    print(f"\n{infoS} Analyzing source codes. Please wait...")
                    for scode in track(range(len(target_source_files)), description="Analyzing..."):
                        try:
                            scode_buffer = open(f"TargetSource{path_seperator}sources{path_seperator}{target_source_files[scode]}", "r").read()
                            for code_key in pattern_file:
                                for code_val in pattern_file[code_key]["patterns"]:
                                    try:
                                        regx = re.findall(code_val, scode_buffer)
                                        if regx != [] and '' not in regx:
                                            if f"defpackage{path_seperator}" in target_source_files[scode]:
                                                categs[code_key].append([str(code_val), target_source_files[scode].replace(f"defpackage{path_seperator}", "")])
                                            else:
                                                categs[code_key].append([str(code_val), target_source_files[scode]])
                                    except:
                                        continue
                        except:
                            continue
                else:
                    print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
                    print(f">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

            # Print area
            PrintCategs()

def pattern_scanner_ex(regex, target_files, target_type, value_array):
    for url in track(range(len(target_files)), description=f"Processing {target_type}..."):
        try:
            source_buffer = open(target_files[url], "r").read()
            url_regex = re.findall(regex, source_buffer)
            if url_regex != []:
                for val in url_regex:
                    if val not in value_array:
                        if "<" in val:
                            value_array.append(val.split("<")[0])
                        else:
                            value_array.append(val)
        except:
            continue

def pattern_scanner(target_pattern):
    extracted_values = []
    path = f"TargetAPK{path_seperator}sources{path_seperator}"
    fnames = sc0pehelper.recursive_dir_scan(path)
    if fnames != []:
        pattern_scanner_ex(regex=target_pattern,
                           target_files=fnames,
                           target_type="sources",
                           value_array=extracted_values
        )
    path = f"TargetAPK{path_seperator}resources{path_seperator}"
    fnames = sc0pehelper.recursive_dir_scan(path)
    if fnames != []:
        pattern_scanner_ex(regex=target_pattern,
                           target_files=fnames,
                           target_type="resources",
                           value_array=extracted_values
        )

    if extracted_values != []:
        return extracted_values
    else:
        return []

# Scan files for url and ip patterns
def Get_IP_URL(targetAPK):
    print(f"\n{infoS} Looking for possible IP address patterns. Please wait...")
    ip_vals = pattern_scanner(target_pattern=r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
    # Extract ip addresses from file
    if ip_vals != []:
        ipTables = Table()
        ipTables.add_column("[bold green]IP Address", justify="center")
        ipTables.add_column("[bold green]Country", justify="center")
        ipTables.add_column("[bold green]City", justify="center")
        ipTables.add_column("[bold green]Region", justify="center")
        ipTables.add_column("[bold green]ISP", justify="center")
        ipTables.add_column("[bold green]Proxy", justify="center")
        ipTables.add_column("[bold green]Hosting", justify="center")
        for ips in ip_vals:
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
        print(f"{errorS} There is no possible IP address pattern found!")
    
    # Extract url values
    print(f"\n{infoS} Looking for URL values. Please wait...")
    url_vals = pattern_scanner(target_pattern=r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    if url_vals != []:
        urltable = Table()
        urltable.add_column("[bold green]Extracted URL Values", justify="center")
        for uv in url_vals:
            urltable.add_row(str(uv))
        print(urltable)
    else:
        print(f"{errorS} There is no URL pattern found!")

# Permission analyzer
def Analyzer(parsed):
    global danger
    global normal
    statistics = Table()
    statistics.add_column("[bold green]Permissions", justify="center")
    statistics.add_column("[bold green]State", justify="center")

    # Getting blacklisted permissions
    with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}perms.json", "r") as f:
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
        print("\n[bold white on red]There is no permissions found!\n")
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
        targetAPK = sys.argv[1]

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

        # Yara matches
        print(f"\n{infoS} Performing YARA rule matching...")
        sc0pehelper.yara_rule_scanner("android", targetAPK, config_path=f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf", report_object=reportz)

        # Decompiling and scanning libraries
        print(f"\n{infoS} Performing library analysis...")
        try:
            MultiYaraScanner(targetAPK)
        except:
            print("\n[bold white on red]An error occured while decompiling the file. Please check configuration file and modify the [blink]Decompiler[/blink] option.")
            print(f"[bold white]>>> Configuration file path: [bold green]{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf")

        # Malware family detection
        print(f"\n{infoS} Performing malware family detection. Please wait!!")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}andro_familydetect.py \"{targetAPK}\""
        os.system(command)

        # Source code analysis zone
        print(f"\n{infoS} Performing source code analysis...")
        ScanSource(targetAPK)

        # IP and URL value scan
        Get_IP_URL(targetAPK)

        # Print reports
        if sys.argv[2] == "True":
            sc0pehelper.report_writer("android", reportz)
    except KeyboardInterrupt:
        print("\n[bold white on red]An error occured. Press [blink]CTRL+C[/blink] to exit.\n")