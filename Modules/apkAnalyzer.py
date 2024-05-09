#!/usr/bin/python3

import json
import sys
import re
import os
import yara
import getpass
import configparser
import requests
import subprocess
import distutils.spawn
from datetime import date

from utils import err_exit

# Module handling
try:
    from androguard.core.bytecodes.apk import APK
except:
    err_exit("Error: >androguard< module not found.")

try:
    from rich import print
    from rich.table import Table
    from rich.progress import track
except:
    err_exit("Error: >rich< module not found.")

try:
    import pyaxmlparser
except:
    err_exit("Error: >pyaxmlparser< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()

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
path_seperator = "/"
setup_scr = "setup.sh"
strings_param = "--all"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"
    strings_param = "-a"
elif sys.platform == "darwin":
    strings_param = "-a"
else:
    pass

# Getting target APK
targetAPK = sys.argv[1]

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# necessary variables
danger = 0
normal = 0

# Perform strings
_ = subprocess.run(f"strings {strings_param} \"{targetAPK}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
if sys.platform != "win32":
    _ = subprocess.run(f"strings {strings_param} -e l {targetAPK} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)


# Gathering all strings from file
allStrings = open("temp.txt", "r").read().split('\n')

# Parsing date
today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Gathering username
username = getpass.getuser()

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}detections.json"))

# Creating report structure

# Read config file
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf")

class APKAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.decompiler_path = conf["Decompiler"]["decompiler"]
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self.full_path_file = os.path.abspath(self.target_file)
        self.reportz = {
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
            "code_patterns": {},
            "user": username,
            "date": dformat,
        }

    def report_writer(self, target_os, report_object):
        with open(f"sc0pe_{target_os}_report.json", "w") as rp_file:
            json.dump(report_object, rp_file, indent=4)
        print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_{target_os}_report.json\n")

    def recursive_dir_scan(self, target_directory):
        fnames = []
        for root, d_names, f_names in os.walk(target_directory):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames

    def yara_rule_scanner(self, filename, report_object):
        yara_match_indicator = 0
        try:
            allRules = os.listdir(self.rule_path)
        except:
            finalpath = f"{sc0pe_path}{path_seperator}{self.rule_path}"
            allRules = os.listdir(finalpath)

        # This array for holding and parsing easily matched rules
        yara_matches = []
        for rul in allRules:
            try:
                rules = yara.compile(f"{finalpath}{rul}")
                tempmatch = rules.match(filename)
                if tempmatch != []:
                    for matched in tempmatch:
                        if matched.strings != []:
                            if matched not in yara_matches:
                                yara_matches.append(matched)
            except:
                continue

        # Printing area
        if yara_matches != []:
            yara_match_indicator += 1
            for rul in yara_matches:
                yaraTable = Table()
                print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
                yaraTable.add_column("Offset", style="bold green", justify="center")
                yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
                report_object["matched_rules"].append({str(rul): []})
                for matched_pattern in rul.strings:
                    yaraTable.add_row(f"{hex(matched_pattern.instances[0].offset)}", f"{str(matched_pattern.instances[0].matched_data)}")
                    try:
                        report_object["matched_rules"][-1][str(rul)].append({"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": matched_pattern.instances[0].matched_data.decode("ascii")})
                    except:
                        report_object["matched_rules"][-1][str(rul)].append({"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": str(matched_pattern.instances[0].matched_data)})
                print(yaraTable)
                print(" ")

        if yara_match_indicator == 0:
            print(f"[bold white on red]There is no rules matched for {filename}")

    def MultiYaraScanner(self):
        lib_files_indicator = 0
        # Check if the decompiler exist on system
        if os.path.exists(self.decompiler_path):
            if os.path.exists("TargetAPK"):
                pass
            else:
                # Executing decompiler...
                print(f"{infoS} Decompiling target APK file...")
                os.system(f"{self.decompiler_path} -q -d TargetAPK \"{self.full_path_file}\"")

            # Scan for library files and analyze them
            path = f"TargetAPK{path_seperator}resources{path_seperator}"
            fnames = self.recursive_dir_scan(path)
            if fnames != []:
                for extens in fnames:
                    if os.path.splitext(extens)[1] == ".so":
                        lib_files_indicator += 1
                        self.yara_rule_scanner(extens, report_object=self.reportz)

            if lib_files_indicator == 0:
                print("\n[bold white on red]There is no library files found for analysis!\n")
        else:
            print("[blink]Decompiler([bold green]JADX[white])[/blink] [white]not found. Skipping...")

    def print_file_report(self, file_report_obj):
        for obj in file_report_obj:
            if file_report_obj[obj]["patterns"]:
                print(f"[bold magenta]>>>>[white] File Name: [bold yellow]{obj}")
                print(f"[bold magenta]>>>>[white] Categories: [bold red]{file_report_obj[obj]['categories']}")
                rep_table = Table()
                rep_table.add_column("[bold green]Patterns", justify="center")

                # Add elements to table in the same time
                for pattern in file_report_obj[obj]["patterns"]:
                    rep_table.add_row(str(pattern))

                # Print summary
                print(rep_table)
                print("")

    # Source code analysis
    def ScanSource(self):
        # Check for decompiled source
        if os.path.exists(f"TargetAPK{path_seperator}"):
            # Prepare source files
            path = f"TargetAPK{path_seperator}sources{path_seperator}"
            fnames = self.recursive_dir_scan(path)
            if fnames != []:
                print(f"\n{infoS} Preparing source files...")
                target_source_files = []
                file_report = {}
                for sources in track(range(len(fnames)), description="Processing files..."):
                    sanitized = fnames[sources].replace(f'TargetAPK{path_seperator}sources{path_seperator}', '')
                    target_source_files.append(sanitized)
                    if ("android" not in sanitized) and ("kotlin" not in sanitized):
                        file_report.update({sanitized: {"patterns": [], "categories": []}})

                # Analyze source files
                if target_source_files != [] and len(target_source_files) > 1:
                    print(f"\n{infoS} Analyzing source codes. Please wait...")
                    for scode in track(range(len(target_source_files)), description="Analyzing..."):
                        try:
                            scode_buffer = open(f"TargetAPK{path_seperator}sources{path_seperator}{target_source_files[scode]}", "r").read()
                            for code_key in pattern_file:
                                for code_val in pattern_file[code_key]["patterns"]:
                                    # Scan patterns...
                                    try:
                                        regx = re.findall(code_val, scode_buffer)
                                        if regx != [] and '' not in regx:
                                            file_report[target_source_files[scode]]["patterns"].append(code_val)
                                            if (code_key not in file_report[target_source_files[scode]]["categories"]) and (code_key != "" or code_key is not None):
                                                file_report[target_source_files[scode]]["categories"].append(code_key)
                                    except:
                                        continue
                            self.reportz["code_patterns"].update(file_report)
                        except:
                            continue
                    # Printing report
                    self.print_file_report(file_report_obj=file_report)
                else:
                    print(f"\n{errorS} Looks like there is nothing to scan or maybe there is an [bold green]Anti-Analysis[white] technique implemented!")
                    print(f"{infoS} You need to select \"[bold green]yes[white]\" option in [bold yellow]Analyze All Packages[white]")
        else:
            print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
            print(f">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

    # Following function will perform JAR file analysis
    def PerformJAR(self):
        # First we need to check if there is a META-INF file
        fbuf = open(self.target_file, "rb").read()
        chek = re.findall("META-INF", str(fbuf))
        if chek != []:
            print(f"{infoS} File Type: [bold green]JAR")
            chek = re.findall(".class", str(fbuf))
            if chek != []:

                # Check if the decompiler exist on system
                if os.path.exists(self.decompiler_path):
                    # Executing decompiler...
                    print(f"{infoS} Decompiling target file...")
                    os.system(f"{self.decompiler_path} -q -d TargetSource \"{self.full_path_file}\"")

                    # If we successfully decompiled the target file
                    if os.path.exists("TargetSource"):
                        # Reading MANIFEST file
                        print(f"\n{infoS} MANIFEST file found. Fetching data...")
                        data = open(f"TargetSource{path_seperator}resources{path_seperator}META-INF{path_seperator}MANIFEST.MF").read()
                        print(data)

                        # Preapare source files
                        fnames = self.recursive_dir_scan(target_directory=f"TargetSource{path_seperator}sources{path_seperator}")
                        print(f"{infoS} Preparing source files...")
                        target_source_files = []
                        file_report = {}
                        for sources in track(range(len(fnames)), description="Processing files..."):
                            sanitized = fnames[sources].replace(f'TargetSource{path_seperator}sources{path_seperator}', '')
                            target_source_files.append(sanitized)
                            if ("android" not in sanitized) and ("kotlin" not in sanitized):
                                file_report.update({sanitized: {"patterns": [], "categories": []}})

                        # Analyze source files
                        print(f"\n{infoS} Analyzing source codes. Please wait...")
                        for scode in track(range(len(target_source_files)), description="Analyzing..."):
                            try:
                                scode_buffer = open(f"TargetSource{path_seperator}sources{path_seperator}{target_source_files[scode]}", "r").read()
                                for code_key in pattern_file:
                                    for code_val in pattern_file[code_key]["patterns"]:
                                        try:
                                            regx = re.findall(code_val, scode_buffer)
                                            if regx != [] and '' not in regx:
                                                file_report[target_source_files[scode]]["patterns"].append(code_val)
                                                if (code_key not in file_report[target_source_files[scode]]["categories"]) and (code_key != "" or code_key is not None):
                                                    file_report[target_source_files[scode]]["categories"].append(code_key)
                                        except:
                                            continue
                                self.reportz["code_patterns"].update(file_report)
                            except:
                                continue
                    else:
                        print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
                        print(f">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]{apka.decompiler_path}")

                # Printing report
                self.print_file_report(file_report_obj=file_report)

    def analyze_dex_file(self):
        if os.path.exists("TargetAPK"):
            self.ScanSource()
        else:
            print(f"{infoS} Decompiling target file...")
            os.system(f"{self.decompiler_path} -q -d TargetAPK \"{self.full_path_file}\"")
            self.ScanSource()

    def get_possible_package_names(self):
        print(f"\n{infoS} Looking for package name...")
        # Handle aapt2 errors and get package_name anyway
        package_name_proc = subprocess.run(f"aapt2 dump packagename \"{self.target_file}\"", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if package_name_proc.returncode == 0:
            package_name = package_name_proc.stdout.decode().strip('\n')
            return package_name
        else:
            try:
                # Get package_name from error message
                package_name = re.findall(r"com.[a-z0-9]*.[a-z0-9]*", package_name_proc.stderr.decode())[0]
                return package_name
            except:
                return None

    def pattern_scanner_ex(self, regex, target_files, target_type, value_array):
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

    def pattern_scanner(self, target_pattern):
        extracted_values = []
        path = f"TargetAPK{path_seperator}sources{path_seperator}"
        fnames = self.recursive_dir_scan(path)
        if fnames != []:
            self.pattern_scanner_ex(regex=target_pattern,
                            target_files=fnames,
                            target_type="sources",
                            value_array=extracted_values
            )
        path = f"TargetAPK{path_seperator}resources{path_seperator}"
        fnames = self.recursive_dir_scan(path)
        if fnames != []:
            self.pattern_scanner_ex(regex=target_pattern,
                            target_files=fnames,
                            target_type="resources",
                            value_array=extracted_values
            )

        if extracted_values != []:
            return extracted_values
        else:
            return []

    # Scan files for url and ip patterns
    def Get_IP_URL(self):
        print(f"\n{infoS} Looking for possible IP address patterns. Please wait...")
        ip_vals = self.pattern_scanner(target_pattern=r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
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
        url_vals = self.pattern_scanner(target_pattern=r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
        if url_vals != []:
            sanitizer = []
            urltable = Table()
            urltable.add_column("[bold green]Extracted URL Values", justify="center")
            for uv in url_vals:
                if str(uv) not in sanitizer:
                    urltable.add_row(str(uv))
                    sanitizer.append(uv)
            print(urltable)
        else:
            print(f"{errorS} There is no URL pattern found!")

    # Permission analyzer
    def Analyzer(self, parsed):
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
                self.reportz["permissions"].append({str(pp): "Risky"})
                danger += 1
            else:
                statistics.add_row(str(pp), "[bold yellow]Info")
                self.reportz["permissions"].append({str(pp): "Info"})
                normal += 1

        # If there is no permission:
        if danger == 0 and normal == 0:
            print("\n[bold white on red]There is no permissions found!\n")
        else:
            print(statistics)

    # Analyzing more deeply
    def DeepScan(self, parsed):
        # Getting features
        featStat = Table()
        featStat.add_column("[bold green]Features", justify="center")
        features = parsed.get_features()
        if features != []:
            for ff in features:
                featStat.add_row(str(ff))
                self.reportz["features"].append(ff)
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
                self.reportz["activities"].append(aa)
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
                self.reportz["services"].append(ss)
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
                self.reportz["receivers"].append(rr)
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
                self.reportz["providers"].append(pp)
            print(provStat)
        else:
            pass

    def GeneralInformation(self, targetAPK, axml_obj):
        print(f"\n{infoS} General Informations about [bold green]{targetAPK}[white]")
        self.reportz["target_file"] = targetAPK

        # Parsing target apk file
        if axml_obj:
            # Lets print!!
            print(f"[bold red]>>>>[white] App Name: [bold green]{axml_obj.get_app_name()}")
            print(f"[bold red]>>>>[white] Package Name: [bold green]{axml_obj.get_package()}")
            self.reportz["app_name"] = axml_obj.get_app_name()
            self.reportz["package_name"] = axml_obj.get_package()
        else:
            print(f"[bold red]>>>>[white] Possible Package Name: [bold green]{package_names}")
            self.reportz["package_name"] = package_names
            self.reportz["app_name"] = None

        # Gathering play store information
        if axml_obj:
            print(f"\n{infoS} Sending query to Google Play Store about target application.")
            try:
                playinf = requests.get(f"https://play.google.com/store/apps/details?id={axml_obj.get_package()}")
                if playinf.ok:
                    print("[bold red]>>>>[white] Google Play Store: [bold green]Found\n")
                    self.reportz["play_store"] = True
                else:
                    print("[bold red]>>>>[white] Google Play Store: [bold red]Not Found\n")
                    self.reportz["play_store"] = None
            except:
                print("\n[bold white on red]An error occured while querying to Google Play Store!\n")
                self.reportz["play_store"] = None
        else:
            print(f"\n{infoS} Sending query to Google Play Store about target application.")
            try:
                playinf = requests.get(f"https://play.google.com/store/apps/details?id={package_names}")
                if playinf.ok:
                    print("[bold red]>>>>[white] Google Play Store: [bold green]Found\n")
                    self.reportz["play_store"] = True
                else:
                    print("[bold red]>>>>[white] Google Play Store: [bold red]Not Found\n")
                    self.reportz["play_store"] = None
            except:
                print("\n[bold white on red]An error occured while querying to Google Play Store!\n")
                self.reportz["play_store"] = None

        if axml_obj:
            print(f"[bold red]>>>>[white] SDK Version: [bold green]{axml_obj.get_effective_target_sdk_version()}")
            print(f"[bold red]>>>>[white] Main Activity: [bold green]{axml_obj.get_main_activity()}")
            self.reportz["sdk_version"] = axml_obj.get_effective_target_sdk_version()
            self.reportz["main_activity"] = axml_obj.get_main_activity()
            try:
                if axml_obj.get_libraries() != []:
                    print("[bold red]>>>>[white] Libraries:")
                    for libs in axml_obj.get_libraries():
                        print(f"[bold magenta]>>[white] {libs}")
                        self.reportz["libraries"].append(libs)
                    print(" ")

                if axml_obj.get_signature_names() != []:
                    print("[bold red]>>>>[white] Signatures:")
                    for sigs in axml_obj.get_signature_names():
                        print(f"[bold magenta]>>[white] {sigs}")
                        self.reportz["signatures"].append(sigs)
                    print(" ")
            except:
                pass
        else:
            self.reportz["sdk_version"] = None
            self.reportz["main_activity"] = None
            self.reportz["libraries"] = None
            self.reportz["signatures"] = None

# Execution
if __name__ == '__main__':
    try:
        # Create object
        apka = APKAnalyzer(target_file=targetAPK)

        # Check for JAR file
        if sys.argv[3] == "JAR":
            apka.PerformJAR()
            sys.exit(0)

        # Check for DEX file
        if sys.argv[3] == "DEX":
            apka.analyze_dex_file()
            sys.exit(0)

        # Get axml object
        try:
            axml_obj = pyaxmlparser.APK(targetAPK)
            # In case of package name parsing issues
            if axml_obj.get_package() == '':
                print(f"\n{errorS} It looks like the target [bold green]AndroidManifest.xml[white] is corrupted!!")
                axml_obj = None
                package_names = apka.get_possible_package_names()
        except:
            print(f"\n{errorS} It looks like the target [bold green]AndroidManifest.xml[white] is corrupted!!")
            axml_obj = None
            package_names = apka.get_possible_package_names()

        # General informations
        apka.GeneralInformation(targetAPK, axml_obj)

        # Parsing target apk for androguard
        try:
            parsed = APK(targetAPK)
        except:
            parsed = None

        if parsed:
            # Permissions side
            apka.Analyzer(parsed)

            # Deep scanner
            apka.DeepScan(parsed)

        # Yara matches
        print(f"\n{infoS} Performing YARA rule matching...")
        apka.yara_rule_scanner(targetAPK, report_object=apka.reportz)

        # Decompiling and scanning libraries
        print(f"\n{infoS} Performing library analysis...")
        try:
            apka.MultiYaraScanner()
        except:
            print("\n[bold white on red]An error occured while decompiling the file. Please check configuration file and modify the [blink]Decompiler[/blink] option.")
            print(f"[bold white]>>> Configuration file path: [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

        # Malware family detection
        print(f"\n{infoS} Performing malware family detection. Please wait!!")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}andro_familydetect.py \"{targetAPK}\""
        os.system(command)

        # Source code analysis zone
        print(f"\n{infoS} Performing source code analysis...")
        apka.ScanSource()

        # IP and URL value scan
        apka.Get_IP_URL()

        # Print reports
        if sys.argv[2] == "True":
            apka.report_writer("android", apka.reportz)
    except KeyboardInterrupt:
        print("\n[bold white on red]An error occured. Press [blink]CTRL+C[/blink] to exit.\n")