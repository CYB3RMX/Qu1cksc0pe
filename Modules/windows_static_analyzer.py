#!/usr/bin/python3

import os
import re
import sys
import yara
import json
import sqlite3
import hashlib
import warnings
import binascii
import subprocess
import configparser

from utils import err_exit, get_argv

try:
    from rich import print
    from rich.table import Table
    from rich.progress import track
except:
    err_exit("Error: >rich< module not found.")

try:
    import pefile as pf
except:
    err_exit("Error: >pefile< module not found.")

try:
    warnings.filterwarnings("ignore")
    import clr
except:
    print("Error: >pythonnet< module not found.")
    print(f"[bold red]>>>[white] You can execute: [bold green]sudo apt install mono-complete && pip3 install pythonnet[white]")
    sys.exit(1)

try:
    import floss
    from floss import main
    from floss import strings
except:
    err_exit("Error: >flare-floss< module not found.")

try:
    import vivisect
    vivisect.logging.disable() # Suppressing error messages
except:
    err_exit("Error: >vivisect< module not found.")

try:
    from colorama import Fore, Style
except ModuleNotFoundError as e:
    print("Error: >colorama< module not found.")
    raise e

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

#--------------------------------------------- Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

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

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
fileName = sys.argv[1]

# Loading dnlib.dll
clr.AddReference(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}dnlib.dll")
from dnlib.DotNet import *
from System.IO import *

#--------------------------------------------------------------------- Keywords for categorized scanning
windows_api_list = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_categories.json"))
dotnet_malware_pattern = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}dotnet_malware_patterns.json"))

#--------------------------------------------- Dictionary of Categories
dictCateg = {
    "Registry": [],
    "File": [],
    "Networking/Web": [],
    "Keyboard/Keylogging": [],
    "Process": [],
    "Memory Management": [],
    "Dll/Resource Handling": [],
    "Evasion/Bypassing": [],
    "System/Persistence": [],
    "COMObject": [],
    "Cryptography": [],
    "Information Gathering": [],
    "Other/Unknown": []
}

#------------------------------------ Report structure
winrep = {
    "filename": "",
    "timedatestamp": "",
    "hash_md5": "",
    "hash_sha1": "",
    "hash_sha256": "",
    "imphash": "",
    "all_imports_exports": 0,
    "categorized_imports": 0,
    "categories": {},
    "matched_rules": [],
    "linked_dll": [],
    "pdb_file_name": "",
    "debug_signature": "",
    "sections": {}
}

#------------------------------------ Read and parse config file
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf")

# Perform strings
_ = subprocess.run(f"strings {strings_param} \"{fileName}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
if sys.platform != "win32":
    _ = subprocess.run(f"strings {strings_param} -e l {fileName} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

class WindowsAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.allFuncs = 0
        self.windows_imports_and_exports = []
        self.executable_buffer = open(self.target_file, "rb").read()
        self.all_strings = open("temp.txt", "r").read().split("\n")
        self.blacklisted_patterns = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}dotnet_blacklisted_methods.txt", "r").read().split("\n")
        self.sus_reg_keys = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}suspicious_registry_keys.txt", "r").read().split("\n")
        self.rule_path = conf["Rule_PATH"]["rulepath"]

        # Check for windows file type
        self.exec_type = subprocess.run(["file", self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ".Net" in self.exec_type.stdout.decode():
            print(f"{infoS} File Type: [bold green].NET Executable[white]\n")
            self.dotnet_file_analyzer()
            sys.exit(0)
        elif "MSI Installer" in self.exec_type.stdout.decode():
            print(f"{infoS} File Type: [bold green]Microsoft Software Installer[white]\n")
            self.msi_file_analyzer()
            sys.exit(0)
        else:
            print(f"{infoS} File Type: [bold green]Windows Executable[white]\n")
            self.gather_windows_imports_and_exports()

    def gather_windows_imports_and_exports(self):
        print(f"{infoS} Performing extraction of imports and exports. Please wait...")
        try:
            self.binaryfile = pf.PE(fileName)
            # -- Extract imports
            for imps in self.binaryfile.DIRECTORY_ENTRY_IMPORT:
                try:
                    for im in imps.imports:
                        self.windows_imports_and_exports.append([im.name.decode("ascii"), hex(self.binaryfile.OPTIONAL_HEADER.ImageBase + im.address)]) # For full address and not only offset
                except:
                    continue
            # -- Extract exports
            for exp in self.binaryfile.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    self.windows_imports_and_exports.append([exp.name.decode('utf-8'), hex(self.binaryfile.OPTIONAL_HEADER.ImageBase + exp.address)]) # For full address and not only offset
                except:
                    continue
        except:
            binary_data = open(fileName, "rb").read()
            for index in track(range(len(windows_api_list)), description="Analyzing.."):
                current_categ = list(windows_api_list.keys())[index]
                for api in windows_api_list[current_categ]["apis"]:
                    try:
                        matcher = re.finditer(api.encode(), binary_data, re.IGNORECASE)
                        for pos in matcher:
                            if [api, hex(pos.start())] not in self.windows_imports_and_exports:
                                self.windows_imports_and_exports.append([api, hex(pos.start())])
                    except:
                        continue
        if self.windows_imports_and_exports != []:
            self.api_categorizer()
            self.dictcateg_parser()
        else:
            print(f"{errorS} There is no pattern about function/API imports!\n")

    def api_categorizer(self):
        for win_api in self.windows_imports_and_exports:
            for key in windows_api_list:
                if win_api[0] in windows_api_list[key]["apis"]:
                    if win_api[0] != "":
                        windows_api_list[key]["occurence"] += 1
                        dictCateg[key].append(win_api)
                        self.allFuncs += 1

    def dictcateg_parser(self):
        for key in dictCateg:
            if dictCateg[key] != []:
                # More important categories
                if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                    tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
                else:
                    tables = Table()
                
                # Printing zone
                tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
                tables.add_column("Address", justify="center")
                winrep["categories"].update({key: []})
                for func in dictCateg[key]:
                    if func[0] == "":
                        pass
                    else:
                        tables.add_row(f"[bold red]{func[0]}", f"[bold red]{func[1]}")
                        winrep["categories"][key].append(func)
                print(tables)

    def dll_files(self):
        try:
            dllTable = Table()
            dllTable.add_column("Linked DLL Files", style="bold green", justify="center")
            for items in self.binaryfile.DIRECTORY_ENTRY_IMPORT:
                dlStr = str(items.dll.decode())
                dllTable.add_row(f"{dlStr}", style="bold red")
                winrep["linked_dll"].append(dlStr)
            print(dllTable)
        except:
            pass

    def gather_timestamp(self):
        mydict = self.binaryfile.dump_dict()
        tempstr = mydict["FILE_HEADER"]["TimeDateStamp"]["Value"][11:].replace("[", "")
        datestamp = tempstr.replace("]", "")
        return datestamp

    def scan_for_special_artifacts(self):
        switch = 0
        print(f"\n{infoS} Performing special artifact detection. Please wait...")
        spec_table = Table()
        spec_table.add_column("[bold green]Artifact Names", justify="center")
        spec_table.add_column("[bold green]Patterns", justify="center")
        spec_table.add_column("[bold green]Occurence", justify="center")
        special = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}special_artifact_patterns.json"))
        for spec in special:
            for pat in special[spec]["patterns"]:
                ofs = re.findall(pat.encode(), self.executable_buffer)
                if ofs != []:
                    spec_table.add_row(spec, pat, str(len(ofs)))
                    switch += 1
        if switch != 0:
            print(spec_table)
        else:
            print(f"{errorS} There is no special artifact pattern found!\n")

    def check_for_valid_registry_keys(self):
        print(f"\n{infoS} Looking for: [bold green]Windows Registry Key[white]")
        # Defining table and patterns
        reg_table = Table()
        reg_table.add_column("[bold green]Registry Keys", justify="center")
        reg_key_array = [r"SOFTWARE\\[A-Za-z0-9_\\/\\\s]*", r"HKCU_[A-Za-z0-9_\\/\\\s]*", r"HKLM_[A-Za-z0-9_\\/\\\s]*", r"SYSTEM\\[A-Za-z0-9_\\/\\\s]*"]

        # Array for holding keys
        registry_keys = []

        # Search for keys in file buffer
        for key in reg_key_array:
            chk = re.findall(key, str(self.all_strings), re.IGNORECASE) # "re.IGNORECASE" in case of non case sensitive values
            if chk != []:
                for pattern in chk:
                    if len(pattern) > 10 and pattern not in registry_keys:
                        registry_keys.append(pattern)
        # Print output
        if registry_keys != []:
            for reg in registry_keys:
                if reg.upper() in self.sus_reg_keys:
                    reg_table.add_row(f"[bold yellow]{reg} (SUSPICIOUS!)")
                else:
                    reg_table.add_row(reg)
            print(reg_table)
        else:
            print(f"{errorS} There is no pattern about registry keys!\n")

    def check_for_interesting_stuff(self):
        print(f"\n{infoS} Looking for: [bold green]Interesting String Patterns[white]")
        # Defining table and patterns
        stuff_table = Table()
        stuff_table.add_column("[bold green]Interesting Patterns", justify="center")
        interesting_stuff = [
            r'\b[a-zA-Z0-9_\-\\/:]+\.pdb', r'\b[a-zA-Z0-9_\-\\/:]+\.vbs', 
            r'\b[a-zA-Z0-9_\-\\/:]+\.vba', r'\b[a-zA-Z0-9_\-\\/:]+\.vbe', 
            r'\b[a-zA-Z0-9_\-\\/:]+\.exe', r'\b[a-zA-Z0-9_\-\\/:]+\.ps1',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dll', r'\b[a-zA-Z0-9_\-\\/:]+\.bat',
            r'\b[a-zA-Z0-9_\-\\/:]+\.cmd', r'\b[a-zA-Z0-9_\-\\/:]+\.tmp',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dmp', r'\b[a-zA-Z0-9_\-\\/:]+\.cfg',
            r'\b[a-zA-Z0-9_\-\\/:]+\.lnk', r'\b[a-zA-Z0-9_\-\\/:]+\.config',
            r'\b[a-zA-Z0-9_\-\\/:]+\.7z', r'\b[a-zA-Z0-9_\-\\/:]+\.docx',
            r"SeLockMemoryPrivilege", r"SeShutdownPrivilege",
            r"SeChangeNotifyPrivilege", r"SeUndockPrivilege",
            r"SeIncreaseWorkingSetPrivilege", r"SeTimeZonePrivilege",
            r"Select \* from \w+", r"VirtualBox", r"vmware", r"syscall\.[a-zA-Z0-9]+"
        ]

        # Array for holding string values
        intstf = []

        # Search for keys in file buffer
        for key in track(range(len(interesting_stuff)), description="Analyzing..."):
            chk = re.findall(interesting_stuff[key], str(self.all_strings), re.IGNORECASE) # "re.IGNORECASE" in case of non case sensitive values
            if chk != []:
                for pattern in chk:
                    if pattern not in intstf:
                        intstf.append(pattern)

        # Print output
        if intstf != []:
            for stf in intstf:
                if (stf in interesting_stuff) or (".cmd" in stf or ".bat" in stf or ".exe" in stf or "syscall" in stf) or ("Select" in stf):
                    stuff_table.add_row(f"[bold red]{stf}[white]")
                else:
                    stuff_table.add_row(stf)
            print(stuff_table)
        else:
            print(f"{errorS} There is no pattern about interesting string values!\n")

    def detect_embedded_PE(self):
        print(f"\n{infoS} Performing embedded PE file detection...")
        mz_header = "4D5A9000"
        valid_offsets = []
        matches = re.finditer(binascii.unhexlify(mz_header), self.executable_buffer)
        for pos in matches:
            if pos.start() != 0:
                valid_offsets.append(pos.start())
        if valid_offsets != []:
            print(f"{infoS} There is possible [bold red]{len(valid_offsets)}[white] embedded PE file found!")
            print(f"{infoS} Execute: [bold green]python qu1cksc0pe.py --file {fileName} --sigcheck[white] to extract them!\n")
        else:
            print(f"{errorS} There is no embedded PE file!\n")

    def section_parser(self):
        peStatistics = Table(title="* Informations About Sections *", title_style="bold italic cyan", title_justify="center")
        peStatistics.add_column("Section Name", justify="center")
        peStatistics.add_column("Virtual Size", justify="center")
        peStatistics.add_column("Virtual Address", justify="center")
        peStatistics.add_column("Size Of Raw Data", justify="center")
        peStatistics.add_column("Pointer to Raw Data", justify="center")
        peStatistics.add_column("Entropy", justify="center")

        # Parsing sections
        for sect in self.binaryfile.sections:
            try:
                if sect.get_entropy() >= 7:
                    peStatistics.add_row(
                        str(sect.Name.decode().rstrip('\x00')),
                        f"{hex(sect.Misc_VirtualSize)}",
                        f"{hex(sect.VirtualAddress)}",
                        f"{hex(sect.SizeOfRawData)}",
                        f"{hex(sect.PointerToRawData)}",
                        f"[bold red]{sect.get_entropy()} [i]Possible obfuscation!![/i]"
                    )
                else:
                    peStatistics.add_row(
                        str(sect.Name.decode().rstrip('\x00')),
                        f"{hex(sect.Misc_VirtualSize)}",
                        f"{hex(sect.VirtualAddress)}",
                        f"{hex(sect.SizeOfRawData)}",
                        f"{hex(sect.PointerToRawData)}",
                        str(sect.get_entropy())
                    )
                winrep["sections"].update(
                    {
                        str(sect.Name.decode().rstrip('\x00')):
                        {
                            "virtualsize": hex(sect.Misc_VirtualSize),
                            "virtualaddress": hex(sect.VirtualAddress),
                            "sizeofrawdata": hex(sect.SizeOfRawData),
                            "pointertorawdata": hex(sect.PointerToRawData),
                            "entropy": str(sect.get_entropy())
                        }
                    }
                )
            except:
                continue
        print(peStatistics)

    def decode_section(self, viv_obj, fvas_to_emulate):
        decoded_strings = floss.main.decode_strings(viv_obj, fvas_to_emulate, 4)
        if decoded_strings != []:
            ss_table = Table()
            ss_table.add_column("[bold green]Decoded Strings", justify="center")
            for ss in decoded_strings:
                ss_table.add_row(ss.string)
            print(ss_table)
        else:
            print(f"\n{errorS} There is no decoded string value found!")

    def decode_strings_floss(self, viv_obj, decode_features):
        top_functions = floss.main.get_top_functions(decode_features, 20)
        fvas_to_emulate = floss.main.get_function_fvas(top_functions)
        fvas_tight_funcs = floss.main.get_tight_function_fvas(decode_features)
        fvas_to_emulate = floss.main.append_unique(fvas_to_emulate, fvas_tight_funcs)
        if len(fvas_to_emulate) >= 150:
            print(f"\n{infoS} Looks like we have [bold red]{len(fvas_to_emulate)}[white] functions to emulate!!")
            choice = str(input(f"\n{infoC} Do you want to emulate functions and decode strings anyway? [Y/n]: "))
            if choice == "Y" or choice == "y":
                self.decode_section(viv_obj, fvas_to_emulate)
        else:
            self.decode_section(viv_obj, fvas_to_emulate)

    def analyze_via_viv(self):
        print(f"\n{infoS} Performing analysis via Vivisect and Floss...")
        viv = vivisect.VivWorkspace() # Creating workspace
        print(f"{infoS} Initializing [bold green]viv.analyze[white]. Please wait...")
        viv.loadFromFile(self.target_file)
        viv.analyze()

        # Extract strings via flare-floss
        print(f"{infoS} Performing [bold green]stack string[white] extraction. Please wait...")
        selected_functions = floss.main.select_functions(viv, None)
        stack_strings = floss.main.extract_stackstrings(viv, selected_functions, 4)
        if stack_strings != []:
            ss_table = Table()
            ss_table.add_column("[bold green]Extracted Stack Strings", justify="center")
            for ss in stack_strings:
                ss_table.add_row(ss.string)
            print(ss_table)
        else:
            print(f"\n{errorS} There is no stack string value found!\n")

        # Extract tight strings
        print(f"\n{infoS} Performing [bold green]tight string[white] extraction. Please wait...")
        decode_features, _ = floss.main.find_decoding_function_features(viv, viv.getFunctions())
        tight_loops = floss.main.get_functions_with_tightloops(decode_features)
        tight_strings = floss.main.extract_tightstrings(viv, tight_loops, 4)
        if tight_strings != []:
            ss_table = Table()
            ss_table.add_column("[bold green]Extracted Tight Strings", justify="center")
            for ss in tight_strings:
                ss_table.add_row(ss.string)
            print(ss_table)
        else:
            print(f"\n{errorS} There is no tight string value found!\n")

        # String decoding via function emulation
        print(f"\n{infoS} Performing string decode via function emulation. Please wait...")
        self.decode_strings_floss(viv, decode_features)

        # Get functions
        print(f"\n{infoS} Extracting and parsing function informations. Please wait...")
        funcz = viv.getFunctions()

        # Perform basic analysis against functions
        # -- Create table
        fun_table = Table()
        fun_table.add_column("[bold green]Function Name", justify="center")
        fun_table.add_column("[bold green]Size", justify="center")
        fun_table.add_column("[bold green]Offset", justify="center")
        fun_table.add_column("[bold green]Xrefs From This Address", justify="center")
        fun_table.add_column("[bold green]Xrefs To This Address", justify="center")

        # -- Parse functions
        print(f"[bold magenta]>>>[white] Number of functions: [bold green]{len(funcz)}[white]")
        for fun in track(range(len(funcz)), description="Processing..."):
            try:
                fn_name = viv.getName(funcz[fun])
                fn_size = viv.getCodeBlock(funcz[fun])[1]
                xrf_fr = len(viv.getXrefsFrom(funcz[fun]))
                xrf_to = len(viv.getXrefsTo(funcz[fun]))

                # -- If we have function size larger than 200 there is must be something!
                if fn_size >= 200:
                    table_str = f"[bold red]{fn_size} Attention!![white]"
                else:
                    table_str = str(fn_size)

                # -- Check for xrefs_fr
                if xrf_fr != 0:
                    xrf_fr_str = f"[bold red]{xrf_fr}[white]"
                else:
                    xrf_fr_str = str(xrf_fr)

                # -- Check for xrefs_to
                if xrf_to != 0:
                    xrf_to_str = f"[bold red]{xrf_to}[white]"
                else:
                    xrf_to_str = str(xrf_to)

                fun_table.add_row(
                    fn_name,
                    table_str,
                    str(hex(fun)),
                    xrf_fr_str,
                    xrf_to_str
                )
            except:
                continue
        print(fun_table)

    def hash_calculator(self, filename, report_object):
        hashmd5 = hashlib.md5()
        hashsha1 = hashlib.sha1()
        hashsha256 = hashlib.sha256()
        try:
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashmd5.update(chunk)
            ff.close()
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha1.update(chunk)
            ff.close()
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha256.update(chunk)
            ff.close()
        except:
            pass
        print(f"[bold red]>>>>[white] MD5: [bold green]{hashmd5.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA1: [bold green]{hashsha1.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA256: [bold green]{hashsha256.hexdigest()}")
        report_object["hash_md5"] = hashmd5.hexdigest()
        report_object["hash_sha1"] = hashsha1.hexdigest()
        report_object["hash_sha256"] = hashsha256.hexdigest()

    def yara_rule_scanner(self, filename, report_object):
        yara_match_indicator = 0
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

    def report_writer(self, target_os, report_object):
        with open(f"sc0pe_{target_os}_{winrep['hash_sha256']}_report.json", "w") as rp_file:
            json.dump(report_object, rp_file, indent=4)
        print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_{target_os}_{winrep['hash_sha256']}_report.json\n")

    def statistics_method(self):
        datestamp = self.gather_timestamp()
        print(f"\n[bold green]-> [white]Statistics for: [bold green][i]{self.target_file}[/i]")
        print(f"[bold magenta]>>[white] Time Date Stamp: [bold green][i]{datestamp}[/i]")
        winrep["filename"] = self.target_file
        winrep["timedatestamp"] = datestamp
        self.hash_calculator(self.target_file, winrep)
        print(f"[bold magenta]>>[white] IMPHASH: [bold green]{self.binaryfile.get_imphash()}")
        winrep["imphash"] = self.binaryfile.get_imphash()

        # printing all function statistics
        statistics = Table()
        statistics.add_column("Categories", justify="center")
        statistics.add_column("Number of Functions or Strings", justify="center")
        statistics.add_row("[bold green][i]All Imports,Exports[/i]", f"[bold green]{len(self.windows_imports_and_exports)}")
        statistics.add_row("[bold green][i]Categorized Imports[/i]", f"[bold green]{self.allFuncs}")
        winrep["all_imports_exports"] = len(self.windows_imports_and_exports)
        winrep["categorized_imports"] = self.allFuncs
        for key in windows_api_list:
            if windows_api_list[key]["occurence"] == 0:
                pass
            else:
                if key == "Keyboard/Keylogging" or key == "Evasion/Bypassing" or key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                    statistics.add_row(f"[bold yellow]{key}", f"[bold red]{windows_api_list[key]['occurence']}")
                else:
                    statistics.add_row(key, str(windows_api_list[key]["occurence"]))
        print(statistics)

        # Warning about obfuscated file
        if self.allFuncs < 20:
            print("[bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
            print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
            sys.exit(0)

    def get_debug_information(self):
        try:
            debug_buffer = self.binaryfile.DIRECTORY_ENTRY_DEBUG[0].entry
            pdb_name = debug_buffer.PdbFileName.decode().strip("\x00")
            print(f"\n{infoS} Parsing DEBUG information...")
            print(f"[bold magenta]>>>[white] PDB Name: [bold green]{pdb_name}")
            winrep["pdb_file_name"] = pdb_name
            print(f"[bold magenta]>>>[white] Debug Signature: [bold green]{debug_buffer.Signature_String}")
            winrep["debug_signature"] = debug_buffer.Signature_String

            # Check if the signature string in our database
            print(f"\n{infoS} Checking the target PDB in our malicious PDB database...")
            sig_base = sqlite3.connect(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_debug_signatures")
            sig_cursor = sig_base.cursor()

            # Create table for pretty output
            debug_table = Table(title="* Associated Signatures *", title_justify="center", title_style="bold italic cyan")
            debug_table.add_column("[bold green]PDB Name", justify="center")
            debug_table.add_column("[bold green]Signature", justify="center")

            # 1. Check signature first
            exist = sig_cursor.execute(f"SELECT * FROM debug_signatures where signature=\"{debug_buffer.Signature_String}\"").fetchall()
            if exist:
                debug_table.add_row(f"[bold red]{exist[0][0]}[white]", f"[bold red]{exist[0][1]}[white]")
                print(debug_table)
            else:
                # 2. Check pdb name
                # Now we use "LIKE" statement for better detection capability
                if "\\" in pdb_name:
                    pdb_name_query = pdb_name.split("\\")[-1]
                else:
                    pdb_name_query = pdb_name
                exist = sig_cursor.execute(f"SELECT * FROM debug_signatures where pdb_name like \'%{pdb_name_query}%\'").fetchall()
                if exist:
                    for answ in exist:
                        debug_table.add_row(f"[bold red]{answ[0]}[white]", f"[bold red]{answ[1]}[white]")
                    print(debug_table)
        except AttributeError:
            print(f"\n{errorS} There is no information about DEBUG section!")
        except UnicodeDecodeError:
            print(f"\n{errorS} PDB file name might be corrupted!")
            
    def dotnet_file_analyzer(self):
        print(f"{infoS} Performing .NET analysis...")

        self.gather_windows_imports_and_exports()

        # Load the assembly using dnlib
        assembly = AssemblyDef.Load(self.target_file)

        class_names = []
        print(f"\n{infoS} Extracting and analyzing classes...")
        for module in assembly.Modules:
            for typ in module.Types:
                if "<" not in typ.FullName:
                    class_names.append(typ.FullName)
                    dotnet_table = Table()
                    dotnet_table.add_column(f"Methods in Class: [bold green]{typ.FullName}[white]", justify="center")
                    methodz = []
                    for met in typ.Methods:
                        if str(met.Name) not in methodz:
                            methodz.append(str(met.Name))
                            if str(met.Name) in self.blacklisted_patterns:
                                dotnet_table.add_row(f"[bold red]{str(met.Name)}[white]")
                            else:
                                dotnet_table.add_row(str(met.Name))
                    print(dotnet_table)

        print(f"\n{infoS} Performing pattern analysis...")
        fswc = 0
        dot_fam = Table()
        dot_fam.add_column(f"[bold green]Malware Family/Artifact", justify="center")
        dot_fam.add_column(f"[bold green]Pattern Occurence", justify="center")
        for family in dotnet_malware_pattern:
            for dotp in dotnet_malware_pattern[family]["patterns"]:
                matcher = re.findall(dotp, str(class_names), re.IGNORECASE)
                if matcher != []:
                    dotnet_malware_pattern[family]["occurence"] += len(matcher)
            if dotnet_malware_pattern[family]["occurence"] != 0:
                dot_fam.add_row(family, str(dotnet_malware_pattern[family]["occurence"]))
                fswc += 1
        if fswc != 0:
            print(dot_fam)
        else:
            print(f"{errorS} Couldn\'t detect any pattern. This file might be obfuscated!\n")

        self.check_for_valid_registry_keys()
        self.check_for_interesting_stuff()
        self.detect_embedded_PE()

        # Get debug information
        self.get_debug_information()

        try:
            self.analyze_via_viv()
        except:
            print(f"{errorS} An error occured while analyzing functions! This file might have some [bold red]anti-analysis[white] technique!")

        # Try to parse target via pefile for get more information
        try:
            print(f"\n{infoS} Parsing section information...")
            self.section_parser()

            print(f"\n{infoS} Checking linked DLL files...")
            self.dll_files()
        except:
            pass

        # Yara rule match
        print(f"\n{infoS} Performing YARA rule matching...")
        self.yara_rule_scanner(fileName, report_object=winrep)
        self.statistics_method()
        # Print reports
        if get_argv(2) == "True":
            self.report_writer("windows", winrep)

    def msi_file_analyzer(self):
        print(f"{infoS} Performing Microsoft Software Installer analysis...\n")
        self.gather_windows_imports_and_exports()
        self.check_for_valid_registry_keys()
        self.check_for_interesting_stuff()
        self.detect_embedded_PE()
        # Yara rule match
        print(f"\n{infoS} Performing YARA rule matching...")
        self.yara_rule_scanner(fileName, report_object=winrep)

# Execute
windows_analyzer = WindowsAnalyzer(target_file=str(fileName))
windows_analyzer.dll_files()
windows_analyzer.get_debug_information()
windows_analyzer.scan_for_special_artifacts()
windows_analyzer.check_for_valid_registry_keys()
windows_analyzer.check_for_interesting_stuff()
windows_analyzer.detect_embedded_PE()

# Yara rule match
print(f"\n{infoS} Performing YARA rule matching...")
windows_analyzer.yara_rule_scanner(fileName, report_object=winrep)

windows_analyzer.section_parser()

try:
    windows_analyzer.analyze_via_viv()
except:
    print(f"{errorS} An error occured while analyzing functions! This file might have some [bold red]anti-analysis[white] technique!")

windows_analyzer.statistics_method()

# Print reports
if get_argv(2) == "True":
    windows_analyzer.report_writer("windows", winrep)
