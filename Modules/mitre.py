#!/usr/bin/python3

import re
import sys
import json
import subprocess

from .utils import err_exit

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import pefile as pf
except:
    err_exit("Error: >pefile< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Specify target binary
fileName = sys.argv[1]

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

class MitreAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.all_strings = []
        self.find_bytes = 0
        self.mitre_data_windows = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}mitre_for_windows.json"))
        self.windows_api_list = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_categories.json"))
        self.table_contents = {
            "Discovery": [],
            "Privilege Escalation": [],
            "Persistence": [],
            "Collection": [],
            "Credential Access": [],
            "Defense Evasion": []
        }

    def check_target_os(self):
        tos_buf = subprocess.run(["file", self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "PE" in tos_buf.stdout.decode() and "Windows" in tos_buf.stdout.decode():
            return "windows"
        elif "ELF" in tos_buf.stdout.decode():
            return "linux"
        else:
            return None

    def mitre_data_categorization(self, mitre_data):
        # Detect functions and count
        for key in mitre_data:
            for api in mitre_data[key]:
                for funcs in mitre_data[key][api]:
                    for af in mitre_data[key][api]["api_list"]:
                        if self.find_bytes != 0:
                            if af.encode() in self.all_strings:
                                mitre_data[key][api]["score"] += 1
                        else:
                            if af in self.all_strings:
                                mitre_data[key][api]["score"] += 1

        # Parse table contents
        for key in mitre_data:
            for api in mitre_data[key]:
                for funcs in mitre_data[key][api]:
                    if mitre_data[key][api]["score"] > 0:
                        if api not in self.table_contents[key]:
                            self.table_contents[key].append(api)

        # Render tables
        tech_count = 0
        for tech in self.table_contents:
            if self.table_contents[tech] != []:
                mtable = Table()
                mtable.add_column(f"[bold green]{tech}", justify="center")
                for content in self.table_contents[tech]:
                    mtable.add_row(content)
                print(mtable)
                tech_count += 1
        if tech_count == 0:
            print(f"{errorS} There is no technique detected!")

    def extract_windows_api_imports_exports(self):
        print(f"{infoS} Performing Windows API import/export extraction. Please wait...")
        try:
            binaryfile = pf.PE(self.target_file)
            # -- Extract imports
            for imps in binaryfile.DIRECTORY_ENTRY_IMPORT:
                try:
                    for im in imps.imports:
                        if im.name.decode("ascii") not in self.all_strings:
                            self.all_strings.append(im.name.decode("ascii"))
                except:
                    continue
            # -- Extract exports
            for exps in binaryfile.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    if exps.name.decode("ascii") not in self.all_strings:
                        self.all_strings.append(exps.name.decode("ascii"))
                except:
                    continue
        except:
            binary_data = open(fileName, "rb").read()
            for categ in self.windows_api_list:
                for api in self.windows_api_list[categ]["apis"]:
                    try:
                        matcher = re.findall(api.encode(), binary_data, re.IGNORECASE)
                        if matcher != []:
                            if matcher[0] not in self.all_strings:
                                self.all_strings.append(matcher[0])
                                self.find_bytes += 1
                    except:
                        continue

    def perform_windows_mitre(self):
        self.extract_windows_api_imports_exports()
        self.mitre_data_categorization(mitre_data=self.mitre_data_windows)

# Execution
manls = MitreAnalyzer(target_file=fileName)
target_os = manls.check_target_os()
if target_os == "windows":
    manls.perform_windows_mitre()
else:
    print(f"{errorS} MITRE ATT&CK analysis is only for Windows binaries now!")