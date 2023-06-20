#!/usr/bin/python3

import os
import re
import sys
import json
import warnings
import subprocess

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    import zepu1chr3
except:
    print("Error: >zepu1chr3< module not found.")
    sys.exit(1)

try:
    warnings.filterwarnings("ignore")
    import clr
except:
    print("Error: >pythonnet< module not found.")
    print(f"[bold red]>>>[white] You can execute: [bold green]sudo apt install mono-complete && pip3 install pythonnet[white]")
    sys.exit(1)

#--------------------------------------------- Getting name of the file for statistics
fileName = str(sys.argv[1])

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
# Using helper library
if os.path.exists("/usr/lib/python3/dist-packages/sc0pe_helper.py"):
    from sc0pe_helper import Sc0peHelper
    sc0pehelper = Sc0peHelper(sc0pe_path)
else:
    print(f"{errorS} [bold green]sc0pe_helper[white] library not installed. You need to execute [bold green]setup.sh[white] script!")
    sys.exit(1)

# Loading dnlib.dll
clr.AddReference(f"{sc0pe_path}/Systems/Windows/dnlib.dll")
from dnlib.DotNet import *
from System.IO import *

#--------------------------------------------- Gathering all function imports from binary
zep = zepu1chr3.Binary()
tfl = zep.File(fileName)
pe = pf.PE(fileName)
allStrings = []
try:
    binaryfile = pf.PE(fileName)
    for imps in binaryfile.DIRECTORY_ENTRY_IMPORT:
        try:
            for im in imps.imports:
                allStrings.append([im.name.decode("ascii"), hex(binaryfile.OPTIONAL_HEADER.ImageBase + im.address)]) # For full address and not only offset
        except:
            continue
except:
    for imps in zep.GetImports(tfl):
        try:
            allStrings.append(imps["realname"], imps["offset"])
        except:
            continue

# Get exports
try:
    binaryfile = pf.PE(fileName)
    for exp in binaryfile.DIRECTORY_ENTRY_EXPORT.symbols:
        try:
            allStrings.append([exp.name.decode('utf-8'), hex(binaryfile.OPTIONAL_HEADER.ImageBase + exp.address)]) # For full address and not only offset

        except:
            continue
except:
    pass

# Get number of functions via radare2
try:
    num_of_funcs = len(zep.GetFunctions(tfl))
except:
    num_of_funcs = None

#--------------------------------------------------------------------- Keywords for categorized scanning
windows_api_list = json.load(open(f"{sc0pe_path}/Systems/Windows/windows_api_categories.json"))
dotnet_malware_pattern = json.load(open(f"{sc0pe_path}/Systems/Windows/dotnet_malware_patterns.json"))

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
    "all_imports": 0,
    "categorized_imports": 0,
    "number_of_functions": 0,    
    "categories": {},
    "matched_rules": [],
    "linked_dll": [],
    "sections": {}
}

#------------------------------------ Defining function
class WindowsAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.allFuncs = 0
        self.import_indicator = 0
        self.executable_buffer = open(self.target_file, "rb").read()
        self.interesting_stuff = [
            r"[a-zA-Z0-9_.]*pdb", r"[a-zA-Z0-9_.]*vbs", 
            r"[a-zA-Z0-9_.]*vba", r"[a-zA-Z0-9_.]*vbe", 
            r"[a-zA-Z0-9_.]*exe", r"[a-zA-Z0-9_.]*ps1",
            r"[a-zA-Z0-9_.]*dll", r"[a-zA-Z0-9_.]*bat",
            r"[a-zA-Z0-9_.]*cmd", r"[a-zA-Z0-9_.]*tmp",
            r"[a-zA-Z0-9_.]*dmp", r"[a-zA-Z0-9_.]*cfg",
            r"[a-zA-Z0-9_.]*lnk", r"[a-zA-Z0-9_.]*config"
        ]
        self.int_stf = {
            "offsets": [],
            "interesting_stuff": []
        }
        self.exec_type = subprocess.run(["file", self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ".Net" in self.exec_type.stdout.decode():
            self.dotnet_file_analyzer()
            sys.exit(0)

    def api_categorizer(self):
        for win_api in allStrings:
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
                        winrep["categories"][key].append(func[0])
                        self.import_indicator += 1
                print(tables)

        # If there is no function imported in target executable
        if self.import_indicator == 0:
            print("[bold white on red]There is no function/API imports found.")
            print("[magenta]>>[white] Try [bold green][i]--packer[/i] [white]or [bold green][i]--lang[/i] [white]to see additional info about target file.\n")

    def dll_files(self):
        try:
            dllTable = Table()
            dllTable.add_column("Linked DLL Files", style="bold green")
            for items in binaryfile.DIRECTORY_ENTRY_IMPORT:
                dlStr = str(items.dll.decode())
                dllTable.add_row(f"{dlStr}", style="bold red")
                winrep["linked_dll"].append(dlStr)
            print(dllTable)
        except:
            pass

    def gather_timestamp(self):
        mydict = pe.dump_dict()
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
        special = json.load(open(f"{sc0pe_path}/Systems/Multiple/special_artifact_patterns.json"))
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

    def check_for_registry_keys_and_interesting_stuff(self):
        reg_table = Table()
        reg_table.add_column("[bold green]Offsets", justify="center")
        reg_table.add_column("[bold green]Registry Keys", justify="center")
        reg_key_array = [r"SOFTWARE\\[A-Za-z0-9_\\]*", r"HKCU_[A-Za-z0-9_\\]*", r"HKLM_[A-Za-z0-9_\\]*", r"SYSTEM\\[A-Za-z0-9_\\]*"]

        stuff_table = Table()
        stuff_table.add_column("[bold green]Offsets", justify="center")
        stuff_table.add_column("[bold green]Interesting Patterns", justify="center")

        # First check for keys about software
        found_keys = {
            "offsets": [],
            "registry_keys": []
        }
        self.reg_interest_check(reg_key_array, found_keys, reg_table, "registry_keys")
        self.reg_interest_check(self.interesting_stuff, self.int_stf, stuff_table, "interesting_stuff")

    def reg_interest_check(self, pattern_array, target_dict, table_obj, stuff_type):
        self.pattern_array = pattern_array
        self.target_dict = target_dict
        self.table_obj = table_obj
        self.stuff_type = stuff_type

        for key in self.pattern_array:
            chk = re.finditer(key.encode(), self.executable_buffer)
            for rr in chk:
                if len(rr.group()) > 10 and self.stuff_type == "registry_keys":
                    self.target_dict["offsets"].append(rr.start())
                    self.target_dict[stuff_type].append(rr.group())
                elif b"." in rr.group():
                    self.target_dict["offsets"].append(rr.start())
                    self.target_dict[stuff_type].append(rr.group())
                else:
                    pass
        if self.target_dict["offsets"] != []:
            if self.stuff_type == "registry_keys":
                print(f"\n{infoS} Looks like we found patterns about registry keys. Attempting to extraction...")
            else:
                print(f"\n{infoS} Looks like we found patterns about interesting stuff. Attempting to locate...")
            for ofs, key in zip(self.target_dict["offsets"], self.target_dict[stuff_type]):
                self.table_obj.add_row(str(hex(ofs)), key.decode())
            print(self.table_obj)

    def section_parser(self):
        peStatistics = Table(title="* Informations About Sections *", title_style="bold italic cyan", title_justify="center")
        peStatistics.add_column("Section Name", justify="center")
        peStatistics.add_column("Virtual Size", justify="center")
        peStatistics.add_column("Virtual Address", justify="center")
        peStatistics.add_column("Size Of Raw Data", justify="center")
        peStatistics.add_column("Pointer to Raw Data", justify="center")
        peStatistics.add_column("Entropy", justify="center")

        # Parsing sections
        for sect in pe.sections:
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

    def statistics_method(self):
        datestamp = self.gather_timestamp()
        print(f"\n[bold green]-> [white]Statistics for: [bold green][i]{self.target_file}[/i]")
        print(f"[bold magenta]>>[white] Time Date Stamp: [bold green][i]{datestamp}[/i]")
        winrep["filename"] = self.target_file
        winrep["timedatestamp"] = datestamp
        sc0pehelper.hash_calculator(self.target_file, winrep)
        print(f"[bold magenta]>>[white] IMPHASH: [bold green]{binaryfile.get_imphash()}")
        winrep["imphash"] = binaryfile.get_imphash()

        # printing all function statistics
        statistics = Table()
        statistics.add_column("Categories", justify="center")
        statistics.add_column("Number of Functions or Strings", justify="center")
        statistics.add_row("[bold green][i]All Imports,Exports[/i]", f"[bold green]{len(allStrings)}")
        statistics.add_row("[bold green][i]Categorized Imports[/i]", f"[bold green]{self.allFuncs}")
        statistics.add_row("[bold green][i]Number of Functions[/i]", f"[bold green]{num_of_funcs}")
        winrep["all_imports_exports"] = len(allStrings)
        winrep["categorized_imports"] = self.allFuncs
        winrep["number_of_functions"] = num_of_funcs
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

    def dotnet_file_analyzer(self):
        print(f"{infoS} Performing .NET analysis...")

        # Load the assembly using dnlib
        assembly = AssemblyDef.Load(self.target_file)

        class_names = []
        for module in assembly.Modules:
            for typ in module.Types:
                if "<Module>" not in typ.FullName:
                    class_names.append(typ.FullName)
                    dotnet_table = Table()
                    dotnet_table.add_column(f"Methods in Class: [bold green]{typ.FullName}[white]", justify="center")
                    methodz = []
                    for met in typ.Methods:
                        if str(met.Name) not in methodz:
                            methodz.append(str(met.Name))
                            dotnet_table.add_row(str(met.Name))
                    print(dotnet_table)

        print(f"\n{infoS} Performing pattern analysis...")
        fswc = 0
        dot_fam = Table()
        dot_fam.add_column(f"[bold green]Malware Family/Artifact", justify="center")
        dot_fam.add_column(f"[bold green]Pattern Occurence", justify="center")
        for family in dotnet_malware_pattern:
            for dotp in dotnet_malware_pattern[family]["patterns"]:
                if dotp in class_names:
                    dotnet_malware_pattern[family]["occurence"] += 1
            if dotnet_malware_pattern[family]["occurence"] != 0:
                dot_fam.add_row(family, str(dotnet_malware_pattern[family]["occurence"]))
                fswc += 1
        if fswc != 0:
            print(dot_fam)
        else:
            print(f"{errorS} Couldn\'t detect any pattern. This file might be obfuscated!\n")

        stuff_table = Table()
        stuff_table.add_column("[bold green]Offsets", justify="center")
        stuff_table.add_column("[bold green]Interesting Patterns", justify="center")
        self.reg_interest_check(self.interesting_stuff, self.int_stf, stuff_table, "interesting_stuff")

# Execute
windows_analyzer = WindowsAnalyzer(target_file=fileName)
windows_analyzer.api_categorizer()
windows_analyzer.dictcateg_parser()
windows_analyzer.dll_files()
windows_analyzer.scan_for_special_artifacts()
windows_analyzer.check_for_registry_keys_and_interesting_stuff()

# Yara rule match
print(f"\n{infoS} Performing YARA rule matching...")
sc0pehelper.yara_rule_scanner("windows", fileName, config_path=f"{sc0pe_path}/Systems/Windows/windows.conf", report_object=winrep)

windows_analyzer.section_parser()
windows_analyzer.statistics_method()

# Print reports
if sys.argv[2] == "True":
    sc0pehelper.report_writer("windows", winrep)