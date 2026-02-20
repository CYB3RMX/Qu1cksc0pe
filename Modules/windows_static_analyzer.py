#!/usr/bin/python3

import os
import re
import sys
import json
import sqlite3
import binascii
import subprocess
import configparser
from utils.helpers import err_exit, get_argv, save_report
from analysis.multiple.multi import perform_strings, calc_hashes, yara_rule_scanner

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
    import dnfile
except:
    dnfile = None

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
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"
else:
    pass

#--------------------------------------------- Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(".path_handler", "r").read().strip()
except Exception:
    # Backwards-compat: allow running without setup, using repo root as base.
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

#--------------------------------------------------------------------- Keywords for categorized scanning
windows_api_list = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_categories.json"))
dotnet_malware_pattern = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}dotnet_malware_patterns.json"))


# --- .NET helpers (dnfile)
def _dn_fullname(row):
    if row is None:
        return ""
    ns = getattr(row, "TypeNamespace", "") or ""
    name = getattr(row, "TypeName", "") or ""
    ns = str(ns).strip()
    name = str(name).strip()
    if ns and name:
        return f"{ns}.{name}"
    return name

def _dn_extends_fullname(typ):
    ext = getattr(typ, "Extends", None)
    row = getattr(ext, "row", None)
    return _dn_fullname(row)

def _dn_is_interface(typ):
    # ECMA-335 TypeAttributes.ClassSemanticsMask: 0x20 == Interface
    try:
        return (int(getattr(typ, "Flags", 0)) & 0x20) != 0
    except Exception:
        return False

def _dn_kind(typ):
    """
    Best-effort type classification based on flags + base type.
    We primarily use this to exclude interop structs/enums which create noisy/empty tables.
    """
    if _dn_is_interface(typ):
        return "interface"
    base = _dn_extends_fullname(typ)
    if base == "System.Enum":
        return "enum"
    if base == "System.ValueType":
        return "struct"
    if base == "System.MulticastDelegate":
        return "delegate"
    return "class"

# Reverse index for fast categorization (api -> category). Built once at import time.
_API_TO_CATEGORY = {}
_API_LOWER_TO_API_AND_CATEGORY = {}
for _cat in windows_api_list:
    for _api in windows_api_list[_cat].get("apis", []):
        if _api not in _API_TO_CATEGORY:
            _API_TO_CATEGORY[_api] = _cat
        _k = str(_api).lower()
        if _k not in _API_LOWER_TO_API_AND_CATEGORY:
            _API_LOWER_TO_API_AND_CATEGORY[_k] = (_api, _cat)

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
    "interesting_string_patterns": [],
    "matched_rules": [],
    "linked_dll": [],
    "pdb_file_name": "",
    "debug_signature": "",
    "sections": {}
}

#------------------------------------ Read and parse config file
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf", encoding="utf-8-sig")

class WindowsAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.allFuncs = 0
        self.windows_imports_and_exports = []
        self.binaryfile = None
        self.executable_buffer = open(self.target_file, "rb").read()
        self.all_strings = perform_strings(self.target_file)
        self.blacklisted_patterns = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}dotnet_blacklisted_methods.txt", "r").read().split("\n")
        self.sus_reg_keys = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}suspicious_registry_keys.txt", "r").read().split("\n")
        self.rule_path = conf["Rule_PATH"]["rulepath"]

        # Check for windows file type
        self.exec_type = subprocess.run(["file", self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.exec_type_str = self.exec_type.stdout.decode(errors="ignore")
        self.is_dotnet = (".net" in self.exec_type_str.lower()) or ("mono/.net" in self.exec_type_str.lower())
        if self.is_dotnet:
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

    def ensure_binaryfile(self, parse_data_dirs=False):
        if self.binaryfile is None:
            try:
                self.binaryfile = pf.PE(self.target_file, fast_load=True)
            except Exception:
                self.binaryfile = None
                return False

        if parse_data_dirs:
            try:
                self.binaryfile.parse_data_directories(
                    directories=[
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                    ]
                )
            except Exception:
                # Best effort: keep already-parsed PE object and continue with available data.
                pass
        return self.binaryfile is not None

    def gather_windows_imports_and_exports(self):
        print(f"{infoS} Performing extraction of imports and exports. Please wait...")
        try:
            # Fast path: avoid parsing every directory; we only need import/export/debug here.
            if not self.ensure_binaryfile(parse_data_dirs=True):
                raise ValueError("PE parser could not load target file.")
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
        except Exception:
            # Fallback path: pefile couldn't parse. Old implementation did O(#APIs * file_size) regex scanning.
            # Instead, use already-extracted strings as a prefilter; then find offsets only for matched APIs.
            bin_lower = self.executable_buffer.lower()
            seen = set()
            for s in self.all_strings:
                ss = str(s).strip()
                if not ss:
                    continue
                key = ss.lower()
                if key in seen:
                    continue
                hit = _API_LOWER_TO_API_AND_CATEGORY.get(key)
                if not hit:
                    continue
                api, _ = hit
                seen.add(key)

                off = -1
                try:
                    pat = key.encode("ascii", errors="ignore")
                    if pat:
                        off = bin_lower.find(pat)
                except Exception:
                    off = -1
                if off == -1:
                    try:
                        off = bin_lower.find(key.encode("utf-16le"))
                    except Exception:
                        off = -1

                self.windows_imports_and_exports.append([api, hex(off) if off != -1 else "N/A"])
        if self.windows_imports_and_exports != []:
            self.api_categorizer()
            self.dictcateg_parser()
        else:
            print(f"{errorS} There is no pattern about function/API imports!\n")

    def api_categorizer(self):
        for win_api in self.windows_imports_and_exports:
            api = win_api[0]
            if not api:
                continue
            cat = _API_TO_CATEGORY.get(api)
            if not cat:
                continue
            windows_api_list[cat]["occurence"] += 1
            dictCateg[cat].append(win_api)
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
                detailed_categories = os.environ.get("SC0PE_WINDOWS_REPORT_DETAILED", "").strip() == "1"
                seen_api = set()
                for func in dictCateg[key]:
                    if func[0] == "":
                        pass
                    else:
                        tables.add_row(f"[bold red]{func[0]}", f"[bold red]{func[1]}")
                        api = func[0]
                        if detailed_categories:
                            winrep["categories"][key].append(func)
                        else:
                            if api not in seen_api:
                                winrep["categories"][key].append(api)
                                seen_api.add(api)
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
            seen = set()
            for stf in intstf:
                # Persist findings into JSON report as well.
                key = str(stf)
                if key not in seen:
                    seen.add(key)
                    suspicious = (stf in interesting_stuff) or (".cmd" in stf or ".bat" in stf or ".exe" in stf or "syscall" in stf) or ("Select" in stf)
                    winrep["interesting_string_patterns"].append({"value": key, "suspicious": bool(suspicious)})

                if (stf in interesting_stuff) or (".cmd" in stf or ".bat" in stf or ".exe" in stf or "syscall" in stf) or ("Select" in stf):
                    stuff_table.add_row(f"[bold red]{key}[white]")
                else:
                    stuff_table.add_row(key)
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
            print(f"{infoS} Execute: [bold green]python qu1cksc0pe.py --file {self.target_file} --sigcheck[white] to extract them!\n")
        else:
            print(f"{errorS} There is no embedded PE file!\n")

    def section_parser(self):
        if not self.ensure_binaryfile(parse_data_dirs=False):
            print(f"{errorS} Could not parse PE section table.")
            return

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

    def statistics_method(self):
        if not self.ensure_binaryfile(parse_data_dirs=False):
            print(f"{errorS} Could not parse PE metadata for detailed statistics.")
            winrep["filename"] = self.target_file
            calc_hashes(self.target_file, winrep)
            return

        datestamp = self.gather_timestamp()
        print(f"\n[bold green]-> [white]Statistics for: [bold green][i]{self.target_file}[/i]")
        print(f"[bold magenta]>>[white] Time Date Stamp: [bold green][i]{datestamp}[/i]")
        winrep["filename"] = self.target_file
        winrep["timedatestamp"] = datestamp
        calc_hashes(self.target_file, winrep)
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
            return

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

        class_names = []
        # Parse .NET metadata without pythonnet (dnfile is pure-Python).
        # If dnfile isn't available, we will still continue with other heuristics.
        if dnfile is None:
            print(f"\n{errorS} Optional dependency missing: [bold red]dnfile[white]")
            print(f"{infoS} Install with: [bold green]pip3 install dnfile[white]\n")
        else:
            try:
                pe = dnfile.dnPE(self.target_file)
                if not getattr(pe, "net", None):
                    raise ValueError("Not a valid .NET assembly (NET directory missing).")

                md = pe.net.metadata
                # Optimized metadata uses #~, unoptimized uses #-.
                mdtables = md.streams.get(b"#~") or md.streams.get(b"#-")
                if mdtables is None:
                    raise ValueError("No metadata tables stream found (#~/#-).")

                # ECMA-335 table id 2 == TypeDef
                typedef_table = mdtables.tables.get(2)
                if typedef_table is None:
                    raise ValueError("TypeDef table not found in metadata tables.")

                print(f"\n{infoS} Extracting and analyzing classes...")
                for typ in typedef_table.rows:
                    try:
                        tname = str(getattr(typ, "TypeName", "")).strip()
                        tns = str(getattr(typ, "TypeNamespace", "")).strip()
                        if not tname:
                            continue
                        full_name = f"{tns}.{tname}" if tns else tname
                        if "<" in full_name:
                            continue

                        # Only show real reference types (classes/delegates). Skip structs/enums/interfaces which
                        # frequently come from P/Invoke interop and cause lots of empty method tables.
                        kind = _dn_kind(typ)
                        if kind not in ("class", "delegate"):
                            continue

                        class_names.append(full_name)

                        # Collect methods first; skip printing empty tables.
                        method_rows = []
                        seen = set()
                        for met_idx in getattr(typ, "MethodList", []) or []:
                            met_row = getattr(met_idx, "row", None)
                            met_name = str(getattr(met_row, "Name", "")).strip()
                            if not met_name or met_name in seen:
                                continue
                            seen.add(met_name)
                            method_rows.append((met_name, met_name in self.blacklisted_patterns))

                        if not method_rows:
                            continue
                        dotnet_table = Table()
                        if kind == "delegate":
                            hdr = f"Methods in Delegate: [bold green]{full_name}[white]"
                        else:
                            hdr = f"Methods in Class: [bold green]{full_name}[white]"
                        dotnet_table.add_column(hdr, justify="center")
                        for met_name, is_black in method_rows:
                            if is_black:
                                dotnet_table.add_row(f"[bold red]{met_name}[white]")
                            else:
                                dotnet_table.add_row(met_name)
                        print(dotnet_table)
                    except Exception:
                        continue

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
            except Exception as e:
                print(f"\n{errorS} An error occured while parsing the .NET file: [bold red]{e}[white]. Continuing...\n")

        self.check_for_valid_registry_keys()
        self.check_for_interesting_stuff()
        self.detect_embedded_PE()

        # Get debug information
        self.get_debug_information()

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
        yara_rule_scanner(self.rule_path, self.target_file, winrep)
        self.statistics_method()
        # Print reports
        if get_argv(2) == "True":
            save_report("windows", winrep)

    def msi_file_analyzer(self):
        print(f"{infoS} Performing Microsoft Software Installer analysis...\n")
        self.gather_windows_imports_and_exports()
        self.check_for_valid_registry_keys()
        self.check_for_interesting_stuff()
        self.detect_embedded_PE()

        # Some MSI samples may fail PE parsing in gather_windows_imports_and_exports fallback path.
        # Try a best-effort parse here; if still unavailable, continue without PE-dependent stages.
        if not hasattr(self, "binaryfile"):
            try:
                self.binaryfile = pf.PE(self.target_file, fast_load=True)
                self.binaryfile.parse_data_directories(
                    directories=[
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                    ]
                )
            except Exception:
                self.binaryfile = None

        if self.binaryfile is not None:
            self.get_debug_information()
            try:
                print(f"\n{infoS} Parsing section information...")
                self.section_parser()
            except Exception:
                pass
            try:
                print(f"\n{infoS} Checking linked DLL files...")
                self.dll_files()
            except Exception:
                pass
        # Yara rule match
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.target_file, winrep)

        # Always fill basic fields, even when binaryfile metadata is unavailable.
        winrep["filename"] = self.target_file
        calc_hashes(self.target_file, winrep)

        if self.binaryfile is not None:
            try:
                self.statistics_method()
            except SystemExit:
                # statistics_method may exit early for low-function samples; still allow report save.
                pass
            except Exception as e:
                print(f"{errorS} MSI statistics stage failed: [bold red]{e}[white]")

        if get_argv(2) == "True":
            save_report("windows", winrep)

def main():
    if len(sys.argv) < 2:
        err_exit("Usage: windows_static_analyzer.py <file> [save_report=True|False]")
    fileName = sys.argv[1]

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
    yara_rule_scanner(windows_analyzer.rule_path, fileName, winrep)
    windows_analyzer.section_parser()
    windows_analyzer.statistics_method()

    # Print reports
    if get_argv(2) == "True":
        save_report("windows", winrep)

if __name__ == "__main__":
    main()
