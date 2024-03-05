#!/usr/bin/python3

import re
import sys
import json

try:
    from wh1tem0cha import Wh1teM0cha
except:
    print("Error: >wh1tem0cha< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Compatibility
path_seperator = "/"
strings_param = "--all"
if sys.platform == "win32":
    path_seperator = "\\"
    strings_param = "-a"
elif sys.platform == "darwin":
    strings_param = "-a"
else:
    pass

# Sc0pe path
sc0pe_path = open(".path_handler", "r").read()

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Target
target_file = sys.argv[1]

# Categories
dict_categ = {
    "Networking/Web": [],
    "Cryptography/SSL Handling": [],
    "Information Gathering": [],
    "Memory Management": [],
    "Process/Execution": []
}

class AppleAnalyzer:
    def __init__(self):
        self._target_binary_buff = open(target_file, "rb").read()
        self.wmocha_object = None # By default

    def _check_ipa_file(self):
        # Most common patterns
        occurence = 0
        m_c_p = [b"Payload\/", b"META-INF\/", b"\.plist"]
        for pattern in m_c_p:
            if re.findall(pattern, self._target_binary_buff):
                occurence += 1

        if occurence > 0:
            return True
        else:
            return False

    def _check_macho_binary(self):
        # Check MACH-O pattern using wh1tem0cha
        wm = Wh1teM0cha(target_file)
        try:
            wm.get_binary_info()
            self.wmocha_object = wm
            return True
        except:
            return False

    def check_target_type(self):
        # This method is for checking if the target file is .ipa or .macho
        if self._check_macho_binary():
            self.analyze_macho_binary()
        elif self._check_ipa_file():
            print(f"{infoS} This feature will release coming soon!")
            #self.analyze_ipa_file()
        else:
            print(f"{errorS} Unknown file type!")

    def parse_libraries(self):
        library_dict = self.wmocha_object.get_dylib_names()
        if library_dict:
            ltable = Table()
            ltable.add_column("[bold green]Dynamic Libraries",justify="center")
            for lib in library_dict:
                if "/Security" in lib["libname"].decode() or "/libresolv" in lib["libname"].decode() or "/libSystem" in lib["libname"].decode():
                    ltable.add_row(f"[bold red]{lib['libname'].decode()} (Possible malicious purposes!)[white]")
                else:
                    ltable.add_row(lib["libname"].decode())
            print(ltable)

    def _perform_pattern_analysis(self):
        osx_patterns = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}OSX{path_seperator}osx_sym_categories.json"))
        for key in osx_patterns:
            for pattern in osx_patterns[key]["patterns"]:
                if re.findall(pattern.encode(), self._target_binary_buff):
                    osx_patterns[key]["occurence"] += 1
                    dict_categ[key].append(pattern)
        self._categ_parser()
        self._print_statistics()

    def _categ_parser(self):
        for key in dict_categ:
            if dict_categ[key] != []:
                ctable = Table()
                ctable.add_column(f"Patterns about [bold green]{key}", justify="center")
                for pattern in dict_categ[key]:
                    ctable.add_row(f"[bold red]{pattern}")
                print(ctable)

    def _print_statistics(self):
        statistics = Table()
        print(f"\n[bold green]->[white] Statistics for: [bold green][i]{target_file}[/i]")
        statistics.add_column("Categories", justify="center")
        statistics.add_column("Number of Patterns", justify="center")
        for key in dict_categ:
            if dict_categ[key] != []:
                if key == "Cryptography" or key == "Information Gathering":
                    statistics.add_row(f"[bold yellow]{key}", f"[bold red]{len(dict_categ[key])}")
                else:
                    statistics.add_row(key, str(len(dict_categ[key])))
        print(statistics)

    def analyze_macho_binary(self):
        # Print binary info first
        print(f"{infoS} Binary Information")
        binary_info = self.wmocha_object.get_binary_info()
        for key in binary_info:
            print(f"[bold magenta]>>>>[white] {key}: [bold green]{binary_info[key]}")

        # Parse segment information
        print(f"\n{infoS} Parsing segment information...")
        seg_table = Table()
        seg_table.add_column("[bold green]name", justify="center")
        seg_table.add_column("[bold green]offset", justify="center")
        seg_table.add_column("[bold green]cmd", justify="center")
        seg_table.add_column("[bold green]cmdsize", justify="center")
        seg_table.add_column("[bold green]vmaddr", justify="center")
        seg_table.add_column("[bold green]vmsize", justify="center")
        seg_table.add_column("[bold green]filesize", justify="center")
        segments = self.wmocha_object.get_segments()
        for seg in segments:
            seg_inf = self.wmocha_object.segment_info(seg["segment_name"].decode())
            seg_table.add_row(seg["segment_name"].decode(), seg_inf["offset"], seg_inf["cmd"], seg_inf["cmdsize"],
                              seg_inf["vmaddr"], seg_inf["vmsize"], seg_inf["filesize"])
        print(seg_table)

        # Parsing sections
        print(f"\n{infoS} Analyzing sections...")
        sec_table = Table()
        sec_table.add_column("[bold green]name", justify="center")
        sec_table.add_column("[bold green]segment", justify="center")
        sec_table.add_column("[bold green]offset", justify="center")
        sec_table.add_column("[bold green]size", justify="center")
        sections = self.wmocha_object.get_sections()
        for sec in sections:
            try:
                sec_inf = self.wmocha_object.section_info(sec["section_name"].decode())
                if "__gosymtab" in sec["section_name"].decode() or "__gopclntab" in sec["section_name"].decode() or "__go_buildinfo" in sec["section_name"].decode():
                    sec_table.add_row(f"[bold red]{sec['section_name'].decode()}[white]", sec_inf["segment_name"].decode(), 
                                      sec_inf["offset"].decode(), sec_inf["size"].decode())
                else:
                    sec_table.add_row(sec["section_name"].decode(), sec_inf["segment_name"].decode(),
                                      sec_inf["offset"].decode(), sec_inf["size"].decode())
            except:
                continue
        print(sec_table)

        # Analyze libraries
        print(f"\n{infoS} Analyzing libraries...")
        self.parse_libraries()

        # Pattern scanner
        print(f"\n{infoS} Performing pattern scan...")
        self._perform_pattern_analysis()

# Execution
apa = AppleAnalyzer()
apa.check_target_type()