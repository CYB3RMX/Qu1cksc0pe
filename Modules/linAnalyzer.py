#!/usr/bin/python3

import os
import sys
import yara
import json
import hashlib
import subprocess
import configparser

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import lief
except:
    print("Error: >lief< module not found.")
    sys.exit(1)

try:
    import pygore
except:
    print("Error: >pygore< module not found.")
    sys.exit(1)

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Target file
target_file = sys.argv[1]

# Compatibility
homeD = os.path.expanduser("~")
path_seperator = "/"
strings_param = "--all"
setup_scr = "setup.sh"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"
    strings_param = "-a"
elif sys.platform == "darwin":
    strings_param = "-a"
else:
    pass

# Perform strings
_ = subprocess.run(f"strings {strings_param} \"{target_file}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
if sys.platform != "win32":
    _ = subprocess.run(f"strings {strings_param} -e l {target_file} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Wordlists
networkz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Networking.txt", "r").read().split("\n")
filez = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Files.txt", "r").read().split("\n")
procesz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Processes.txt", "r").read().split("\n")
memoryz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Memory.txt", "r").read().split("\n")
infogaz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Infoga.txt", "r").read().split("\n")
persisz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Persistence.txt", "r").read().split("\n")
cryptoz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Crypto.txt", "r").read().split("\n")
debuggz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Debug.txt", "r").read().split("\n")
otherz = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}Others.txt", "r").read().split("\n")

# Categories
Networking = []
File = []
Process = []
Memory = []
Information_Gathering = []
System_Persistence = []
Cryptography = []
Evasion = []
Other = []

# Report structure
linrep = {
    "filename": "",
    "machine_type": "",
    "hash_md5": "",
    "hash_sha1": "",
    "hash_sha256": "",
    "binary_entrypoint": "",
    "interpreter": "",
    "categorized_functions": 0,
    "number_of_functions": 0,
    "number_of_sections": 0,
    "number_of_segments": 0,
    "categories": {},
    "sections": [],
    "segments": [],
    "libraries": [],
    "matched_rules": [],
    "security": {"NX": False, "PIE": False}
}

# Scores
scoreDict = {
    "Networking": 0,
    "File": 0,
    "Process": 0,
    "Memory Management": 0,
    "Information Gathering": 0,
    "System/Persistence": 0,
    "Cryptography": 0,
    "Evasion": 0,
    "Other/Unknown": 0
}

# Dictionary of categories
Categs = {
    "Networking": Networking,
    "File": File,
    "Process": Process,
    "Memory Management": Memory,
    "Information Gathering": Information_Gathering,
    "System/Persistence": System_Persistence,
    "Cryptography": Cryptography,
    "Evasion": Evasion,
    "Other/Unknown": Other
}

# Dictionary of arrays
dictArr = {
    "Networking": networkz,
    "File": filez,
    "Process": procesz,
    "Memory Management": memoryz,
    "Information Gathering": infogaz,
    "System/Persistence": persisz,
    "Cryptography": cryptoz,
    "Evasion": debuggz,
    "Other/Unknown": otherz
}

conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux.conf")

class LinuxAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.binary = lief.parse(self.target_file)
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self.getStrings = open("temp.txt", "r").read().split("\n")
        self.allStrings = []
        for ssym in self.binary.symbols:
            self.allStrings.append(ssym.name)

    # Section content parser
    def ContentParser(self, sec_name, content_array):
        cont = ""
        for text in content_array:
            cont += chr(text)
        print(f"[bold magenta]>>[white] Section: [bold yellow]{sec_name}[white] | Content: [bold cyan]{cont}")

    # Binary security checker
    def SecCheck(self):
        chksec = Table(title_justify="center", title="* Security *", title_style="bold italic cyan")
        chksec.add_column("[bold yellow]NX", justify="center")
        chksec.add_column("[bold yellow]PIE", justify="center")
        # Checking NX
        if self.binary.has_nx is True:
            nxstr = "[bold red]True"
        else:
            nxstr = "[bold green]False"

        # Checking PIE
        if self.binary.is_pie is True:
            pistr = "[bold green]True"
        else:
            pistr = "[bold red]False"
        chksec.add_row(nxstr, pistr)
        print(chksec)
        linrep["security"]["NX"] = self.binary.has_nx
        linrep["security"]["PIE"] = self.binary.is_pie

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

    def report_writer(self, target_os, report_object):
        with open(f"sc0pe_{target_os}_report.json", "w") as rp_file:
            json.dump(report_object, rp_file, indent=4)
        print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_{target_os}_report.json\n")

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

    # General information
    def GeneralInformation(self):
        print(f"{infoS} General Informations about [bold green]{self.target_file}")
        print(f"[bold red]>>>>[white] Machine Type: [bold green]{self.binary.header.machine_type.name}")
        print(f"[bold red]>>>>[white] Binary Entrypoint: [bold green]{hex(self.binary.entrypoint)}")
        if self.binary.has_section(".interp"):
            data = self.binary.get_section(".interp")
            interpreter = ""
            for c in data.content:
                interpreter += chr(c)
            print(f"[bold red]>>>>[white] Interpreter: [bold green]{interpreter}")
            linrep["interpreter"] = interpreter
        print(f"[bold red]>>>>[white] Number of Sections: [bold green]{len(self.binary.sections)}")
        print(f"[bold red]>>>>[white] Number of Segments: [bold green]{len(self.binary.segments)}")
        linrep["machine_type"] = self.binary.header.machine_type.name
        linrep["binary_entrypoint"] = str(hex(self.binary.entrypoint))
        linrep["number_of_sections"] = len(self.binary.sections)
        linrep["number_of_segments"] = len(self.binary.segments)
        self.hash_calculator(self.target_file, linrep)
        self.SecCheck()

    # Gathering sections
    def SectionParser(self):
        secTable = Table(title="* Informations About Sections *", title_justify="center", title_style="bold italic cyan")
        secTable.add_column("[bold green]Section Names", justify="center")
        secTable.add_column("[bold green]Size(bytes)", justify="center")
        secTable.add_column("[bold green]Offset", justify="center")
        secTable.add_column("[bold green]Virtual Address", justify="center")
        secTable.add_column("[bold green]Entropy", justify="center")
        for sec in self.binary.sections:
            if sec.name != "" and sec.name != " ":
                secTable.add_row(
                    f"[bold red]{sec.name}", 
                    str(sec.size),
                    str(hex(sec.offset)),
                    str(hex(sec.virtual_address)),
                    str(sec.entropy)
                )
                linrep["sections"].append(
                    {
                        "name": sec.name,
                        "size": sec.size,
                        "offset": str(hex(sec.offset)),
                        "virtual_address": str(hex(sec.virtual_address)),
                        "entropy": str(sec.entropy)
                    }
                )
        print(secTable)

    # Gathering segments
    def SegmentParser(self):
        segTable = Table(title="* Informations About Segments *", title_justify="center", title_style="bold italic cyan")
        segTable.add_column("[bold green]Segments", justify="center")
        segTable.add_column("[bold green]Contained Sections", justify="center")
        for seg in self.binary.segments:
            ssec = []
            if seg.type.name != "" and seg.type.name != " ":
                for sgs in seg.sections:
                    ssec.append(sgs.name)
                segTable.add_row(f"[bold red]{seg.type.name}", str(ssec))
                linrep["segments"].append(seg.type.name)
        print(segTable)

    # Analysis of Golang binaries
    def AnalyzeGolang(self):
        go_file = pygore.GoFile(self.target_file)
        print(f"\n{infoS} Analyzing [bold green]Golang [white]binary...")

        # Parsing compiler information
        comp = go_file.get_compiler_version()
        print(f"\n{infoS} Parsing compiler information...")
        print(f"[bold magenta]>>>[white] Compiler Version: [bold green]{comp.name}")
        print(f"[bold magenta]>>>[white] Timestamp: [bold green]{comp.timestamp}")

        # Parsing..
        go_pkgs = go_file.get_packages()
        go_imps = go_file.get_std_lib_packages()

        # Package info table
        print(f"\n{infoS} Performing deep inspection against target binary...")
        pkg_table = Table(title="* Information About Packages *", title_justify="center", title_style="bold italic cyan")
        pkg_table.add_column("[bold green] Name", justify="center")
        pkg_table.add_column("[bold green] FilePath", justify="center")
        for pk in go_pkgs:
            pkg_table.add_row(pk.name, pk.filepath) # Parsing package name etc.
        print(pkg_table)

        # Parse area
        for pk in go_pkgs:
        # Perform deep inspection for packages
            # Parsing methods
            meth_table = Table(title="* Methods *", title_justify="center", title_style="bold italic cyan")
            meth_table.add_column("[bold green] Name", justify="center")
            meth_table.add_column("[bold green] Receiver", justify="center")
            meth_table.add_column("[bold green] Offset", justify="center")
            if pk.methods != []:
                for meth in pk.methods:
                    meth_table.add_row(meth.name, meth.receiver, hex(meth.offset))
                print(meth_table)
            else:
                print(f"\n[bold red]>>>[white] No methods found in {pk.name}\n")

                # Parsing functions
            fun_table = Table(title="* Functions *", title_justify="center", title_style="bold italic cyan")
            fun_table.add_column("[bold green] Name", justify="center")
            fun_table.add_column("[bold green] Offset", justify="center")
            if pk.functions != []:
                for func in pk.functions:
                    fun_table.add_row(func.name, hex(func.offset))
                print(fun_table)
            else:
                print(f"\n[bold red]>>>[white] No functions found in {pk.name}\n")

        # Parsing imported libraries
        imp_table = Table(title="* Imported Libraries *", title_justify="center", title_style="bold italic cyan")
        imp_table.add_column("[bold green] Name", justify="center")
        if go_imps != []:
            for imp in go_imps:
                imp_table.add_row(imp.name)
            print(imp_table)
        else:
            print(f"\n[bold red]>>>[white] No imported libraries found\n")

    # Defining function
    def Analyzer(self):
        allFuncs = 0

        for key in dictArr:
            for elem in dictArr[key]:
                if elem in self.allStrings:
                    if elem != "":
                        Categs[key].append(elem)
                        allFuncs +=1
        for key in Categs:
            if Categs[key] != []:
                if key == "Information Gathering" or key == "System/Persistence" or key == "Cryptography" or key == "Evasion":
                    tables = Table(title="* WARNING *", title_style="blink italic yellow", title_justify="center", style="yellow")
                else:
                    tables = Table()

                # Printing zone
                tables.add_column(f"Functions or Strings about [bold green]{key}", justify="center")
                linrep["categories"].update({key: []})
                for i in Categs[key]:
                    if i == "":
                        pass
                    else:
                        tables.add_row(f"[bold red]{i}")
                        linrep["categories"][key].append(i)
                        # Threat score
                        if key == "Networking":
                            scoreDict[key] += 1
                        elif key == "File":
                            scoreDict[key] += 1
                        elif key == "Process":
                            scoreDict[key] += 1
                        elif key == "Memory Management":
                            scoreDict[key] += 1
                        elif key == "Information Gathering":
                            scoreDict[key] += 1
                        elif key == "System/Persistence":
                            scoreDict[key] += 1
                        elif key == "Cryptography":
                            scoreDict[key] += 1
                        elif key == "Other/Unknown":
                            scoreDict[key] += 1
                        else:
                            pass
                print(tables)

        # Perform YARA scan
        print(f"\n{infoS} Performing YARA rule matching...")
        self.yara_rule_scanner(self.target_file, report_object=linrep)

        # Get sections
        self.SectionParser()

        # Segments
        self.SegmentParser()

        # Used libraries
        libs = Table()
        libs.add_column("[bold green]Libraries", justify="center")
        if len(self.binary.libraries) > 0:
            for x in self.binary.libraries:
                libs.add_row(f"[bold red]{x}")
                linrep["libraries"].append(x)
            print(libs)

        # Hunting for debug sections
        print(f"\n{infoS} Performing debug section hunt...")
        debugs = []
        for sss in self.binary.sections:
            if ".debug_" in sss.name:
                print(f"[bold red]>>>>[white] {sss.name}")
                debugs.append(sss.name)
        if debugs != []:
            quest = str(input(f"\n>> Do you want to analyze debug strings?[Y/n]: "))
            if quest == "Y" or quest == "y":
                print()
                for ddd in debugs:
                    if ddd == ".debug_str":
                        data = self.binary.get_section(ddd)
                        self.ContentParser(data.name, data.content)
        else:
            print("[bold white on red]There is no debug sections in this binary!!")

        # Statistics zone
        print(f"\n[bold green]->[white] Statistics for: [bold green][i]{self.target_file}[/i]")
        linrep["filename"] = self.target_file

        # Printing zone
        statistics = Table()
        statistics.add_column("Categories", justify="center")
        statistics.add_column("Number of Functions or Strings", justify="center")
        statistics.add_row("[bold green][i]All Functions[/i]", f"[bold green]{len(self.allStrings)}")
        statistics.add_row("[bold green][i]Categorized Functions[/i]", f"[bold green]{allFuncs}")
        linrep["categorized_functions"] = allFuncs
        linrep["number_of_functions"] = len(self.allStrings)
        for key in scoreDict:
            if scoreDict[key] == 0:
                pass
            else:
                if key == "System/Persistence" or key == "Cryptography" or key == "Information Gathering":
                    statistics.add_row(f"[bold yellow]{key}", f"[bold red]{scoreDict[key]}")
                else:
                    statistics.add_row(key, str(scoreDict[key]))
        print(statistics)

        # Warning about obfuscated file
        if allFuncs < 10:
            print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
            print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
            sys.exit(0)

        # Print reports
        if sys.argv[2] == "True":
            self.report_writer("linux", linrep)

        # Look for interesting things
        if "runtime.goexit" in self.getStrings and "runtime.gopanic" in self.getStrings:
            print(f"\n{infoS} Qu1cksc0pe was identified this binary as [bold green]Golang[white] binary.")
            chc = str(input(">>> Do you want to perform special analysis[Y/n]?: "))
            if chc == "Y" or chc == "y":
                self.AnalyzeGolang()

# Execute
if __name__ == "__main__":
    lina = LinuxAnalyzer(target_file=sys.argv[1])
    lina.GeneralInformation()
    lina.Analyzer()