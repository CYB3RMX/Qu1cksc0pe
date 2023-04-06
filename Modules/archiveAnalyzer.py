#!/usr/bin/python3

import re
import os
import sys
import zipfile
import subprocess
import configparser

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

try:
    import rarfile
except:
    print("Error: >rarfile< module not found.")
    sys.exit(1)

try:
    import acefile
except:
    print("Error: >acefile< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Target file
targetFile = str(sys.argv[1])

class ArchiveAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
    def check_archive_type(self):
        arch_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "Zip archive data" in arch_type.stdout.decode():
            return "type_zip"
        elif "RAR archive data" in arch_type.stdout.decode():
            return "type_rar"
        elif "ACE archive data" in arch_type.stdout.decode():
            return "type_ace"
        else:
            return None
    def zip_file_analysis(self):
        # Parsing zip file
        zip_data = zipfile.ZipFile(self.targetFile)

        # Perform basic analysis
        self.perform_basic_scans(arch_object=zip_data, arch_type="zip")

    def rar_file_analysis(self):
        # Parsing rar file
        rar_data = rarfile.RarFile(self.targetFile)

        # Perform basic scans
        self.perform_basic_scans(arch_object=rar_data, arch_type="rar")

    def ace_file_analysis(self):
        # Parsing ace file
        ace_data = acefile.AceArchive(self.targetFile)

        # Perform basic scans
        self.perform_basic_scans(arch_object=ace_data, arch_type="ace")

    def perform_basic_scans(self, arch_object, arch_type):
        self.arch_object = arch_object
        self.arch_type = arch_type

        if self.arch_type == "ace":
            enumerate_arr = self.arch_object.getmembers()
            namelist_arr = self.arch_object.getnames()
        else:
            enumerate_arr = self.arch_object.infolist()
            namelist_arr = self.arch_object.namelist()

        # Enumerating zip file contents
        print(f"\n{infoS} Analyzing archive file contents...")
        contentTable = Table(title="* Archive Contents *", title_style="bold italic cyan", title_justify="center")
        contentTable.add_column("[bold green]File Name", justify="center")
        contentTable.add_column("[bold green]File Size (bytes)", justify="center")
        for zf in enumerate_arr:
            if self.arch_type == "ace":
                contentTable.add_row(zf.filename, str(zf.size))
            else:
                contentTable.add_row(zf.filename, str(zf.file_size))
        print(contentTable)

        # Extract data and analyze it
        for af in namelist_arr:
            try:
                # Write file content into another file for further analysis
                with open(af, "wb") as fc:
                    fc.write(self.arch_object.read(af))

                # Extract embedded URL's
                print(f"\n{infoS} Looking for embedded URL\'s in: [bold green]{af}[white]")
                self.extract_urls(af)

                # Perform YARA scan against file
                detect_os = subprocess.run(["file", af], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if "Windows" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}/Systems/Windows/windows.conf")
                elif "ELF" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}/Systems/Linux/linux.conf")
                elif "Word" in detect_os.stdout.decode() or "Excel" in detect_os.stdout.decode() or "PDF" in detect_os.stdout.decode() or "Rich Text" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}/Systems/Multiple/multiple.conf")
                else:
                    pass

                # Delete file
                os.remove(af)
            except:
                continue

    def extract_urls(self, url_target):
        self.url_target = url_target

        # Configurating strings parameter
        if sys.platform == "darwin":
            strings_param = "-a"
        else:
            strings_param = "--all"

        # Get all strings from file and search url patterns
        strings_buffer = subprocess.run(["strings", strings_param, self.url_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        url_occur = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", str(strings_buffer.stdout.decode().split("\n")))
        if url_occur != []:
            extract = []
            url_table = Table()
            url_table.add_column(f"[bold green]Embedded URL\'s in [bold red]{self.url_target}[white]", justify="center")
            for ux in url_occur:
                if ux not in extract:
                    extract.append(ux)

            for uu in extract:
                url_table.add_row(uu)
            print(url_table)
        else:
            print(f"[bold white on red]There is no URL contained in {self.url_target}")
    def perform_yara_scan(self, yara_target, config_file):
        self.yara_target = yara_target
        self.config_file = config_file
        yara_match_indicator = 0

        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(self.config_file)
        rule_path = conf["Rule_PATH"]["rulepath"]
        finalpath = f"{sc0pe_path}/{rule_path}"
        allRules = os.listdir(finalpath)

        # This array for holding and parsing easily matched rules
        yara_matches = []
        for rul in allRules:
            try:
                rules = yara.compile(f"{finalpath}{rul}")
                tempmatch = rules.match(self.yara_target)
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
            yaraTable = Table()
            yaraTable.add_column(f"[bold green]Matched YARA Rules for: [bold red]{self.yara_target}[white]", justify="center")
            for rul in yara_matches:
                yaraTable.add_row(str(rul))
            print(yaraTable)

        if yara_match_indicator == 0:
            print(f"[bold white on red]Not any rules matched for {self.yara_target}")

# Execution
arch_analyzer = ArchiveAnalyzer(targetFile)
artype = arch_analyzer.check_archive_type()
if artype == "type_zip":
    print(f"{infoS} Archive Type: [bold green]Zip Archive")
    arch_analyzer.zip_file_analysis()
elif artype == "type_rar":
    print(f"{infoS} Archive Type: [bold green]Rar Archive")
    arch_analyzer.rar_file_analysis()
elif artype == "type_ace":
    print(f"{infoS} Archive Type: [bold green]Ace Archive")
    arch_analyzer.ace_file_analysis()
else:
    print(f"{errorS} Archive type not supported.")
    sys.exit(1)