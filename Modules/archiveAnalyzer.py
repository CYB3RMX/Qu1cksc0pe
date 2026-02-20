#!/usr/bin/python3

import re
import os
import sys
import zipfile
import subprocess
import configparser
import shutil
import tempfile

from utils.helpers import err_exit

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

try:
    import rarfile
except:
    err_exit("Error: >rarfile< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"
    path_seperator = "\\"
else:
    pass

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Ensure `analysis.*` imports resolve when running as a script.
modules_dir = os.path.join(sc0pe_path.strip(), "Modules")
if modules_dir not in sys.path:
    sys.path.insert(0, modules_dir)

try:
    from analysis.multiple.multi import yara_rule_scanner
except:
    err_exit("Error: >analysis.multiple.multi< module not found.")

# Target file
targetFile = sys.argv[1]

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
        # `acefile` dependency removed: try extracting with 7-Zip if present.
        seven_zip = shutil.which("7z") or shutil.which("7zz")
        if not seven_zip:
            err_exit(f"{errorS} ACE archive detected but no extractor found. Install 7-Zip (`7z`) or convert the archive.")

        tmpdir = tempfile.mkdtemp(prefix="qu1cksc0pe_ace_")
        try:
            proc = subprocess.run(
                [seven_zip, "x", "-y", f"-o{tmpdir}", self.targetFile],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if proc.returncode != 0:
                err_exit(f"{errorS} Failed to extract ACE archive with 7-Zip.\n{proc.stderr.strip() or proc.stdout.strip()}")

            ace_data = ExtractedArchive(tmpdir)
            self.perform_basic_scans(arch_object=ace_data, arch_type="ace")
        finally:
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

    def perform_basic_scans(self, arch_object, arch_type):
        self.arch_object = arch_object
        self.arch_type = arch_type

        enumerate_arr = self.arch_object.infolist()
        namelist_arr = []

        # Enumerating zip file contents
        print(f"\n{infoS} Analyzing archive file contents...")
        contentTable = Table(title="* Archive Contents *", title_style="bold italic cyan", title_justify="center")
        contentTable.add_column("[bold green]File Name", justify="center")
        contentTable.add_column("[bold green]File Size (bytes)", justify="center")
        for zf in enumerate_arr:
            contentTable.add_row(zf.filename, str(zf.file_size))

            # Check if target content is a directory
            if zf.is_dir():
                pass
            else:
                namelist_arr.append(zf.filename)

        print(contentTable)

        # Extract data and analyze it
        for af in namelist_arr:
            try:
                # Gather file buffer/data
                file_data = self.arch_object.read(af)

                # Sanitize file name
                if "/" in af:
                    af = af.split("/")[-1]
                elif "\\" in af:
                    af = af.split("\\")[-1]
                else:
                    pass

                # Write file content into another file for further analysis
                with open(af, "wb") as fc:
                    fc.write(file_data)

                # Extract embedded URL's
                print(f"\n{infoS} Looking for embedded URL\'s in: [bold green]{af}[white]")
                self.extract_urls(af)

                # Perform YARA scan against file
                detect_os = subprocess.run(["file", af], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if "Windows" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf")
                elif "ELF" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux.conf")
                elif "Word" in detect_os.stdout.decode() or "Excel" in detect_os.stdout.decode() or "PDF" in detect_os.stdout.decode() or "Rich Text" in detect_os.stdout.decode():
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{af}[white]")
                    self.perform_yara_scan(af, config_file=f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf")
                else:
                    pass

                # Delete file
                os.remove(af)
            except:
                continue

    def extract_urls(self, url_target):
        self.url_target = url_target

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

        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(self.config_file, encoding="utf-8-sig")
        rule_path = conf["Rule_PATH"]["rulepath"]
        rep = {"matched_rules": []}
        hit = yara_rule_scanner(rule_path, self.yara_target, rep, quiet_nomatch=True, quiet_errors=False, print_matches=False)
        if not hit:
            print(f"[bold white on red]There is no rules matched for {self.yara_target}")
            return

        # Preserve the original, compact output for archives: list matched rule names only.
        rule_names = []
        for entry in rep.get("matched_rules", []):
            if isinstance(entry, dict):
                for k in entry.keys():
                    if k not in rule_names:
                        rule_names.append(k)

        yaraTable = Table()
        yaraTable.add_column(f"[bold green]Matched YARA Rules for: [bold red]{self.yara_target}[white]", justify="center")
        for rn in rule_names:
            yaraTable.add_row(str(rn))
        print(yaraTable)


class ExtractedArchiveEntry:
    def __init__(self, filename, file_size, is_dir):
        self.filename = filename
        self.file_size = file_size
        self._is_dir = bool(is_dir)

    def is_dir(self):
        return self._is_dir


class ExtractedArchive:
    """
    Minimal read-only archive-like wrapper used for formats we extract via external tools (e.g., ACE via 7z).
    Exposes `infolist()` and `read(name)` similar to zipfile/rarfile objects used by this module.
    """

    def __init__(self, root_dir):
        self.root_dir = os.path.abspath(root_dir)
        self._entries = None

    def infolist(self):
        if self._entries is not None:
            return self._entries

        entries = []
        for base, dnames, fnames in os.walk(self.root_dir):
            rel_base = os.path.relpath(base, self.root_dir)
            rel_base = "" if rel_base == "." else rel_base

            for d in dnames:
                rel = os.path.join(rel_base, d) if rel_base else d
                rel = rel.replace(os.sep, "/")
                entries.append(ExtractedArchiveEntry(rel + "/", 0, True))

            for f in fnames:
                full = os.path.join(base, f)
                rel = os.path.join(rel_base, f) if rel_base else f
                rel = rel.replace(os.sep, "/")
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    sz = 0
                entries.append(ExtractedArchiveEntry(rel, sz, False))

        # Stable ordering for deterministic output
        entries.sort(key=lambda e: e.filename)
        self._entries = entries
        return entries

    def read(self, name):
        # Normalize and prevent path traversal outside root_dir.
        norm = name.replace("\\", "/").lstrip("/")
        full = os.path.abspath(os.path.join(self.root_dir, *norm.split("/")))
        if not (full == self.root_dir or full.startswith(self.root_dir + os.sep)):
            raise ValueError("invalid archive member path")
        with open(full, "rb") as f:
            return f.read()

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
    err_exit(f"{errorS} Archive type not supported.")
