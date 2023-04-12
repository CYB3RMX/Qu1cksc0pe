#!/usr/bin/env python3

import os
import re
import sys
import subprocess
import binascii

# Testing pyaxmlparser existence
try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Testing rich existence
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Configurating strings parameter
if sys.platform == "darwin":
    strings_param = "-a"
else:
    strings_param = "--all"

class ResourceScanner:
    def __init__(self, target_file):
        self.target_file = target_file

    def check_target_os(self):
        fileType = str(pr.magic_file(self.target_file))
        if "PK" in fileType and "Java archive" in fileType:
            print(f"{infoS} Target OS: [bold green]Android[white]\n")
            return "file_android"
        elif "Windows Executable" in fileType:
            print(f"{infoS} Target OS: [bold green]Windows[white]\n")
            return "file_windows"
        else:
            return None

    def android_resource_scanner(self):
        # Categories
        categs = {
            "Presence of Tor": [], "URLs": [], "IP Addresses": []
        }

        # Wordlists for analysis
        dictionary = {
            "Presence of Tor": [
                "obfs4",
                "iat-mode=",
                "meek_lite",
                "found_existing_tor_process",
                "newnym"
            ],
            "URLs": [
                r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
            ],
            "IP Addresses": [
                r'[0-9]+(?:\.[0-9]+){3}:[0-9]+',
                "localhost"
            ]
        }

        # Tables!!
        countTable = Table()
        countTable.add_column("File Type", justify="center")
        countTable.add_column("File Name", justify="center")    
        fileTable = Table()
        fileTable.add_column("Interesting Files", justify="center")

        # Lets begin!
        print(f"{infoS} Parsing file contents...\n")
        apk = pyaxmlparser.APK(self.target_file)

        # Try to find something juicy
        empty = {}
        ftypes = apk.get_files_types()
        for typ in ftypes:
            if ftypes[typ] not in empty.keys():
                empty.update({ftypes[typ]: []})
        for fl in ftypes:
            empty[ftypes[fl]].append(fl)

        # Count file types
        for fl in empty:
            if "image" in fl: # Just get rid of them
                pass
            elif "Dalvik" in fl or "C++ source" in fl or "C source" in fl or "ELF" in fl or "Bourne-Again shell" in fl or "executable" in fl or "JAR" in fl: # Worth to write on the table
                for fname in empty[fl]:
                    countTable.add_row(f"[bold red]{fl}", f"[bold red]{fname}")
            elif "data" in fl:
                for fname in empty[fl]:
                    countTable.add_row(f"[bold yellow]{fl}", f"[bold yellow]{fname}")
            else:
                for fname in empty[fl]:
                    countTable.add_row(str(fl), str(fname))
        print(countTable)

        # Finding .json .bin .dex files
        for fff in apk.get_files():
            if ".json" in fff:
                fileTable.add_row(f"[bold yellow]{fff}")
            elif ".dex" in fff:
                fileTable.add_row(f"[bold red]{fff}")
            elif ".bin" in fff:
                fileTable.add_row(f"[bold cyan]{fff}")
            elif ".sh" in fff:
                fileTable.add_row(f"[bold red]{fff}")
            else:
                pass
        print(fileTable)

        # Analyzing all files
        for key in empty:
            try:
                for kfile in empty[key]:
                    fcontent = apk.get_file(kfile)
                    for ddd in dictionary:
                        for regex in dictionary[ddd]:
                            matches = re.findall(regex, fcontent.decode())
                            if matches != []:
                                categs[ddd].append([matches[0], kfile])
            except:
                continue

        # Output
        counter = 0
        for key in categs:
            if categs[key] != []:
                resTable = Table(title=f"* {key} *", title_style="bold green", title_justify="center")
                resTable.add_column("Pattern", justify="center")
                resTable.add_column("File", justify="center")
                for elements in categs[key]:
                    resTable.add_row(f"[bold yellow]{elements[0]}", f"[bold cyan]{elements[1]}")
                print(resTable)
                counter += 1
        if counter == 0:
            print("\n[bold white on red]There is no interesting things found!\n")

    def windows_resource_scanner(self):
        # Scan strings and find potential embedded PE executables
        possible_patterns = {
            "method_1": {
                "patterns": [
                    r"4D!5A!90",
                    r"4D-5A-90O"
                ]
            },
            "method_2": {
                "patterns": [
                    r"4D5A9ZZZ"
                ]
            },
            "method_3": {
                "patterns": [
                    r"~~~9A5D4"
                ]
            }
        }
        strings_data = subprocess.run(["strings", strings_param, self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        executable_buffer = ""
        for dat in strings_data.stdout.decode().split("\n"):
            for pat in possible_patterns: # Look for methods
                for mpat in possible_patterns[pat]["patterns"]:
                    matcc = re.findall(mpat, dat)
                    if matcc != []:
                        print(f"{infoS} Found potential embedded PE executable pattern: [bold green]{mpat}")
                        executable_buffer = dat
                        target_method = pat
                        target_pattern = mpat

        # After finding pattern and potential data we need to deobfuscate it
        if executable_buffer != "":
            print(f"{infoS} Attempting to deobfuscate PE file data. Please wait...")
            # Using method 1: Replace characters and split one character
            if target_method == "method_1":
                if target_pattern == r"4D!5A!90":
                    self.method_1_replace_split(r1="^", r2="!00", sp1="!", executable_buffer=executable_buffer)
                elif target_pattern == r"4D-5A-90O":
                    self.method_1_replace_split(r1="O", r2="-00", sp1='-', executable_buffer=executable_buffer)
                else:
                    print("Pattern not found!")
            # Using method 2: Double replace
            elif target_method == "method_2":
                if target_pattern == r"4D5A9ZZZ":
                    self.method_2_double_replace(r1="ZZ", r2="0", r3="YY", r4="F", executable_buffer=executable_buffer)
            # Using method 3: Reverse replace
            elif target_method == "method_3":
                if target_pattern == r"~~~9A5D4":
                    self.method_3_reverse_and_replace(r1="~", r2="0", executable_buffer=executable_buffer)
            else:
                print(f"{errorS} There is no method implemented for that data type!")
        else:
            print(f"{errorS} There is no embedded PE executable pattern found!")

    def method_1_replace_split(self, r1, r2, sp1, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.sp1 = sp1 # Split character
        self.executable_buffer = executable_buffer

        # First replace and split characters
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2)
        executable_array = self.executable_buffer.split(self.sp1)

        # Second extract and sanitize data
        output_buffer = ""
        for buf in executable_array:
            output_buffer += buf

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=output_buffer)

        # Finally save data into file
        with open("sc0pe_carved_deobfuscated.exe", "wb") as cf:
            cf.write(binascii.unhexlify(sanitized_data))
        print(f"{infoS} Data saved into: [bold green]sc0pe_carved_deobfuscated.exe[white]")
    def method_2_double_replace(self, r1, r2, r3, r4, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.r3 = r3 # Replace 3
        self.r4 = r4 # Replace 4
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2).replace(self.r3, self.r4)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Finally save data into file
        with open("sc0pe_carved_deobfuscated.exe", "wb") as cf:
            cf.write(binascii.unhexlify(sanitized_data))
        print(f"{infoS} Data saved into: [bold green]sc0pe_carved_deobfuscated.exe[white]")
    def method_3_reverse_and_replace(self, r1, r2, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer[::-1].replace(self.r1, self.r2)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Finally save data into file
        with open("sc0pe_carved_deobfuscated.exe", "wb") as cf:
            cf.write(binascii.unhexlify(sanitized_data))
        print(f"{infoS} Data saved into: [bold green]sc0pe_carved_deobfuscated.exe[white]")
    def buffer_sanitizer(self, executable_buffer):
        self.executable_buffer = executable_buffer

        # Data sanitization
        if '\t' in self.executable_buffer:
            self.executable_buffer = self.executable_buffer.lstrip("\t")

        # Unwanted characters
        unwanted = ['@']
        for uc in unwanted:
            if uc in self.executable_buffer:
                self.executable_buffer = self.executable_buffer.replace(uc, "")

        return self.executable_buffer

# Execution zone
targFile = sys.argv[1]
resource_scan = ResourceScanner(targFile)
if os.path.isfile(targFile):
    ostype = resource_scan.check_target_os()
    if ostype == "file_android":
        resource_scan.android_resource_scanner()
    elif ostype == "file_windows":
        resource_scan.windows_resource_scanner()
    else:
        print("\n[bold white on red]Target OS couldn\'t detected!\n")
else:
    print("\n[bold white on red]Target file not found!\n")