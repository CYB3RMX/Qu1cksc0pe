#!/usr/bin/python3

import re
import sys
import json
import base64
import binascii
import subprocess

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Configurating strings parameter
if sys.platform == "darwin":
    strings_param = "-a"
else:
    strings_param = "--all"

# Load patterns
powershell_code_patterns = json.load(open(f"{sc0pe_path}/Systems/Windows/powershell_code_patterns.json"))

class PowerShellAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.target_buffer_normal = subprocess.run(["strings", strings_param, self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.target_buffer_16bit = subprocess.run(["strings", strings_param, "-e", "l", self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n")+self.target_buffer_normal.stdout.decode().split("\n")

    def scan_code_patterns(self):
        print(f"{infoS} Performing pattern scan...")
        for pat in powershell_code_patterns:
            pat_table = Table()
            pat_table.add_column(f"Extracted patterns about [bold green]{pat}[white]", justify="center")
            for code in powershell_code_patterns[pat]["patterns"]:
                matchh = re.findall(code, str(self.all_strings))
                if matchh != []:
                    pat_table.add_row(code)
                    powershell_code_patterns[pat]["occurence"] += 1
            if powershell_code_patterns[pat]["occurence"] != 0:
                print(pat_table)

    def check_executions(self):
        print(f"\n{infoS} Performing detection of possible executions...")
        exec_patterns = [
            r"regsvr32\s+C://[\w/.:-]+\.dll",
            r"regsvr32\s+C:\\[\w/.:-]+\.dll",
            r'(start\s+\w+\.exe)',
            r'CMD\s+/C\s+powershell\b.*'
        ]
        swc = 0
        exec_table = Table()
        exec_table.add_column(f"Extracted patterns about [bold green]Execution[white]", justify="center")
        for expat in exec_patterns:
            matchs = re.findall(expat, str(self.all_strings), re.IGNORECASE)
            if matchs != []:
                for mm in matchs:
                    exec_table.add_row(mm)
                    swc += 1
        if swc != 0:
            print(exec_table)
        else:
            print(f"{errorS} There is no pattern about execution!\n")

    def extract_path_values(self):
        print(f"\n{infoS} Performing extraction of path values...")
        path_regex = r"'([A-Z]:\\[^']+)'"
        path_table = Table()
        path_table.add_column("Extracted [bold green]PATH[white] values", justify="center")
        mathces = re.findall(path_regex, str(self.all_strings), re.IGNORECASE)
        if mathces != []:
            for path in mathces:
                path_table.add_row(path)
            print(path_table)
        else:
            print(f"{errorS} There is no pattern about path values...\n")

    def byte_array_presence_checker(self):
        pattern = r'\[Byte\[\]\]'
        matches = re.findall(pattern, str(self.all_strings), re.IGNORECASE)
        if matches != []:
            return True
        else:
            return False

    def check_for_xor_key(self):
        pattern = r'-bxor\s+(\d+)'
        matches = re.findall(pattern, str(self.all_strings))
        if matches != []:
            return matches[0]
        else:
            return None

    def find_payloads_xored(self):
        print(f"\n{infoS} Performing payload detection...")
        # First we need to check Bytearrays (Metasploit, CobaltStrike)
        if self.byte_array_presence_checker():
            print(f"{infoS} Looks like we have a possible payload. Attempting to detect its type...")
            self.detect_and_carve_base64_payloads()
            self.detect_and_carve_ascii_number_payloads()
            self.detect_and_carve_hex_values_payloads()
        else:
            print(f"{errorS} There is no pattern about hidden payloads!\n")

    def detect_and_carve_base64_payloads(self):
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        pattern = r'\[System\.Convert\]::FromBase64String\(\'([A-Za-z0-9+/=]+)\'\)'
        b64matches = re.findall(pattern, str(self.all_strings))
        if b64matches != []:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                byte_arr = bytearray(base64.b64decode(b64matches[0]))
                for byt in range(len(byte_arr)):
                    byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
                with open("sc0pe_decoded_b64_payload.bin", "wb") as ff:
                    ff.write(byte_arr)
                print(f"{infoS} Decoded payload saved into: [bold green]sc0pe_decoded_b64_payload.bin[white]")
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def detect_and_carve_ascii_number_payloads(self):
        print(f"\n{infoS} Searching for: [bold green]ASCII Numbers[white]...")
        pattern = r'\[Byte\[\]\]\((\d+(?:,\d+)*)\)'
        asciinum = re.findall(pattern, str(self.all_strings))
        if asciinum != []:
            print(f"{infoS} We have an array of [bold green]ASCII Numbers[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                temp_array = []
                for num in asciinum[0].split(","):
                    temp_array.append(int(num))
                byte_arr = bytearray(temp_array)
                for byt in range(len(byte_arr)):
                    byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
                with open("sc0pe_decoded_ascii_numbers_payload.bin", "wb") as ff:
                    ff.write(byte_arr)
                print(f"{infoS} Decoded payload saved into: [bold green]sc0pe_decoded_ascii_numbers_payload.bin[white]")
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about ASCII Numbers!\n")

    def detect_and_carve_hex_values_payloads(self):
        print(f"\n{infoS} Searching for: [bold green]HEX Values[white]...")
        pattern = r'\[System\.Convert\]::fromHEXString\(\'([0-9a-fA-F]+)\'\)'
        hexval = re.findall(pattern, str(self.all_strings))
        if hexval != []:
            print(f"{infoS} We have an array of [bold green]HEX Values[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                byte_arr = bytearray(binascii.unhexlify(hexval[0]))
                for byt in range(len(byte_arr)):
                    byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
                with open("sc0pe_decoded_hex_values_payload.bin", "wb") as ff:
                    ff.write(byte_arr)
                print(f"{infoS} Decoded payload saved into: [bold green]sc0pe_decoded_hex_values_payload.bin[white]")
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about HEX Values!\n")

# Execution
pwsh_analyzer = PowerShellAnalyzer(sys.argv[1])
pwsh_analyzer.scan_code_patterns()
pwsh_analyzer.extract_path_values()
pwsh_analyzer.check_executions()
pwsh_analyzer.find_payloads_xored()