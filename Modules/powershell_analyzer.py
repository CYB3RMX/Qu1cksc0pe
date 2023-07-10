#!/usr/bin/python3

import re
import io
import sys
import json
import zlib
import gzip
import base64
import binascii
import subprocess
import warnings

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

warnings.filterwarnings("ignore")

class PowerShellAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.target_buffer_normal = subprocess.run(["strings", strings_param, self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.target_buffer_16bit = subprocess.run(["strings", strings_param, "-e", "l", self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n")+self.target_buffer_normal.stdout.decode().split("\n")
        self.pattern_b64 = r"\[(?i)sYsteM\.coNvert\]::FROmbaSe64StRiNG\(\s*[\'\"]([^']*)[\'\"]\s*\)|\[System\.Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=]+)'\s*\)"
        self.pattern_ascii = r'\[Byte\[\]\]\((\d+(?:,\d+)*)\)'
        self.pattern_hex = r'\[System\.Convert\]::fromHEXString\(\'([0-9a-fA-F]+)\'\)'

    def save_data_into_file(self, output_file, data):
        with open(output_file, "wb") as ff:
            ff.write(data)
        print(f"{infoS} Decoded payload saved into: [bold green]{output_file}[white]")

    def scan_code_patterns(self):
        print(f"{infoS} Performing pattern scan...")
        for pat in powershell_code_patterns:
            pat_table = Table()
            pat_table.add_column(f"Extracted patterns about [bold green]{pat}[white]", justify="center")
            for code in powershell_code_patterns[pat]["patterns"]:
                matchh = re.findall(code, str(self.all_strings), re.IGNORECASE)
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
            r'CMD\s+/C\s+powershell\b.*',
            r'powershell\s+-exec\s+bypass\s+-c',
            r'(Start-Process\s+\"[^\"]+\.exe\")'
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

    # ------------------------------------ XORED Payload detection and extratcion
    def check_for_xor_key(self):
        pattern = r'-bxor\s+(\d+)'
        matches = re.findall(pattern, str(self.all_strings), re.IGNORECASE)
        if matches != []:
            return matches[0]
        else:
            return None

    def find_payloads_xored(self):
        print(f"\n{infoS} Performing [bold green]XOR\'ed[white] payload detection...")
        # First we need to check Bytearrays (Metasploit, CobaltStrike)
        if self.check_for_xor_key() is not None:
            print(f"{infoS} Looks like we have a possible [bold green]XOR\'ed[white] payload. Attempting to detect its type...")
            self.detect_and_carve_base64_payloads_xored()
            self.detect_and_carve_ascii_number_payloads_xored()
            self.detect_and_carve_hex_values_payloads_xored()
        else:
            print(f"{errorS} There is no pattern about XOR\'ed payloads!\n")

    def xor_decrypt_and_save(self, payload_type, payload, xor_key):
        if payload_type == "base64":
            byte_arr = bytearray(base64.b64decode(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
            self.save_data_into_file(output_file="sc0pe_decoded_b64_payload.bin", data=byte_arr)
        elif payload_type == "ascii":
            temp_array = []
            for num in payload:
                temp_array.append(int(num))
            byte_arr = bytearray(temp_array)
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
            self.save_data_into_file(output_file="sc0pe_decoded_ascii_numbers_payload.bin", data=byte_arr)
        elif payload_type == "hex":
            byte_arr = bytearray(binascii.unhexlify(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
            self.save_data_into_file(output_file="sc0pe_decoded_hex_values_payload.bin", data=byte_arr)
        else:
            pass

    def detect_and_carve_base64_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64, str(self.all_strings), re.IGNORECASE)
        if b64matches != []:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                self.xor_decrypt_and_save(payload_type="base64", payload=b64matches[0][0], xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def detect_and_carve_ascii_number_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]ASCII Numbers[white]...")
        asciinum = re.findall(self.pattern_ascii, str(self.all_strings), re.IGNORECASE)
        if asciinum != []:
            print(f"{infoS} We have an array of [bold green]ASCII Numbers[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                self.xor_decrypt_and_save(payload_type="ascii", payload=asciinum[0].split(","), xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about ASCII Numbers!\n")

    def detect_and_carve_hex_values_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]HEX Values[white]...")
        hexval = re.findall(self.pattern_hex, str(self.all_strings), re.IGNORECASE)
        if hexval != []:
            print(f"{infoS} We have an array of [bold green]HEX Values[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                self.xor_decrypt_and_save(payload_type="hex", payload=hexval[0], xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about HEX Values!\n")

    # ------------------------------------ non-XORED payload detection and extraction
    def check_for_non_xored_payloads_presence(self):
        print(f"{infoS} Performing [bold green]non-XOR\'ed[white] payload detection...")
        b64_payload = re.findall(self.pattern_b64, str(self.all_strings), re.IGNORECASE)
        ascii_payload = re.findall(self.pattern_ascii, str(self.all_strings), re.IGNORECASE)
        hex_payload = re.findall(self.pattern_hex, str(self.all_strings), re.IGNORECASE)
        pe_payload = re.findall(r"4d5a90", str(self.all_strings), re.IGNORECASE)
        if b64_payload != [] or ascii_payload != [] or hex_payload != [] or pe_payload != []:
            if self.check_for_xor_key() is None:
                print(f"{infoS} Looks like we have a possible [bold green]non-XOR\'ed[white] payload. Attempting to detect its type...")
                self.detect_and_carve_b64_non_xored()
                self.detect_and_carve_pe_executable_non_xored()
            else:
                print(f"{errorS} Couldn\'t detect XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about non-XOR\'ed payloads!\n")

    def detect_and_carve_b64_non_xored(self):
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64, str(self.all_strings), re.IGNORECASE)
        if b64matches != []:
            b64_data = base64.b64decode(b64matches[0][0])
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for compressed data presence...")
            deflatestream = re.findall(r'Io\.CoMpRESSiOn\.defLaTEstReam', str(self.all_strings), re.IGNORECASE)
            gzipstream = re.findall(r"IO\.Compression\.GZipStream", str(self.all_strings), re.IGNORECASE)
            if deflatestream != []:
                print(f"{infoS} Deflatestream data found! Attempting to decompress...")
                decompress_obj = zlib.decompressobj(-zlib.MAX_WBITS)
                decompressed_data = decompress_obj.decompress(b64_data)
                output = io.BytesIO(decompressed_data).read().decode('ascii')
                self.save_data_into_file(output_file="sc0pe_decoded_b64_payload.bin", data=output.encode())
            elif gzipstream != []:
                print(f"{infoS} Gzip data found! Attempting to decompress...")
                decompressed_data = gzip.decompress(b64_data)
                self.save_data_into_file(output_file="sc0pe_decoded_b64_payload.bin", data=decompressed_data)
            else:
                print(f"{infoS} There is no compression. Extracting payload anyway...")
                self.save_data_into_file(output_file="sc0pe_decoded_b64_payload.bin", data=b64_data)
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def detect_and_carve_pe_executable_non_xored(self):
        print(f"\n{infoS} Searching for: [bold green]PE Executable[white] patterns...")
        pe_match = re.findall(r"4d5a90", str(self.all_strings), re.IGNORECASE)
        if pe_match != []:
            print(f"{infoS} Looks like we have possible [bold green]{len(pe_match)}[white] patterns. Attempting to extraction...")
            counter = 0
            for pat in self.all_strings:
                if "4D5A90" in pat and "=" in pat:
                    sanitized = self.buffer_sanitizer(executable_buffer=pat.split("=")[1])
                    self.save_data_into_file(output_file=f"sc0pe_extracted_pe_{counter}.exe", data=binascii.unhexlify(sanitized))
                    counter += 1
        else:
            print(f"{errorS} There is no possible PE executable pattern found!\n")

    def buffer_sanitizer(self, executable_buffer):
        # Unwanted characters
        unwanted = ['@', '\t', '\n', " ", "\'"]
        for uc in unwanted:
            if uc in executable_buffer:
                executable_buffer = executable_buffer.replace(uc, "")

        return executable_buffer

# Execution
pwsh_analyzer = PowerShellAnalyzer(sys.argv[1])
pwsh_analyzer.scan_code_patterns()
pwsh_analyzer.extract_path_values()
pwsh_analyzer.check_executions()
pwsh_analyzer.find_payloads_xored()
pwsh_analyzer.check_for_non_xored_payloads_presence()
