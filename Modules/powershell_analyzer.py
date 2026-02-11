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
import os
import hashlib
	
from utils.helpers import err_exit, get_argv, save_report
	
try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
	
# Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(".path_handler", "r").read().strip()
except Exception:
    # Allow running module directly without `.path_handler`.
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Configurating strings parameter and make compatability
path_seperator = "/"
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"
    path_seperator = "\\"
else:
    pass

# Load patterns
powershell_code_patterns = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}powershell_code_patterns.json"))

warnings.filterwarnings("ignore")

class PowerShellAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.target_buffer_normal = subprocess.run(["strings", strings_param, self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if sys.platform != "win32":
            self.target_buffer_16bit = subprocess.run(["strings", strings_param, "-e", "l", self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n")+self.target_buffer_normal.stdout.decode().split("\n")
        else:
            self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")
        # NOTE: Avoid inline flag blocks like `(?i)` mid-pattern; use re.IGNORECASE in calls instead.
        self.pattern_b64 = [
                            r"\[sYsteM\.coNvert\]::FROmbaSe64StRiNG\(\s*[\'\"]([^'\"]*)[\'\"]\s*\)|\[System\.Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=]+)'\s*\)",
                            r"[A-Za-z0-9+/=]{40,}"
                        ]
        self.pattern_ascii = r'\[Byte\[\]\]\((\d+(?:,\d+)*)\)'
        self.pattern_hex = r'\[System\.Convert\]::fromHEXString\(\'([0-9a-fA-F]+)\'\)'

        # JSON report object (used when qu1cksc0pe runs with --report/--ai).
        self.report = {
            "filename": self.target_file,
            "file_type": "POWERSHELL",
            "hash_md5": "",
            "hash_sha1": "",
            "hash_sha256": "",
            "matched_patterns": {},
            "extracted_paths": [],
            "possible_executions": [],
            "payloads": {
                "xor_key": "",
                "xor_detected": False,
                "decoded_files": [],
                "non_xored_detected": False,
                "non_xored_files": [],
                "normal_base64_decoded_files": [],
            },
            "errors": [],
        }
        self._calc_hashes_into_report()
        self._write_temp_txt()

    def _calc_hashes_into_report(self):
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(self.target_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            self.report["hash_md5"] = md5.hexdigest()
            self.report["hash_sha1"] = sha1.hexdigest()
            self.report["hash_sha256"] = sha256.hexdigest()
        except Exception:
            pass

    def _write_temp_txt(self):
        """
        smart_analyzer.py enriches LLM context by reading ./temp.txt.
        PowerShell analysis previously didn't create it, so --ai had less evidence.
        """
        try:
            if str(os.environ.get("SC0PE_POWERSHELL_WRITE_TEMP_TXT", "1")).strip() == "0":
                return
        except Exception:
            pass

        try:
            # Prefer the strings output (already collected). Keep it simple and ASCII-safe.
            data = "\n".join([s for s in (self.all_strings or []) if isinstance(s, str)])
            with open("temp.txt", "w", encoding="utf-8", errors="ignore") as f:
                f.write(data)
        except Exception:
            # Best-effort only.
            pass

    def _extract_b64_from_match(self, m):
        # re.findall with alternation returns tuples; pick the first non-empty group.
        if isinstance(m, tuple):
            for it in m:
                if it:
                    return str(it)
            return ""
        return str(m or "")

    def save_data_into_file(self, output_file, data):
        with open(output_file, "wb") as ff:
            ff.write(data)
        print(f"{infoS} Decoded payload saved into: [bold green]{output_file}[white]")
        try:
            self.report["payloads"]["decoded_files"].append(output_file)
        except Exception:
            pass
	
    def scan_code_patterns(self):
        print(f"{infoS} Performing pattern scan...")
        self.report["matched_patterns"] = {}
        for pat in powershell_code_patterns:
            pat_table = Table()
            pat_table.add_column(f"Extracted patterns about [bold green]{pat}[white]", justify="center")
            found = []
            for code in powershell_code_patterns[pat]["patterns"]:
                matchh = re.findall(code, str(self.all_strings), re.IGNORECASE)
                if matchh != []:
                    pat_table.add_row(code)
                    found.append(code)
            if found:
                print(pat_table)
                self.report["matched_patterns"][pat] = found
	
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
                    try:
                        self.report["possible_executions"].append(mm)
                    except Exception:
                        pass
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
                try:
                    if path not in self.report["extracted_paths"]:
                        self.report["extracted_paths"].append(path)
                except Exception:
                    pass
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
            try:
                self.report["payloads"]["xor_detected"] = True
                self.report["payloads"]["xor_key"] = str(self.check_for_xor_key() or "")
            except Exception:
                pass
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
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_b64_payload.bin", data=byte_arr)
        elif payload_type == "ascii":
            temp_array = []
            for num in payload:
                temp_array.append(int(num))
            byte_arr = bytearray(temp_array)
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_ascii_numbers_payload.bin", data=byte_arr)
        elif payload_type == "hex":
            byte_arr = bytearray(binascii.unhexlify(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ int(xor_key)
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_hex_values_payload.bin", data=byte_arr)
        else:
            pass

    def detect_and_carve_base64_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64[0], str(self.all_strings), re.IGNORECASE)
        if b64matches != []:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                payload = self._extract_b64_from_match(b64matches[0])
                if payload:
                    self.xor_decrypt_and_save(payload_type="base64", payload=payload, xor_key=xor_key)
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
        try:
            b64_payload = re.findall(self.pattern_b64[0], str(self.all_strings), re.IGNORECASE)
        except re.error as e:
            self.report["errors"].append(f"regex_error_base64_pattern: {e}")
            b64_payload = []
        ascii_payload = re.findall(self.pattern_ascii, str(self.all_strings), re.IGNORECASE)
        hex_payload = re.findall(self.pattern_hex, str(self.all_strings), re.IGNORECASE)
        pe_payload = re.findall(r"4d5a90", str(self.all_strings), re.IGNORECASE)
        if b64_payload != [] or ascii_payload != [] or hex_payload != [] or pe_payload != []:
            if self.check_for_xor_key() is None:
                print(f"{infoS} Looks like we have a possible [bold green]non-XOR\'ed[white] payload. Attempting to detect its type...")
                try:
                    self.report["payloads"]["non_xored_detected"] = True
                except Exception:
                    pass
                self.detect_and_carve_b64_non_xored()
                self.detect_and_carve_pe_executable_non_xored()
            else:
                print(f"{errorS} Couldn\'t detect XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about non-XOR\'ed payloads!\n")

    def detect_and_carve_b64_non_xored(self):
        # This method is for: frombase64 type payloads
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64[0], str(self.all_strings), re.IGNORECASE)
        if b64matches != []:
            payload = self._extract_b64_from_match(b64matches[0])
            if not payload:
                return
            b64_data = base64.b64decode(payload)
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for compressed data presence...")
            deflatestream = re.findall(r'Io\.CoMpRESSiOn\.defLaTEstReam', str(self.all_strings), re.IGNORECASE)
            gzipstream = re.findall(r"IO\.Compression\.GZipStream", str(self.all_strings), re.IGNORECASE)
            if deflatestream != []:
                print(f"{infoS} Deflatestream data found! Attempting to decompress...")
                decompress_obj = zlib.decompressobj(-zlib.MAX_WBITS)
                decompressed_data = decompress_obj.decompress(b64_data)
                output = io.BytesIO(decompressed_data).read().decode('ascii')
                out_name = "qu1cksc0pe_decoded_b64_payload.bin"
                self.save_data_into_file(output_file=out_name, data=output.encode())
                self.report["payloads"]["non_xored_files"].append(out_name)
            elif gzipstream != []:
                print(f"{infoS} Gzip data found! Attempting to decompress...")
                decompressed_data = gzip.decompress(b64_data)
                out_name = "qu1cksc0pe_decoded_b64_payload.bin"
                self.save_data_into_file(output_file=out_name, data=decompressed_data)
                self.report["payloads"]["non_xored_files"].append(out_name)
            else:
                print(f"{infoS} There is no compression. Extracting payload anyway...")
                out_name = "qu1cksc0pe_decoded_b64_payload.bin"
                self.save_data_into_file(output_file=out_name, data=b64_data)
                self.report["payloads"]["non_xored_files"].append(out_name)
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def check_only_legit_base64(self):
        print(f"\n{infoS} Searching for: [bold green]Normal BASE64[white] patterns...")
        b64_match = re.findall(self.pattern_b64[1], str(self.all_strings), re.IGNORECASE)
        if b64_match:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            for enc in b64_match:
                try:
                    decbf = base64.b64decode(enc)
                    if len(decbf.decode()) > 10:
                        out_name = f"qu1cksc0pe_decoded_b64_{len(decbf.decode())}.bin"
                        with open(out_name, "w") as ff:
                            ff.write(decbf.decode())
                        print(f"{infoS} Decoded payload saved into: [bold green]{out_name}[white]")
                        try:
                            self.report["payloads"]["normal_base64_decoded_files"].append(out_name)
                        except Exception:
                            pass
                except:
                    continue
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
                    out_name = f"qu1cksc0pe_extracted_pe_{counter}.exe"
                    self.save_data_into_file(output_file=out_name, data=binascii.unhexlify(sanitized))
                    try:
                        self.report["payloads"]["non_xored_files"].append(out_name)
                    except Exception:
                        pass
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

def main():
    if len(sys.argv) < 2:
        err_exit("Usage: powershell_analyzer.py <file> [save_report=True|False]")

    target_pwsh = sys.argv[1]
    pwsh_analyzer = PowerShellAnalyzer(target_pwsh)
    try:
        pwsh_analyzer.scan_code_patterns()
        pwsh_analyzer.extract_path_values()
        pwsh_analyzer.check_executions()
        pwsh_analyzer.find_payloads_xored()
        pwsh_analyzer.check_for_non_xored_payloads_presence()
        pwsh_analyzer.check_only_legit_base64()
    except Exception as e:
        # Keep module alive; allow --ai flow to proceed with a partial report.
        try:
            pwsh_analyzer.report["errors"].append(f"analysis_error: {e}")
        except Exception:
            pass
        print(f"{errorS} PowerShell analysis error: {e}")

    if get_argv(2) == "True":
        save_report("powershell", pwsh_analyzer.report)


if __name__ == "__main__":
    main()
