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
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    # Allow running module directly without the path cache.
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Configurating strings parameter and make compatability
path_seperator = "/"
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"
    path_seperator = "\\"

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
                "decoded_base64_values_file": "",
                "decoded_base64_values_count": 0,
            },
            "errors": [],
            "extracted_urls": [],
            "extracted_ips": [],
            "large_variable_blobs": [],
        }
        self.decoded_b64_entries = []
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

    def _record_decoded_b64_text(self, decoded_text, output_file=""):
        text = str(decoded_text or "").replace("\x00", "").strip()
        if len(text) < 10:
            return
        entry = {
            "output_file": str(output_file or ""),
            "decoded_text": text,
        }
        if entry not in self.decoded_b64_entries:
            self.decoded_b64_entries.append(entry)

    def _maybe_record_bytes_as_text(self, blob, output_file=""):
        try:
            raw = bytes(blob)
        except Exception:
            return
        try:
            text = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
        except Exception:
            text = ""
        # Prefer readable text; if not readable, keep a hex representation so decoded value is still preserved.
        if len(text) < 10:
            hex_text = raw.hex()
            if hex_text:
                self._record_decoded_b64_text(decoded_text=f"[non-printable-bytes-hex]\n{hex_text}", output_file=output_file)
            return
        printable_ratio = sum(ch.isprintable() for ch in text) / max(len(text), 1)
        if printable_ratio >= 0.85:
            self._record_decoded_b64_text(decoded_text=text, output_file=output_file)
            return
        hex_text = raw.hex()
        if hex_text:
            self._record_decoded_b64_text(decoded_text=f"[non-printable-bytes-hex]\n{hex_text}", output_file=output_file)

    def write_decoded_b64_list_file(self):
        if not self.decoded_b64_entries:
            return

        out_name = "qu1cksc0pe_decoded_b64_values.txt"
        try:
            with open(out_name, "w", encoding="utf-8", errors="ignore") as ff:
                for idx, entry in enumerate(self.decoded_b64_entries, 1):
                    ff.write(f"[{idx}] output_file: {entry['output_file'] or '-'}\n")
                    ff.write(entry["decoded_text"])
                    if not entry["decoded_text"].endswith("\n"):
                        ff.write("\n")
                    ff.write("-" * 70 + "\n")
            print(f"{infoS} Decoded BASE64 values list saved into: [bold green]{out_name}[white]")
            self.report["payloads"]["decoded_base64_values_file"] = out_name
            self.report["payloads"]["decoded_base64_values_count"] = len(self.decoded_b64_entries)
            self.report["payloads"]["normal_base64_decoded_files"] = [out_name]
        except Exception as exc:
            self.report["errors"].append(f"decoded_base64_values_write_error: {exc}")
		
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
            r'(Start-Process\s+\"[^\"]+\.exe\")',
            r'(?:IEX|Invoke-Expression)\s*\(',
            r'&\s*\(\s*\$\w+',
            r'&\s*\$\w+',
            r'Invoke-Command\b',
            r'WMIC\s+process\s+call\s+create',
            r'mshta(?:\.exe)?\s+',
            r'(?:c|w)script(?:\.exe)?\s+',
            r'rundll32(?:\.exe)?\s+',
            r'msiexec(?:\.exe)?\s+/[iq]',
            r'bitsadmin\s+/transfer',
            r'certutil\s+-decode',
            r'(?:New-Object|\.)\s*Net\.WebClient',
            r'(?:DownloadFile|DownloadString|DownloadData)\s*\(',
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
        path_patterns = [
            r"'([A-Z]:\\[^']+)'",           # single-quoted drive paths
            r'"([A-Z]:\\[^"]+)"',           # double-quoted drive paths
            r"'(\\\\[^']+)'",               # single-quoted UNC paths
            r'"(\\\\[^"]+)"',               # double-quoted UNC paths
            r'(\$env:\w+\\[^\s\'">\]]+)',   # environment variable paths
        ]
        path_table = Table()
        path_table.add_column("Extracted [bold green]PATH[white] values", justify="center")
        found = False
        seen = set()
        for path_regex in path_patterns:
            for path in re.findall(path_regex, str(self.all_strings), re.IGNORECASE):
                if path in seen:
                    continue
                seen.add(path)
                path_table.add_row(path)
                found = True
                try:
                    if path not in self.report["extracted_paths"]:
                        self.report["extracted_paths"].append(path)
                except Exception:
                    pass
        if found:
            print(path_table)
        else:
            print(f"{errorS} There is no pattern about path values...\n")

    # ------------------------------------ XORED Payload detection and extratcion
    def check_for_xor_key(self):
        text = str(self.all_strings)
        # Literal integer key: -bxor 0x1F or -bxor 31
        for pattern in (r'-bxor\s+(0x[0-9a-fA-F]+)', r'-bxor\s+(\d+)'):
            m = re.findall(pattern, text, re.IGNORECASE)
            if m:
                val = m[0]
                return str(int(val, 16)) if val.startswith(("0x", "0X")) else val
        # Variable key: -bxor $keyVar  → return variable name for reporting
        mv = re.findall(r'-bxor\s+(\$\w+)', text, re.IGNORECASE)
        if mv:
            return mv[0]   # e.g. "$key" — caller receives a string, won't cast to int
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
        try:
            xor_int = int(xor_key) & 0xFF
        except (ValueError, TypeError):
            print(f"{errorS} XOR key [bold yellow]{xor_key}[white] is a variable — cannot decrypt statically.\n")
            return
        if payload_type == "base64":
            byte_arr = bytearray(base64.b64decode(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self._maybe_record_bytes_as_text(blob=byte_arr, output_file="base64_xored_payload")
            print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
        elif payload_type == "ascii":
            temp_array = []
            for num in payload:
                temp_array.append(int(num))
            byte_arr = bytearray(temp_array)
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_ascii_numbers_payload.bin", data=byte_arr)
        elif payload_type == "hex":
            byte_arr = bytearray(binascii.unhexlify(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_hex_values_payload.bin", data=byte_arr)

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
                self._record_decoded_b64_text(decoded_text=output, output_file="base64_non_xored_deflate")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
            elif gzipstream != []:
                print(f"{infoS} Gzip data found! Attempting to decompress...")
                decompressed_data = gzip.decompress(b64_data)
                self._maybe_record_bytes_as_text(blob=decompressed_data, output_file="base64_non_xored_gzip")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
            else:
                print(f"{infoS} There is no compression. Extracting payload anyway...")
                self._maybe_record_bytes_as_text(blob=b64_data, output_file="base64_non_xored_raw")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
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
                    self._maybe_record_bytes_as_text(blob=decbf, output_file="base64_normal_match")
                except:
                    continue
            print(f"{infoS} Decoded BASE64 payload values queued for [bold green]qu1cksc0pe_decoded_b64_values.txt[white]")
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

    def extract_network_iocs(self):
        """Extract URLs and IP addresses from the script."""
        print(f"\n{infoS} Performing network IOC extraction...")
        text = str(self.all_strings)
        found = False

        urls = list(dict.fromkeys(re.findall(r'https?://[^\s\'"<>\]]+', text, re.IGNORECASE)))
        if urls:
            url_table = Table()
            url_table.add_column("Extracted [bold green]URL[white] values", justify="left")
            for u in urls[:50]:
                url_table.add_row(u)
            print(url_table)
            self.report["extracted_urls"] = urls[:50]
            found = True

        ips = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        # filter obviously non-IP version strings (0.0.0.0 is still valid)
        ips = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))]
        if ips:
            ip_table = Table()
            ip_table.add_column("Extracted [bold green]IP[white] values", justify="center")
            for ip in ips[:50]:
                ip_table.add_row(ip)
            print(ip_table)
            self.report["extracted_ips"] = ips[:50]
            found = True

        if not found:
            print(f"{errorS} There are no network IOCs found!\n")

    def detect_large_variable_blobs(self):
        """Detect variables holding large Base64-like blobs (e.g. encrypted payloads)."""
        print(f"\n{infoS} Performing large variable blob detection...")
        # Read source directly for multi-line variable assignments
        try:
            with open(self.target_file, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except Exception:
            source = str(self.all_strings)

        pattern = r'\$(\w+)\s*=\s*["\']([A-Za-z0-9+/=]{200,})["\']'
        blobs = re.findall(pattern, source)
        if not blobs:
            print(f"{errorS} There are no large variable blobs found!\n")
            return

        blob_table = Table()
        blob_table.add_column("[bold green]Variable[white]", justify="center")
        blob_table.add_column("[bold green]Length[white]", justify="center")
        blob_table.add_column("[bold green]Preview (first 60 chars)[white]", justify="left")
        report_blobs = []
        for var_name, blob in blobs[:20]:
            blob_table.add_row(f"${var_name}", str(len(blob)), blob[:60] + "...")
            report_blobs.append({"variable": f"${var_name}", "length": len(blob), "preview": blob[:60]})
        print(blob_table)
        self.report["large_variable_blobs"] = report_blobs

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
        pwsh_analyzer.extract_network_iocs()
        pwsh_analyzer.detect_large_variable_blobs()
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

    # Aggregate decoded BASE64 text values into a single list file.
    pwsh_analyzer.write_decoded_b64_list_file()

    if get_argv(2) == "True":
        save_report("powershell", pwsh_analyzer.report)


if __name__ == "__main__":
    main()
