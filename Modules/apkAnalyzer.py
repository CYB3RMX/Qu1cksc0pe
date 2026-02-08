#!/usr/bin/python3

import json
import sys
import re
import os
import getpass
import configparser
import requests
import subprocess
import shutil
import zipfile
import time
import hashlib
import math
import struct
from urllib.parse import urlparse
from datetime import date

from utils.helpers import err_exit
from analysis.multiple.multi import perform_strings, chk_wlist, yara_rule_scanner as shared_yara_rule_scanner

# Module handling
try:
    from androguard.core.bytecodes.apk import APK
except:
    err_exit("Error: >androguard< module not found.")

try:
    from rich import print
    from rich.table import Table
    from rich.progress import track
except:
    err_exit("Error: >rich< module not found.")

try:
    import pyaxmlparser
except:
    err_exit("Error: >pyaxmlparser< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Get python binary
if shutil.which("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Compatibility
homeD = os.path.expanduser("~")
path_seperator = "/"
setup_scr = "setup.sh"
strings_param = "-a"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"
else:
    pass

# Getting target APK
targetAPK = sys.argv[1]

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# necessary variables
danger = 0
normal = 0

# Gathering all strings from file
allStrings = perform_strings(targetAPK)

# Parsing date
today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Gathering username
username = getpass.getuser()

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}detections.json"))

# Creating report structure

# Read config file
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}libScanner.conf")

class APKAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        # Report verbosity control:
        # - default: compact JSON (avoid duplicating heavy fields)
        # - set `SC0PE_ANDROID_REPORT_DETAILED=1` to keep full details
        self.detailed_report = os.environ.get("SC0PE_ANDROID_REPORT_DETAILED", "").strip() == "1"
        self.decompiler_path = self.resolve_decompiler_path(conf["Decompiler"]["decompiler"])
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self.full_path_file = os.path.abspath(self.target_file)
        self.max_detailed_entries = 25
        self.low_signal_categories = {"Java Reflection", "File Operations"}
        self.last_decompile_error = ""
        self.last_decompile_error_detail = ""
        # JADX may return a non-zero exit code even when it produced usable output.
        # Keep "hard" errors separate from "soft" warnings so we can continue analysis.
        self.last_decompile_warning = ""
        self.last_decompile_warning_detail = ""
        self.last_source_report = {
            "matched_files": 0,
            "shown_files": 0,
            "hidden_low_signal_third_party_files": 0,
            "category_counts": {},
            "findings": []
        }
        self.reportz = {
            "target_file": "",
            "analysis_type": "",
            "app_name": "",
            "package_name": "",
            "play_store": False,
            "sdk_version": "",
            "main_activity": "",
            "features": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "libraries": [],
            "signatures": [],
            "permissions": [],
            "matched_rules": [],
            # Backwards-compatible: keep `matched_rules` as-is, and store a richer form here.
            "yara_detailed_matches": [],
            "native_libraries": [],
            "native_library_triage": [],
            "code_patterns": {},
            "decompilation": {
                "attempted": False,
                "success": False,
                "output_dir": "",
                "error": "",
                "error_detail": "",
                "warning": "",
                "warning_detail": ""
            },
            "manifest": {
                "present": False,
                "entries": {}
            },
            "source_summary": {
                "matched_files": 0,
                "shown_files": 0,
                "hidden_low_signal_third_party_files": 0,
                "category_counts": {}
            },
            "source_findings_total": 0,
            "source_findings_truncated": False,
            "source_findings": [],
            "user": username,
            "date": dformat,
        }
        # Pre-compile regex patterns once. The built-in `re` cache is small and
        # gets thrashed for large pattern sets, which makes per-file scanning slow.
        self._compiled_code_patterns = self._compile_code_patterns()

    def _sha256_file(self, fpath):
        h = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _is_elf(self, fpath):
        try:
            with open(fpath, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except Exception:
            return False

    def _infer_abi_from_path(self, any_path):
        p = (any_path or "").replace("\\", "/").lower()
        for abi in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "mips64", "mips"):
            if f"/{abi}/" in p:
                return abi
        return "unknown"

    def _shannon_entropy_bytes(self, b):
        if not b:
            return 0.0
        counts = [0] * 256
        for x in b:
            counts[x] += 1
        n = len(b)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    def _entropy_file(self, fpath, max_bytes=1024 * 1024):
        try:
            with open(fpath, "rb") as f:
                buf = f.read(max_bytes)
            return self._shannon_entropy_bytes(buf)
        except Exception:
            return None

    def _parse_elf_header(self, fpath):
        """
        Minimal ELF header parser (no external deps).
        Returns dict with class/endian/machine or None if not ELF/parseable.
        """
        try:
            with open(fpath, "rb") as f:
                hdr = f.read(64)
            if len(hdr) < 20 or hdr[0:4] != b"\x7fELF":
                return None
            ei_class = hdr[4]  # 1=32-bit, 2=64-bit
            ei_data = hdr[5]   # 1=little, 2=big
            endian = "<" if ei_data == 1 else ">" if ei_data == 2 else None
            if not endian:
                return None
            e_machine = struct.unpack(endian + "H", hdr[18:20])[0]
            machine_map = {
                3: "x86",
                8: "mips",
                40: "arm",
                62: "x86_64",
                183: "aarch64",
            }
            return {
                "class": 32 if ei_class == 1 else 64 if ei_class == 2 else None,
                "endian": "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown",
                "machine": int(e_machine),
                "machine_name": machine_map.get(e_machine, "unknown"),
            }
        except Exception:
            return None

    def _infer_abi_from_elf(self, elf_header):
        if not elf_header:
            return "unknown"
        m = elf_header.get("machine_name", "unknown")
        if m == "aarch64":
            return "arm64-v8a"
        if m == "arm":
            return "armeabi-v7a"
        if m == "x86_64":
            return "x86_64"
        if m == "x86":
            return "x86"
        if m == "mips":
            return "mips"
        return "unknown"

    def _extract_ascii_strings_from_bytes(self, b, min_len=4, max_strings=2000):
        out = []
        cur = bytearray()
        for x in b:
            if 32 <= x <= 126:
                cur.append(x)
                continue
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
                if len(out) >= max_strings:
                    return out
            cur = bytearray()
        if len(cur) >= min_len and len(out) < max_strings:
            out.append(cur.decode("ascii", errors="ignore"))
        return out

    def native_lib_triage(self, fpath, zip_path=""):
        """
        Lightweight heuristics for native libs:
        - ELF header info (arch, class, endian)
        - entropy estimate
        - indicator strings + simple URL/IP extraction
        """
        triage = {
            "path": zip_path or fpath,
            "zip_path": zip_path,
            "size": None,
            "elf": False,
            "elf_header": None,
            "abi": "unknown",
            "entropy": None,
            "indicator_hits": {},
            "indicator_matches": {},
            "urls": [],
            "ip_addresses": [],
        }
        try:
            triage["size"] = os.path.getsize(fpath)
        except Exception:
            pass

        triage["elf"] = self._is_elf(fpath)
        elf_hdr = self._parse_elf_header(fpath) if triage["elf"] else None
        triage["elf_header"] = elf_hdr

        abi = self._infer_abi_from_path(zip_path or fpath)
        if abi == "unknown":
            abi = self._infer_abi_from_elf(elf_hdr)
        triage["abi"] = abi

        triage["entropy"] = self._entropy_file(fpath, max_bytes=1024 * 1024)

        max_scan = 4 * 1024 * 1024
        try:
            with open(fpath, "rb") as f:
                buf = f.read(max_scan)
        except Exception:
            buf = b""

        strings = self._extract_ascii_strings_from_bytes(buf, min_len=4, max_strings=3000)
        joined = "\n".join(strings)

        try:
            triage["urls"] = sorted(set(re.findall(r"https?://[^\s\"'<>]+", joined)))[:50]
        except Exception:
            triage["urls"] = []
        try:
            triage["ip_addresses"] = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", joined)))[:50]
        except Exception:
            triage["ip_addresses"] = []

        indicators = {
            "jni": ("JNI_OnLoad", "JNI_OnUnload"),
            "dynamic_loading": ("dlopen", "dlsym", "android_dlopen_ext"),
            "process_exec": ("system(", "popen(", "execve", "fork", "kill(", "ptrace", "prctl"),
            "hooking": ("frida", "gadget", "xposed", "substrate", "magisk", "zygisk"),
            "anti_debug": ("ptrace", "TracerPid", "ro.debuggable", "ro.secure"),
            "fs_proc": ("/proc/", "/system/bin/", "/data/local/tmp"),
            "crypto": ("AES", "DES", "RSA", "ChaCha", "HMAC", "SHA1", "SHA256", "MD5"),
            "network": ("http://", "https://", "User-Agent", "socket", "connect", "SSL", "TLS"),
        }
        matches = {}
        hits = {}
        low = joined.lower()
        for cat, needles in indicators.items():
            found = []
            for n in needles:
                try:
                    if n.lower() in low:
                        found.append(n)
                except Exception:
                    continue
            if found:
                # Keep stable ordering but unique.
                found_unique = list(dict.fromkeys(found))
                matches[cat] = found_unique
                hits[cat] = len(found_unique)
        triage["indicator_hits"] = hits
        triage["indicator_matches"] = matches
        return triage

    def _resolve_yara_rule_dir(self):
        # Deprecated: YARA scanning is delegated to Modules/analysis/multiple/multi.py
        return ""

    def _load_yara_rules(self):
        # Deprecated: YARA scanning is delegated to Modules/analysis/multiple/multi.py
        return

    def _list_so_files_in_dir(self, root_dir):
        if not root_dir or not os.path.isdir(root_dir):
            return []
        out = []
        for p in self.recursive_dir_scan(root_dir):
            if p.lower().endswith(".so"):
                out.append(p)
        return out

    def _safe_extract_zip_member(self, zf, member_name, dest_dir):
        # Prevent zip-slip.
        dest_abs = os.path.abspath(dest_dir)
        member_name = (member_name or "").lstrip("/").replace("\\", "/")
        out_path = os.path.abspath(os.path.join(dest_abs, member_name))
        if not out_path.startswith(dest_abs + os.sep):
            return None
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        try:
            with zf.open(member_name, "r") as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
        except Exception:
            return None
        return out_path

    def extract_native_libs_from_apk(self, dest_dir):
        """
        Extract native libs directly from APK zip, independent of JADX output.
        Returns list of dicts: {"path", "zip_path", "size"}.
        """
        results = []
        try:
            os.makedirs(dest_dir, exist_ok=True)
            with zipfile.ZipFile(self.full_path_file, "r") as zf:
                for info in zf.infolist():
                    zpath = info.filename or ""
                    zlow = zpath.lower()
                    if not zlow.endswith(".so"):
                        continue
                    out_path = self._safe_extract_zip_member(zf, zpath, dest_dir)
                    if not out_path:
                        continue
                    results.append({"path": out_path, "zip_path": zpath, "size": int(getattr(info, "file_size", 0) or 0)})
        except Exception:
            return []
        return results

    def _compile_code_patterns(self):
        compiled = []
        try:
            for category, data in pattern_file.items():
                for pat in data.get("patterns", []):
                    try:
                        compiled.append((category, pat, re.compile(pat)))
                    except Exception:
                        continue
        except Exception:
            pass
        return compiled

    def _scan_buffer_for_patterns(self, buf, record):
        """
        Scan buffer with precompiled patterns and update record in-place.
        record: {"patterns": set(), "categories": set()}
        """
        for cat, pat_str, pat_re in self._compiled_code_patterns:
            try:
                if pat_re.search(buf):
                    record["patterns"].add(pat_str)
                    if cat not in ("", None):
                        record["categories"].add(cat)
            except Exception:
                continue

    def is_valid_jadx_launcher(self, launcher_path):
        if not launcher_path or not os.path.exists(launcher_path):
            return False

        launcher_dir = os.path.dirname(launcher_path)
        possible_libs = [
            os.path.abspath(os.path.join(launcher_dir, "..", "lib")),
            os.path.abspath(os.path.join(launcher_dir, "lib")),
        ]
        for lib_dir in possible_libs:
            if os.path.isdir(lib_dir):
                for fname in os.listdir(lib_dir):
                    if fname.startswith("jadx-cli-") and fname.endswith(".jar"):
                        return True
        return False

    def resolve_decompiler_path(self, configured_path):
        cleaned = str(configured_path).strip().strip('"').strip("'")
        cleaned = os.path.expandvars(os.path.expanduser(cleaned))

        candidates = []
        if cleaned:
            candidates.append(cleaned)

        jadx_on_path = shutil.which("jadx")
        if jadx_on_path:
            candidates.append(jadx_on_path)

        default_jadx_dir = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}jadx"
        candidates.append(f"{default_jadx_dir}{path_seperator}bin{path_seperator}jadx")
        candidates.append(f"{default_jadx_dir}{path_seperator}jadx")

        if os.path.isdir(default_jadx_dir):
            for subdir in os.listdir(default_jadx_dir):
                subdir_full = f"{default_jadx_dir}{path_seperator}{subdir}"
                if os.path.isdir(subdir_full):
                    candidates.append(f"{subdir_full}{path_seperator}bin{path_seperator}jadx")
                    candidates.append(f"{subdir_full}{path_seperator}jadx")

        if sys.platform == "win32":
            candidates.append(f"{default_jadx_dir}{path_seperator}bin{path_seperator}jadx.bat")
            candidates.append(f"{default_jadx_dir}{path_seperator}jadx.bat")

        for cpath in candidates:
            if self.is_valid_jadx_launcher(cpath):
                return cpath

        return cleaned

    def ensure_java_runtime(self):
        java_path = shutil.which("java")
        if java_path:
            return True

        java_home = os.environ.get("JAVA_HOME", "")
        if java_home:
            java_home_bin = os.path.join(java_home, "bin", "java")
            if os.path.exists(java_home_bin):
                return True

        print("[blink]Java Runtime[white] not found. Skipping decompilation...")
        if sys.platform == "win32":
            print(f"{infoS} Install JRE/JDK and set [bold green]JAVA_HOME[white].")
        else:
            print(f"{infoS} Install Java (example): [bold green]sudo apt-get install default-jre-headless[white]")
        return False

    def run_decompiler(self, output_dir):
        self.last_decompile_error = ""
        self.last_decompile_error_detail = ""
        self.last_decompile_warning = ""
        self.last_decompile_warning_detail = ""
        if not self.decompiler_path or not os.path.exists(self.decompiler_path):
            print("[blink]Decompiler([bold green]JADX[white])[/blink] [white]not found. Skipping...")
            if self.decompiler_path:
                print(f"{infoS} Configured decompiler path: [bold yellow]{self.decompiler_path}")
            self.last_decompile_error = "decompiler_not_found"
            return False

        if not self.ensure_java_runtime():
            self.last_decompile_error = "java_runtime_not_found"
            return False

        # JADX cannot process archives containing encrypted zip entries.
        encrypted_entries = self.get_encrypted_zip_entries(self.full_path_file)
        if encrypted_entries is not None and encrypted_entries != []:
            self.last_decompile_error = "encrypted_zip_entries_detected"
            self.last_decompile_error_detail = f"encrypted_entry_count={len(encrypted_entries)}"
            print(f"{errorS} Decompiler execution skipped.")
            print(f">>> [bold yellow]Details:[white] encrypted zip entries detected ({len(encrypted_entries)}).")
            print(f">>> [bold yellow]First entry:[white] {encrypted_entries[0]}")
            return False

        def _decompile_output_usable(out_dir):
            try:
                if not out_dir or not os.path.isdir(out_dir):
                    return False
                # Common JADX layout: <out>/sources and <out>/resources
                sources_dir = os.path.join(out_dir, "sources")
                resources_dir = os.path.join(out_dir, "resources")
                if os.path.isdir(sources_dir):
                    for root, _, files in os.walk(sources_dir):
                        for f in files:
                            if f.endswith((".java", ".kt", ".smali", ".xml", ".js", ".json")):
                                return True
                            # Even obfuscated output should still yield some files.
                            return True
                if os.path.isdir(resources_dir):
                    for root, _, files in os.walk(resources_dir):
                        if files:
                            return True
                return False
            except Exception:
                return False

        proc = subprocess.run(
            [self.decompiler_path, "-q", "-d", output_dir, self.full_path_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            # JADX often returns non-zero when some classes failed, but still writes output.
            # If we have usable output, continue and record a warning instead of failing hard.
            usable = _decompile_output_usable(output_dir)
            if usable:
                print(f"{errorS} Decompiler finished with errors but produced output. Continuing...")
            else:
                print(f"{errorS} Decompiler execution failed.")
            print(f">>> [bold yellow]Exit code:[white] {proc.returncode}")

            first_line = ""
            if proc.stderr:
                first_line = proc.stderr.strip().splitlines()[0]
            elif proc.stdout:
                first_line = proc.stdout.strip().splitlines()[0]

            if first_line:
                print(f">>> [bold yellow]Details:[white] {first_line}")

            if usable:
                self.last_decompile_warning = first_line if first_line else f"exit_code_{proc.returncode}"
                self.last_decompile_warning_detail = f"exit_code={proc.returncode}"
                return True

            self.last_decompile_error = first_line if first_line else f"exit_code_{proc.returncode}"
            self.last_decompile_error_detail = f"exit_code={proc.returncode}"
            return False
        return True

    def get_encrypted_zip_entries(self, file_path):
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                return [info.filename for info in zf.infolist() if info.flag_bits & 0x1]
        except Exception:
            return None

    def report_writer(self, target_os, report_object):
        clean_report = self.prepare_clean_report(report_object)
        with open(f"sc0pe_{target_os}_report.json", "w") as rp_file:
            json.dump(clean_report, rp_file, indent=4)
        print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_{target_os}_report.json\n")

    def prune_empty_values(self, data):
        if isinstance(data, dict):
            pruned = {}
            for key, value in data.items():
                p_val = self.prune_empty_values(value)
                if p_val in ("", None, [], {}):
                    continue
                pruned[key] = p_val
            return pruned
        if isinstance(data, list):
            pruned_list = []
            for item in data:
                p_item = self.prune_empty_values(item)
                if p_item in ("", None, [], {}):
                    continue
                pruned_list.append(p_item)
            return pruned_list
        return data

    def prepare_clean_report(self, report_object):
        clean_report = json.loads(json.dumps(report_object))
        analysis_type = str(clean_report.get("analysis_type", "")).upper()
        detailed = os.environ.get("SC0PE_ANDROID_REPORT_DETAILED", "").strip() == "1"

        if analysis_type in ("JAR", "DEX"):
            apk_only_fields = [
                "app_name",
                "package_name",
                "play_store",
                "sdk_version",
                "main_activity",
                "features",
                "activities",
                "services",
                "receivers",
                "providers",
                "libraries",
                "signatures",
                "permissions"
            ]
            for field in apk_only_fields:
                clean_report.pop(field, None)

            if clean_report.get("source_findings"):
                clean_report.pop("code_patterns", None)
            clean_report.pop("native_libraries", None)
            clean_report.pop("native_library_triage", None)
            clean_report.pop("yara_detailed_matches", None)

        # For APK analysis we already store the findings list; `code_patterns` is a large
        # duplicate mapping (file -> patterns/categories). Keep it only in detailed mode.
        if (not detailed) and clean_report.get("source_findings"):
            clean_report.pop("code_patterns", None)

        for finding in clean_report.get("source_findings", []):
            if finding.get("third_party", False) is False:
                finding.pop("third_party", None)

        return self.prune_empty_values(clean_report)

    def recursive_dir_scan(self, target_directory):
        fnames = []
        for root, d_names, f_names in os.walk(target_directory):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames

    def yara_rule_scanner(self, filename, report_object, quiet_nomatch=False, header_label=""):
        # Use shared scanner from Modules/analysis/multiple/multi.py
        return shared_yara_rule_scanner(
            self.rule_path,
            filename,
            report_object,
            quiet_nomatch=quiet_nomatch,
            header_label=header_label,
            detailed_key="yara_detailed_matches",
        )

    def MultiYaraScanner(self):
        # Native library scanning should not depend on JADX success; we can always
        # extract and scan libs from the APK zip.
        lib_files_indicator = 0
        scanned = 0
        matched = 0
        self.reportz["decompilation"]["output_dir"] = "TargetAPK"
        self.reportz["decompilation"]["warning"] = ""
        self.reportz["decompilation"]["warning_detail"] = ""
        # Try to decompile (optional). Even if this fails, continue with zip-based extraction.
        if self.decompiler_path and os.path.exists(self.decompiler_path):
            if os.path.exists("TargetAPK"):
                self.reportz["decompilation"]["success"] = True
            else:
                print(f"{infoS} Decompiling target APK file...")
                self.reportz["decompilation"]["attempted"] = True
                if self.run_decompiler("TargetAPK"):
                    if self.last_decompile_warning:
                        self.reportz["decompilation"]["warning"] = self.last_decompile_warning
                        self.reportz["decompilation"]["warning_detail"] = self.last_decompile_warning_detail
                    self.reportz["decompilation"]["success"] = True
                else:
                    # Record decompiler error but keep going with zip extraction.
                    self.reportz["decompilation"]["error"] = self.last_decompile_error
                    self.reportz["decompilation"]["error_detail"] = self.last_decompile_error_detail
        else:
            # Not a fatal error for native library scanning anymore.
            self.reportz["decompilation"]["error"] = "decompiler_not_found"

        # Collect libraries from JADX output (if any) and directly from the APK zip.
        libs = []
        jadx_libs = self._list_so_files_in_dir(f"TargetAPK{path_seperator}resources{path_seperator}")
        for p in jadx_libs:
            libs.append({"path": p, "source": "jadx_output", "zip_path": "", "size": os.path.getsize(p) if os.path.exists(p) else 0})

        # Keep native-lib extraction separate from `TargetAPK/` so we don't
        # accidentally make other stages think decompilation output exists.
        extracted_dir = "NativeLibs_extracted"
        # Keep the directory deterministic, but avoid stale results.
        try:
            if os.path.isdir(extracted_dir):
                shutil.rmtree(extracted_dir)
        except Exception:
            pass
        zip_libs = self.extract_native_libs_from_apk(extracted_dir)
        for item in zip_libs:
            libs.append({"path": item["path"], "source": "apk_zip", "zip_path": item.get("zip_path", ""), "size": item.get("size", 0)})

        # Deduplicate by sha256 so we don't rescan the same bytes coming from two sources.
        uniq = {}
        for item in libs:
            p = item["path"]
            if not p or not os.path.exists(p):
                continue
            try:
                sha = self._sha256_file(p)
            except Exception:
                sha = ""
            key = sha if sha else os.path.abspath(p)
            item["sha256"] = sha
            item["elf"] = self._is_elf(p)
            elf_hdr = self._parse_elf_header(p) if item["elf"] else None
            item["elf_header"] = elf_hdr
            abi = self._infer_abi_from_path(item.get("zip_path") or p)
            if abi == "unknown":
                abi = self._infer_abi_from_elf(elf_hdr)
            item["abi"] = abi

            if key in uniq:
                # Prefer the APK-zip entry when available (better naming + ABI inference).
                if uniq[key].get("source") != "apk_zip" and item.get("source") == "apk_zip":
                    uniq[key] = item
                continue
            uniq[key] = item

        libs = list(uniq.values())
        libs.sort(key=lambda x: (x.get("abi", "unknown"), x.get("zip_path", ""), x.get("path", "")))

        if not libs:
            print("\n[bold white on red]There is no native library (.so) found for analysis!\n")
            return

        # Store inventory in report (useful even if no YARA match happens).
        self.reportz["native_libraries"] = []
        self.reportz["native_library_triage"] = []
        for item in libs:
            self.reportz["native_libraries"].append({
                "path": item.get("zip_path") or item.get("path"),
                "source": item.get("source"),
                "abi": item.get("abi"),
                "sha256": item.get("sha256"),
                "size": item.get("size"),
                "elf": item.get("elf")
            })

        # Print a compact inventory summary.
        inv = {}
        for item in libs:
            k = item.get("abi", "unknown")
            inv[k] = inv.get(k, 0) + 1
        inv_table = Table()
        inv_table.add_column("ABI", style="bold cyan", justify="left")
        inv_table.add_column("Count", style="bold green", justify="center")
        for abi, cnt in sorted(inv.items(), key=lambda kv: (-kv[1], kv[0])):
            inv_table.add_row(str(abi), str(cnt))
        print(inv_table)

        # Scan libraries (quiet for no-match to avoid spam).
        for item in libs:
            lib_files_indicator += 1
            scanned += 1
            if item.get("zip_path"):
                label = f"Native library ({item.get('abi', 'unknown')}): [bold yellow]{item.get('zip_path')}[white]"
            else:
                label = f"Native library ({item.get('abi', 'unknown')}): [bold yellow]{item.get('path')}[white]"

            # Always print the file label so triage output isn't "floating".
            print(f"[bold magenta]>>>>[white] {label}[white]")

            # Lightweight native triage (prints only when it finds signals/IOCs).
            tri = self.native_lib_triage(item["path"], zip_path=item.get("zip_path", ""))
            self.reportz["native_library_triage"].append(tri)
            if tri.get("indicator_hits") or tri.get("urls") or tri.get("ip_addresses"):
                tri_table = Table()
                tri_table.add_column("Key", style="bold cyan", justify="left")
                tri_table.add_column("Value", style="bold green", justify="left")
                eh = tri.get("elf_header") or {}
                arch = eh.get("machine_name", "unknown")
                cls = eh.get("class", "unknown")
                ent = tri.get("entropy")
                tri_table.add_row("ELF", "yes" if tri.get("elf") else "no")
                tri_table.add_row("Arch", f"{arch} (ELF{cls})")
                if ent is not None:
                    tri_table.add_row("Entropy", f"{ent:.2f}")
                if tri.get("indicator_matches"):
                    lines = []
                    for cat, pats in sorted(tri["indicator_matches"].items(), key=lambda kv: kv[0]):
                        show = pats[:8]
                        extra = len(pats) - len(show)
                        s = ", ".join(show)
                        if extra > 0:
                            s = f"{s} (+{extra})"
                        lines.append(f"{cat}: {s}")
                    tri_table.add_row("Patterns", "\n".join(lines))
                if tri.get("urls"):
                    samples = tri["urls"][:3]
                    s = "\n".join(samples)
                    if len(tri["urls"]) > len(samples):
                        s = f"{s}\n(+{len(tri['urls'])-len(samples)})"
                    tri_table.add_row("URLs", s)
                if tri.get("ip_addresses"):
                    samples = tri["ip_addresses"][:3]
                    s = "\n".join(samples)
                    if len(tri["ip_addresses"]) > len(samples):
                        s = f"{s}\n(+{len(tri['ip_addresses'])-len(samples)})"
                    tri_table.add_row("IPs", s)
                print(tri_table)

            # YARA match results follow the label above; avoid duplicate headers.
            hit = self.yara_rule_scanner(item["path"], report_object=self.reportz, quiet_nomatch=True, header_label="")
            if hit:
                matched += 1

        no_match = scanned - matched
        print(f"\n{infoS} Native library scan summary: [bold green]{scanned}[white] scanned, [bold red]{matched}[white] with YARA hits, [bold yellow]{no_match}[white] without hits.\n")

    def print_file_report(self, file_report_obj):
        def _entries_to_findings(ent_list):
            out = []
            for item in ent_list:
                out.append({
                    "file_name": item["file_name"],
                    "categories": item["categories"],
                    "patterns": item["patterns"],
                    "third_party": item["is_third_party"]
                })
            return out

        entries = self.prepare_report_entries(file_report_obj)
        if entries == []:
            print(f"{infoS} There is no suspicious source-code pattern detected.")
            self.last_source_report = {
                "matched_files": 0,
                "shown_files": 0,
                "hidden_low_signal_third_party_files": 0,
                "category_counts": {},
                "findings": []
            }
            self.reportz["source_summary"] = {
                "matched_files": 0,
                "shown_files": 0,
                "hidden_low_signal_third_party_files": 0,
                "category_counts": {}
            }
            self.reportz["source_findings_total"] = 0
            self.reportz["source_findings_truncated"] = False
            self.reportz["source_findings"] = []
            return

        display_entries, hidden_count = self.filter_report_entries(entries)
        category_count = {}
        for item in entries:
            for cat in item["categories"]:
                category_count[cat] = category_count.get(cat, 0) + 1
        # Report size control: store full findings only in detailed mode.
        findings_full = _entries_to_findings(entries)
        if self.detailed_report:
            findings = findings_full
        else:
            findings = _entries_to_findings(display_entries[:self.max_detailed_entries])

        self.last_source_report = {
            "matched_files": len(entries),
            "shown_files": min(len(display_entries), self.max_detailed_entries),
            "hidden_low_signal_third_party_files": hidden_count,
            "category_counts": category_count,
            "findings": findings
        }
        self.reportz["source_summary"] = {
            "matched_files": len(entries),
            "shown_files": min(len(display_entries), self.max_detailed_entries),
            "hidden_low_signal_third_party_files": hidden_count,
            "category_counts": category_count
        }
        self.reportz["source_findings_total"] = len(findings_full)
        self.reportz["source_findings_truncated"] = (len(findings) != len(findings_full))
        self.reportz["source_findings"] = findings
        self.print_pattern_summary(entries=entries, display_entries=display_entries, hidden_count=hidden_count)
        self.print_detailed_report(entries=display_entries)

    def normalize_source_path(self, source_path):
        return source_path.replace("\\", "/").strip("/")

    def is_third_party_source(self, source_path):
        normalized = self.normalize_source_path(source_path).lower()
        third_party_prefixes = (
            "android/",
            "androidx/",
            "kotlin/",
            "kotlinx/",
            "com/google/",
            "org/apache/",
            "org/json/",
            "org/slf4j/",
            "org/intellij/",
            "com/squareup/",
            "okhttp3/",
            "retrofit2/",
            "javax/",
            "net/fabricmc/",
        )
        return normalized.startswith(third_party_prefixes)

    def prepare_report_entries(self, file_report_obj):
        entries = []
        for fname in file_report_obj:
            patterns = list(dict.fromkeys(file_report_obj[fname]["patterns"]))
            categories = sorted(list(dict.fromkeys(file_report_obj[fname]["categories"])))
            if patterns:
                entries.append({
                    "file_name": fname,
                    "patterns": patterns,
                    "categories": categories,
                    "is_third_party": self.is_third_party_source(fname)
                })

        entries.sort(
            key=lambda item: (
                item["is_third_party"],
                -len(item["categories"]),
                -len(item["patterns"]),
                item["file_name"].lower()
            )
        )
        return entries

    def filter_report_entries(self, entries):
        hidden_count = 0
        filtered = []
        for item in entries:
            if item["is_third_party"]:
                high_signal_present = any(cat not in self.low_signal_categories for cat in item["categories"])
                if not high_signal_present:
                    hidden_count += 1
                    continue
            filtered.append(item)

        if filtered == []:
            return entries, 0
        return filtered, hidden_count

    def print_pattern_summary(self, entries, display_entries, hidden_count):
        summary_table = Table()
        summary_table.add_column("[bold cyan]Metric", justify="left")
        summary_table.add_column("[bold green]Value", justify="center")
        summary_table.add_row("Matched source files", str(len(entries)))
        summary_table.add_row("Files shown in detail", str(min(len(display_entries), self.max_detailed_entries)))
        if hidden_count > 0:
            summary_table.add_row("Hidden low-signal third-party files", str(hidden_count))
        print(summary_table)

        category_count = {}
        for item in entries:
            for cat in item["categories"]:
                category_count[cat] = category_count.get(cat, 0) + 1

        category_table = Table()
        category_table.add_column("[bold cyan]Category", justify="left")
        category_table.add_column("[bold green]Matched Files", justify="center")
        for cat, count in sorted(category_count.items(), key=lambda kv: (-kv[1], kv[0].lower())):
            category_table.add_row(cat, str(count))
        print(category_table)
        print("")

    def print_detailed_report(self, entries):
        shown_entries = entries[:self.max_detailed_entries]
        for item in shown_entries:
            print(f"[bold magenta]>>>>[white] File Name: [bold yellow]{item['file_name']}")
            print(f"[bold magenta]>>>>[white] Categories: [bold red]{item['categories']}")
            rep_table = Table()
            rep_table.add_column("[bold green]Patterns", justify="center")
            for pattern in item["patterns"]:
                rep_table.add_row(str(pattern))
            print(rep_table)
            print("")

        if len(entries) > self.max_detailed_entries:
            print(f"{infoS} Detail limit reached. Showing first [bold green]{self.max_detailed_entries}[white] files.")

    # Source code analysis
    def ScanSource(self):
        # Check for decompiled source
        if os.path.exists(f"TargetAPK{path_seperator}"):
            # Prepare source files
            path = f"TargetAPK{path_seperator}sources{path_seperator}"
            fnames = self.recursive_dir_scan(path)
            if fnames != []:
                print(f"\n{infoS} Preparing source files...")
                target_source_files = []
                for sources in track(range(len(fnames)), description="Processing files..."):
                    sanitized = fnames[sources].replace(f"TargetAPK{path_seperator}sources{path_seperator}", "")
                    # Skip high-noise paths early (previously still scanned but would just KeyError/skip).
                    if ("android" in sanitized) or ("kotlin" in sanitized):
                        continue
                    target_source_files.append(sanitized)

                # Analyze source files
                if target_source_files:
                    print(f"\n{infoS} Analyzing source codes. Please wait...")
                    t0 = time.perf_counter()
                    file_report = {}
                    for scode in track(range(len(target_source_files)), description="Analyzing..."):
                        src_rel = target_source_files[scode]
                        src_path = f"TargetAPK{path_seperator}sources{path_seperator}{src_rel}"
                        try:
                            with open(src_path, "r", errors="ignore") as f:
                                scode_buffer = f.read()
                        except Exception:
                            continue

                        record = {"patterns": set(), "categories": set()}
                        self._scan_buffer_for_patterns(scode_buffer, record)
                        if record["patterns"]:
                            file_report[src_rel] = {
                                "patterns": sorted(record["patterns"]),
                                "categories": sorted(record["categories"]),
                            }

                    if self.detailed_report:
                        self.reportz["code_patterns"].update(file_report)
                    self.print_file_report(file_report_obj=file_report)
                    _ = time.perf_counter() - t0
                else:
                    print(f"\n{errorS} Looks like there is nothing to scan or maybe there is an [bold green]Anti-Analysis[white] technique implemented!")
                    print(f"{infoS} You need to select \"[bold green]yes[white]\" option in [bold yellow]Analyze All Packages[white]")
        else:
            print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
            if self.last_decompile_error != "":
                print(f">>>[bold yellow] Hint: [white]Decompiler failed earlier. Reason: [bold red]{self.last_decompile_error}")
            else:
                print(f">>>[bold yellow] Hint: [white]Don\'t forget to specify decompiler path in [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

    # Following function will perform JAR file analysis
    def PerformJAR(self):
        file_report = {}
        self.reportz["analysis_type"] = "JAR"
        self.reportz["target_file"] = self.target_file
        self.reportz["decompilation"] = {
            "attempted": False,
            "success": False,
            "output_dir": "",
            "error": "",
            "error_detail": "",
            "warning": "",
            "warning_detail": ""
        }
        self.reportz["manifest"] = {
            "present": False,
            "entries": {}
        }
        self.reportz["source_summary"] = {
            "matched_files": 0,
            "shown_files": 0,
            "hidden_low_signal_third_party_files": 0,
            "category_counts": {}
        }
        self.reportz["source_findings"] = []

        # First we need to check if there is a META-INF file
        fbuf = open(self.target_file, "rb").read()
        chek = re.findall("META-INF", str(fbuf))
        if chek == []:
            return

        print(f"{infoS} File Type: [bold green]JAR")
        chek = re.findall(".class", str(fbuf))
        if chek == []:
            print(f"{errorS} There is no class file in target archive.")
            return

        # Check if the decompiler exist on system
        if not self.decompiler_path or not os.path.exists(self.decompiler_path):
            print("[blink]Decompiler([bold green]JADX[white])[/blink] [white]not found. Skipping...")
            if self.decompiler_path:
                print(f"{infoS} Configured decompiler path: [bold yellow]{self.decompiler_path}")
            return

        # Executing decompiler...
        print(f"{infoS} Decompiling target file...")
        self.reportz["decompilation"]["attempted"] = True
        self.reportz["decompilation"]["output_dir"] = "TargetSource"
        if not self.run_decompiler("TargetSource"):
            self.reportz["decompilation"]["error"] = self.last_decompile_error
            self.reportz["decompilation"]["error_detail"] = self.last_decompile_error_detail
            return
        if self.last_decompile_warning:
            self.reportz["decompilation"]["warning"] = self.last_decompile_warning
            self.reportz["decompilation"]["warning_detail"] = self.last_decompile_warning_detail
        self.reportz["decompilation"]["success"] = True

        # If we successfully decompiled the target file
        if not os.path.exists("TargetSource"):
            print("[bold white on red]Couldn\'t locate source codes. Did target file decompiled correctly?")
            print(f">>>[bold yellow] Hint: [white]Decompiler execution failed or target is malformed.")
            self.reportz["decompilation"]["error"] = "target_source_not_found"
            return

        # Reading MANIFEST file
        manifest_path = f"TargetSource{path_seperator}resources{path_seperator}META-INF{path_seperator}MANIFEST.MF"
        if os.path.exists(manifest_path):
            print(f"\n{infoS} MANIFEST file found. Fetching data...")
            data = open(manifest_path).read()
            print(data)
            manifest_entries = {}
            for line in data.splitlines():
                if ": " in line:
                    k, v = line.split(": ", 1)
                    manifest_entries[k.strip()] = v.strip()
            self.reportz["manifest"] = {
                "present": True,
                "entries": manifest_entries
            }
        else:
            print(f"{errorS} MANIFEST.MF could not be found in decompiled output.")

        # Prepare source files
        fnames = self.recursive_dir_scan(target_directory=f"TargetSource{path_seperator}sources{path_seperator}")
        print(f"{infoS} Preparing source files...")
        target_source_files = []
        for sources in track(range(len(fnames)), description="Processing files..."):
            sanitized = fnames[sources].replace(f'TargetSource{path_seperator}sources{path_seperator}', '')
            if ("android" not in sanitized) and ("kotlin" not in sanitized):
                target_source_files.append(sanitized)

        # Analyze source files
        print(f"\n{infoS} Analyzing source codes. Please wait...")
        t0 = time.perf_counter()
        for scode in track(range(len(target_source_files)), description="Analyzing..."):
            src_rel = target_source_files[scode]
            src_path = f"TargetSource{path_seperator}sources{path_seperator}{src_rel}"
            try:
                with open(src_path, "r", errors="ignore") as f:
                    scode_buffer = f.read()
            except Exception:
                continue

            record = {"patterns": set(), "categories": set()}
            self._scan_buffer_for_patterns(scode_buffer, record)
            if record["patterns"]:
                file_report[src_rel] = {
                    "patterns": sorted(record["patterns"]),
                    "categories": sorted(record["categories"]),
                }

        self.reportz["code_patterns"].update(file_report)
        _ = time.perf_counter() - t0

        # Printing report
        if file_report:
            self.print_file_report(file_report_obj=file_report)

    def analyze_dex_file(self):
        self.reportz["analysis_type"] = "DEX"
        self.reportz["target_file"] = self.target_file
        self.reportz["decompilation"] = {
            "attempted": False,
            "success": False,
            "output_dir": "TargetAPK",
            "error": "",
            "error_detail": "",
            "warning": "",
            "warning_detail": ""
        }
        if os.path.exists("TargetAPK"):
            self.reportz["decompilation"]["success"] = True
            self.ScanSource()
        else:
            if not self.decompiler_path or not os.path.exists(self.decompiler_path):
                print("[blink]Decompiler([bold green]JADX[white])[/blink] [white]not found. Skipping...")
                if self.decompiler_path:
                    print(f"{infoS} Configured decompiler path: [bold yellow]{self.decompiler_path}")
                self.reportz["decompilation"]["error"] = "decompiler_not_found"
                return
            print(f"{infoS} Decompiling target file...")
            self.reportz["decompilation"]["attempted"] = True
            if not self.run_decompiler("TargetAPK"):
                self.reportz["decompilation"]["error"] = self.last_decompile_error
                self.reportz["decompilation"]["error_detail"] = self.last_decompile_error_detail
                return
            if self.last_decompile_warning:
                self.reportz["decompilation"]["warning"] = self.last_decompile_warning
                self.reportz["decompilation"]["warning_detail"] = self.last_decompile_warning_detail
            self.reportz["decompilation"]["success"] = True
            self.ScanSource()

    def get_possible_package_names(self):
        print(f"\n{infoS} Looking for package name...")
        # Handle aapt2 errors and get package_name anyway
        package_name_proc = subprocess.run(f"aapt2 dump packagename \"{self.target_file}\"", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if package_name_proc.returncode == 0:
            package_name = package_name_proc.stdout.decode().strip('\n')
            return package_name
        else:
            try:
                # Get package_name from error message
                package_name = re.findall(r"com.[a-z0-9]*.[a-z0-9]*", package_name_proc.stderr.decode())[0]
                return package_name
            except:
                return None

    def pattern_scanner_ex(self, regex, target_files, target_type, value_array):
        for url in track(range(len(target_files)), description=f"Processing {target_type}..."):
            try:
                source_buffer = open(target_files[url], "r").read()
                url_regex = re.findall(regex, source_buffer)
                if url_regex != []:
                    for val in url_regex:
                        if val not in value_array:
                            if "<" in val:
                                value_array.append(val.split("<")[0])
                            else:
                                value_array.append(val)
            except:
                continue

    def pattern_scanner(self, target_pattern):
        extracted_values = []
        path = f"TargetAPK{path_seperator}sources{path_seperator}"
        fnames = self.recursive_dir_scan(path)
        if fnames != []:
            self.pattern_scanner_ex(regex=target_pattern,
                            target_files=fnames,
                            target_type="sources",
                            value_array=extracted_values
            )
        path = f"TargetAPK{path_seperator}resources{path_seperator}"
        fnames = self.recursive_dir_scan(path)
        if fnames != []:
            self.pattern_scanner_ex(regex=target_pattern,
                            target_files=fnames,
                            target_type="resources",
                            value_array=extracted_values
            )

        if extracted_values != []:
            return extracted_values
        else:
            return []

    # Scan files for url and ip patterns
    def Get_IP_URL(self):
        print(f"\n{infoS} Looking for possible IP address patterns. Please wait...")
        ip_vals = self.pattern_scanner(target_pattern=r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
        # Extract ip addresses from file
        if ip_vals != []:
            ipTables = Table()
            ipTables.add_column("[bold green]IP Address", justify="center")
            ipTables.add_column("[bold green]Country", justify="center")
            ipTables.add_column("[bold green]City", justify="center")
            ipTables.add_column("[bold green]Region", justify="center")
            ipTables.add_column("[bold green]ISP", justify="center")
            ipTables.add_column("[bold green]Proxy", justify="center")
            ipTables.add_column("[bold green]Hosting", justify="center")
            for ips in ip_vals:
                if ips[0] != '0':
                    data = requests.get(f"http://ip-api.com/json/{ips}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting")
                    if data.json()['status'] != 'fail':
                        ipTables.add_row(
                            str(ips), str(data.json()['country']), 
                            str(data.json()['city']), 
                            str(data.json()['regionName']), 
                            str(data.json()['isp']),
                            str(data.json()['proxy']),
                            str(data.json()['hosting'])
                        )
            print(ipTables)
        else:
            print(f"{errorS} There is no possible IP address pattern found!")
    
        # Extract url values
        print(f"\n{infoS} Looking for URL values. Please wait...")
        url_vals = self.pattern_scanner(target_pattern=r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
        if url_vals != []:
            sanitizer = []
            filtered_urls = []
            urltable = Table()
            urltable.add_column("[bold green]Extracted URL Values", justify="center")
            for uv in url_vals:
                uvs = str(uv)
                uvs_l = uvs.lower()
                if uvs in sanitizer:
                    continue
                sanitizer.append(uvs)

                # Hide "legit" domains via global whitelist matcher.
                # chk_wlist() returns False if a whitelist entry matches.
                try:
                    if not chk_wlist(uvs_l):
                        continue
                    host = urlparse(uvs_l).hostname or ""
                    if host and (not chk_wlist(host)):
                        continue
                except Exception:
                    pass

                # Hide format-string URL templates (very common in SDKs, low-signal).
                if ("%s" in uvs) or ("%1$" in uvs) or ("%2$" in uvs):
                    continue

                filtered_urls.append(uvs)

            if filtered_urls:
                for u in filtered_urls:
                    urltable.add_row(u)
                print(urltable)
            else:
                print(f"{errorS} There is no URL value found!")
        else:
            print(f"{errorS} There is no URL pattern found!")

    # Permission analyzer
    def Analyzer(self, parsed):
        global danger
        global normal
        statistics = Table()
        statistics.add_column("[bold green]Permissions", justify="center")
        statistics.add_column("[bold green]State", justify="center")

        # Getting blacklisted permissions
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}perms.json", "r") as f:
            permissions = json.load(f)

        apkPerms = parsed.get_permissions()
        permArr = []

        # Getting target APK file's permissions
        for p in range(len(permissions)):
            permArr.append(permissions[p]["permission"])

        # Parsing permissions
        for pp in apkPerms:
            if pp.split(".")[-1] in permArr:
                statistics.add_row(str(pp), "[bold red]Risky")
                self.reportz["permissions"].append({str(pp): "Risky"})
                danger += 1
            else:
                statistics.add_row(str(pp), "[bold yellow]Info")
                self.reportz["permissions"].append({str(pp): "Info"})
                normal += 1

        # If there is no permission:
        if danger == 0 and normal == 0:
            print("\n[bold white on red]There is no permissions found!\n")
        else:
            print(statistics)

    # Analyzing more deeply
    def DeepScan(self, parsed):
        # Getting features
        featStat = Table()
        featStat.add_column("[bold green]Features", justify="center")
        features = parsed.get_features()
        if features != []:
            for ff in features:
                featStat.add_row(str(ff))
                self.reportz["features"].append(ff)
            print(featStat)
        else:
            pass

        # Activities
        activeStat = Table()
        activeStat.add_column("[bold green]Activities", justify="center")
        actos = parsed.get_activities()
        if actos != []:
            for aa in actos:
                activeStat.add_row(str(aa))
                self.reportz["activities"].append(aa)
            print(activeStat)
        else:
            pass

        # Services
        servStat = Table()
        servStat.add_column("[bold green]Services", justify="center")
        servv = parsed.get_services()
        if servv != []:
            for ss in servv:
                servStat.add_row(str(ss))
                self.reportz["services"].append(ss)
            print(servStat)
        else:
            pass

        # Receivers
        recvStat = Table()
        recvStat.add_column("[bold green]Receivers", justify="center")
        receive = parsed.get_receivers()
        if receive != []:
            for rr in receive:
                recvStat.add_row(str(rr))
                self.reportz["receivers"].append(rr)
            print(recvStat)
        else:
            pass

        # Providers
        provStat = Table()
        provStat.add_column("[bold green]Providers", justify="center")
        provids = parsed.get_providers()
        if provids != []:
            for pp in provids:
                provStat.add_row(str(pp))
                self.reportz["providers"].append(pp)
            print(provStat)
        else:
            pass

    def GeneralInformation(self, targetAPK, axml_obj):
        print(f"\n{infoS} General Informations about [bold green]{targetAPK}[white]")
        self.reportz["analysis_type"] = "APK"
        self.reportz["target_file"] = targetAPK

        # Parsing target apk file
        if axml_obj:
            # Lets print!!
            print(f"[bold red]>>>>[white] App Name: [bold green]{axml_obj.get_app_name()}")
            print(f"[bold red]>>>>[white] Package Name: [bold green]{axml_obj.get_package()}")
            self.reportz["app_name"] = axml_obj.get_app_name()
            self.reportz["package_name"] = axml_obj.get_package()
        else:
            print(f"[bold red]>>>>[white] Possible Package Name: [bold green]{package_names}")
            self.reportz["package_name"] = package_names
            self.reportz["app_name"] = None

        # Gathering play store information
        if axml_obj:
            print(f"\n{infoS} Sending query to Google Play Store about target application.")
            try:
                playinf = requests.get(f"https://play.google.com/store/apps/details?id={axml_obj.get_package()}")
                if playinf.ok:
                    print("[bold red]>>>>[white] Google Play Store: [bold green]Found\n")
                    self.reportz["play_store"] = True
                else:
                    print("[bold red]>>>>[white] Google Play Store: [bold red]Not Found\n")
                    self.reportz["play_store"] = None
            except:
                print("\n[bold white on red]An error occured while querying to Google Play Store!\n")
                self.reportz["play_store"] = None
        else:
            print(f"\n{infoS} Sending query to Google Play Store about target application.")
            try:
                playinf = requests.get(f"https://play.google.com/store/apps/details?id={package_names}")
                if playinf.ok:
                    print("[bold red]>>>>[white] Google Play Store: [bold green]Found\n")
                    self.reportz["play_store"] = True
                else:
                    print("[bold red]>>>>[white] Google Play Store: [bold red]Not Found\n")
                    self.reportz["play_store"] = None
            except:
                print("\n[bold white on red]An error occured while querying to Google Play Store!\n")
                self.reportz["play_store"] = None

        if axml_obj:
            print(f"[bold red]>>>>[white] SDK Version: [bold green]{axml_obj.get_effective_target_sdk_version()}")
            print(f"[bold red]>>>>[white] Main Activity: [bold green]{axml_obj.get_main_activity()}")
            self.reportz["sdk_version"] = axml_obj.get_effective_target_sdk_version()
            self.reportz["main_activity"] = axml_obj.get_main_activity()
            try:
                if axml_obj.get_libraries() != []:
                    print("[bold red]>>>>[white] Libraries:")
                    for libs in axml_obj.get_libraries():
                        print(f"[bold magenta]>>[white] {libs}")
                        self.reportz["libraries"].append(libs)
                    print(" ")

                if axml_obj.get_signature_names() != []:
                    print("[bold red]>>>>[white] Signatures:")
                    for sigs in axml_obj.get_signature_names():
                        print(f"[bold magenta]>>[white] {sigs}")
                        self.reportz["signatures"].append(sigs)
                    print(" ")
            except:
                pass
        else:
            self.reportz["sdk_version"] = None
            self.reportz["main_activity"] = None
            self.reportz["libraries"] = None
            self.reportz["signatures"] = None

# Execution
if __name__ == '__main__':
    try:
        # Create object
        apka = APKAnalyzer(target_file=targetAPK)

        # Check for JAR file
        if sys.argv[3] == "JAR":
            apka.PerformJAR()
            if sys.argv[2] == "True":
                apka.report_writer("android", apka.reportz)
            sys.exit(0)

        # Check for DEX file
        if sys.argv[3] == "DEX":
            apka.analyze_dex_file()
            if sys.argv[2] == "True":
                apka.report_writer("android", apka.reportz)
            sys.exit(0)

        # Get axml object
        try:
            axml_obj = pyaxmlparser.APK(targetAPK)
            # In case of package name parsing issues
            if axml_obj.get_package() == '':
                print(f"\n{errorS} It looks like the target [bold green]AndroidManifest.xml[white] is corrupted!!")
                axml_obj = None
                package_names = apka.get_possible_package_names()
        except:
            print(f"\n{errorS} It looks like the target [bold green]AndroidManifest.xml[white] is corrupted!!")
            axml_obj = None
            package_names = apka.get_possible_package_names()

        # General informations
        apka.GeneralInformation(targetAPK, axml_obj)

        # Parsing target apk for androguard
        try:
            parsed = APK(targetAPK)
        except:
            parsed = None

        if parsed:
            # Permissions side
            apka.Analyzer(parsed)

            # Deep scanner
            apka.DeepScan(parsed)

        # Yara matches
        print(f"\n{infoS} Performing YARA rule matching...")
        apka.yara_rule_scanner(targetAPK, report_object=apka.reportz)

        # Decompiling and scanning libraries
        print(f"\n{infoS} Performing library analysis...")
        try:
            apka.MultiYaraScanner()
        except:
            print("\n[bold white on red]An error occured while decompiling the file. Please check configuration file and modify the [blink]Decompiler[/blink] option.")
            print(f"[bold white]>>> Configuration file path: [bold green]Systems{path_seperator}Android{path_seperator}libScanner.conf")

        # Malware family detection
        print(f"\n{infoS} Performing malware family detection. Please wait!!")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}andro_familydetect.py \"{targetAPK}\""
        os.system(command)

        # Source code analysis zone
        print(f"\n{infoS} Performing source code analysis...")
        apka.ScanSource()

        # IP and URL value scan
        apka.Get_IP_URL()

        # Print reports
        if sys.argv[2] == "True":
            apka.report_writer("android", apka.reportz)
    except KeyboardInterrupt:
        print("\n[bold white on red]An error occured. Press [blink]CTRL+C[/blink] to exit.\n")
