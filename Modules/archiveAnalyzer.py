#!/usr/bin/python3

import re
import os
import sys
import zipfile
import subprocess
import configparser
import shutil
import tempfile
from urllib.parse import urlparse, urlunparse

try:
    # Module execution (python -m Modules.archiveAnalyzer)
    from .utils.helpers import err_exit, get_argv, save_report
except ImportError:
    # Raw execution (python Modules/archiveAnalyzer.py)
    from utils.helpers import err_exit, get_argv, save_report

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< not found.")

try:
    import yara
except Exception:
    err_exit("Error: >yara< module not found.")

try:
    import rarfile
except Exception:
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

# Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(".path_handler", "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Ensure `analysis.*` imports resolve when running as a script.
modules_dir = os.path.join(sc0pe_path, "Modules")
if modules_dir not in sys.path:
    sys.path.insert(0, modules_dir)

try:
    from analysis.multiple.multi import yara_rule_scanner
except Exception:
    err_exit("Error: >analysis.multiple.multi< module not found.")

# Target file / behavior flags
targetFile = str(get_argv(1, "")).strip()
if not targetFile:
    err_exit("[bold white on red]Target file not found!\n")
EMIT_REPORT = str(get_argv(2, "False")).strip().lower() == "true"

report = {
    "analysis_type": "archive",
    "target_type": "archive",
    "target_file": targetFile,
    "archive_type": "",
    "archive_member_count": 0,
    "archive_file_count": 0,
    "archive_directory_count": 0,
    "archive_contents": [],
    "scanned_members": [],
    "embedded_urls": [],
    "embedded_urls_by_member": {},
    "matched_rules": [],
    "matched_rules_by_member": [],
    "errors": [],
}

def _load_domain_whitelist():
    wpath = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt"
    out = []
    try:
        with open(wpath, "r", encoding="utf-8", errors="ignore") as wf:
            for ln in wf:
                tok = str(ln).strip().lower()
                if not tok or tok.startswith("#"):
                    continue
                out.append(tok)
    except Exception:
        return []
    return out


def _is_whitelisted_hostname(hostname, whitelist_tokens):
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return False

    for tok in whitelist_tokens:
        t = str(tok or "").strip().lower().strip()
        if not t:
            continue

        # Tokens ending with "." are treated as prefix domains (e.g., amazon.)
        if t.endswith("."):
            base = t.rstrip(".")
            if host == base or host.startswith(base + "."):
                return True
            continue

        # Full domain/suffix match.
        if "." in t and (host == t or host.endswith("." + t)):
            return True

        # Fallback for intentionally partial entries in whitelist.
        if len(t) >= 5 and t in host:
            return True

    return False


def _normalize_candidate_url(raw_url):
    s = str(raw_url or "").replace("\x00", "").strip()
    if not s:
        return ""
    s = s.strip(" \t\r\n\"'`[](){}<>")
    s = s.rstrip("\\")
    while s and s[-1] in ".,;:)]}'\"":
        s = s[:-1]
    if not s:
        return ""

    try:
        parsed = urlparse(s)
    except Exception:
        return ""
    if parsed.scheme not in ("http", "https"):
        return ""
    if not parsed.netloc:
        return ""

    host = str(parsed.hostname or "").strip().lower().strip(".")
    if not host:
        return ""

    # Common cert/blob residue seen in embedded binary strings (e.g. "...com0A").
    host = re.sub(r"0[0-9a-z]{1,3}$", "", host)
    host = host.strip(".")
    if not host or re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,24}", host) is None:
        return ""

    netloc = host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    return urlunparse((parsed.scheme, netloc, path, "", query, fragment))


def _calc_hashes_silent(filename):
    hashes = {"hash_md5": "", "hash_sha1": "", "hash_sha256": ""}
    try:
        import hashlib

        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
        hashes["hash_md5"] = hash_md5.hexdigest()
        hashes["hash_sha1"] = hash_sha1.hexdigest()
        hashes["hash_sha256"] = hash_sha256.hexdigest()
    except Exception:
        pass
    return hashes


class ArchiveAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
        self.report = report
        self._embedded_urls = set()
        self._domain_whitelist = _load_domain_whitelist()

    def check_archive_type(self):
        arch_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        detected = arch_type.stdout.decode(errors="ignore")
        if "Zip archive data" in detected:
            return "type_zip"
        if "RAR archive data" in detected:
            return "type_rar"
        if "ACE archive data" in detected:
            return "type_ace"
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

    def _member_display_name(self, member_name):
        normalized = str(member_name).replace("\\", "/")
        parts = [x for x in normalized.split("/") if x]
        return parts[-1] if parts else normalized

    def _member_temp_path(self, member_name, index):
        display_name = self._member_display_name(member_name) or "entry.bin"
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", display_name)
        sanitized = sanitized[:80] if len(sanitized) > 80 else sanitized
        if not sanitized:
            sanitized = "entry.bin"
        return f".qu1cksc0pe_archive_{os.getpid()}_{index}_{sanitized}"

    def _rule_config_by_magic(self, magic_output):
        if "Windows" in magic_output:
            return f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf"
        if "ELF" in magic_output:
            return f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux.conf"
        if (
            "Word" in magic_output
            or "Excel" in magic_output
            or "PDF" in magic_output
            or "Rich Text" in magic_output
        ):
            return f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf"
        return ""

    def perform_basic_scans(self, arch_object, arch_type):
        self.arch_object = arch_object
        self.arch_type = arch_type

        enumerate_arr = self.arch_object.infolist()
        namelist_arr = []
        dir_count = 0
        file_count = 0

        # Enumerating archive file contents
        print(f"\n{infoS} Analyzing archive file contents...")
        contentTable = Table(title="* Archive Contents *", title_style="bold italic cyan", title_justify="center")
        contentTable.add_column("[bold green]File Name", justify="center")
        contentTable.add_column("[bold green]File Size (bytes)", justify="center")

        for zf in enumerate_arr:
            zf_name = str(getattr(zf, "filename", ""))
            zf_size = int(getattr(zf, "file_size", 0) or 0)
            is_dir = bool(zf.is_dir())

            contentTable.add_row(zf_name, str(zf_size))
            self.report["archive_contents"].append({
                "name": zf_name,
                "size": zf_size,
                "is_dir": is_dir,
            })

            if is_dir:
                dir_count += 1
            else:
                file_count += 1
                namelist_arr.append(zf_name)

        print(contentTable)

        self.report["archive_type"] = str(arch_type)
        self.report["archive_member_count"] = len(self.report["archive_contents"])
        self.report["archive_file_count"] = file_count
        self.report["archive_directory_count"] = dir_count

        # Extract data and analyze it
        for index, archive_member in enumerate(namelist_arr):
            temp_path = self._member_temp_path(archive_member, index)
            display_name = self._member_display_name(archive_member)
            scan_item = {
                "member": archive_member,
                "display_name": display_name,
                "detected_type": "",
                "url_count": 0,
                "matched_rule_names": [],
            }

            try:
                # Gather file buffer/data
                file_data = self.arch_object.read(archive_member)

                # Write file content into temporary file for further analysis
                with open(temp_path, "wb") as fc:
                    fc.write(file_data)

                # Extract embedded URLs
                print(f"\n{infoS} Looking for embedded URL\'s in: [bold green]{display_name}[white]")
                urls = self.extract_urls(temp_path, display_name=display_name)
                scan_item["url_count"] = len(urls)
                if urls:
                    self.report["embedded_urls_by_member"][archive_member] = urls
                    for uu in urls:
                        if uu not in self._embedded_urls:
                            self._embedded_urls.add(uu)
                            self.report["embedded_urls"].append(uu)

                # Perform YARA scan against extracted file
                detect_os = subprocess.run(["file", temp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                detect_text = detect_os.stdout.decode(errors="ignore")
                scan_item["detected_type"] = detect_text.strip()
                config_file = self._rule_config_by_magic(detect_text)
                if config_file:
                    print(f"\n{infoS} Performing YARA scan against: [bold green]{display_name}[white]")
                    matched_rules = self.perform_yara_scan(
                        yara_target=temp_path,
                        config_file=config_file,
                        report_name=display_name,
                    )
                    scan_item["matched_rule_names"] = matched_rules
                    if matched_rules:
                        self.report["matched_rules_by_member"].append(
                            {
                                "member": archive_member,
                                "rules": matched_rules,
                            }
                        )
                self.report["scanned_members"].append(scan_item)
            except Exception as exc:
                self.report["errors"].append(
                    {
                        "member": archive_member,
                        "error": str(exc),
                    }
                )
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass

    def extract_urls(self, url_target, display_name=""):
        # Get all strings from file and search url patterns
        strings_buffer = subprocess.run(["strings", strings_param, url_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        strings_text = strings_buffer.stdout.decode(errors="ignore")
        url_occur = re.findall(r"https?://[^\s\"'<>\\]+", strings_text, re.IGNORECASE)

        target_label = str(display_name or url_target)
        if url_occur:
            extracted = []
            for ux in url_occur:
                cleaned = _normalize_candidate_url(ux)
                if not cleaned:
                    continue
                try:
                    host = urlparse(cleaned).hostname or ""
                except Exception:
                    host = ""
                if _is_whitelisted_hostname(host, self._domain_whitelist):
                    continue
                if cleaned not in extracted:
                    extracted.append(cleaned)

            if extracted:
                url_table = Table()
                url_table.add_column(f"[bold green]Embedded URL\'s in [bold red]{target_label}[white]", justify="center")
                for uu in extracted:
                    url_table.add_row(uu)
                print(url_table)
                return extracted

        print(f"[bold white on red]There is no URL contained in {target_label}")
        return []

    def perform_yara_scan(self, yara_target, config_file, report_name=""):
        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(config_file, encoding="utf-8-sig")
        rule_path = conf["Rule_PATH"]["rulepath"]
        rep = {"matched_rules": []}
        hit = yara_rule_scanner(
            rule_path,
            yara_target,
            rep,
            quiet_nomatch=True,
            quiet_errors=False,
            print_matches=False,
        )
        if not hit:
            print(f"[bold white on red]There is no rules matched for {report_name or yara_target}")
            return []

        # Preserve the original, compact output for archives: list matched rule names only.
        rule_names = []
        for entry in rep.get("matched_rules", []):
            if isinstance(entry, dict):
                for k in entry.keys():
                    if k not in rule_names:
                        rule_names.append(k)

        if EMIT_REPORT and rep.get("matched_rules"):
            self.report["matched_rules"].extend(rep.get("matched_rules", []))

        yaraTable = Table()
        yaraTable.add_column(f"[bold green]Matched YARA Rules for: [bold red]{report_name or yara_target}[white]", justify="center")
        for rn in rule_names:
            yaraTable.add_row(str(rn))
        print(yaraTable)
        return rule_names


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
report.update(_calc_hashes_silent(targetFile))
artype = arch_analyzer.check_archive_type()
if artype == "type_zip":
    report["archive_type"] = "zip"
    print(f"{infoS} Archive Type: [bold green]Zip Archive")
    arch_analyzer.zip_file_analysis()
elif artype == "type_rar":
    report["archive_type"] = "rar"
    print(f"{infoS} Archive Type: [bold green]Rar Archive")
    arch_analyzer.rar_file_analysis()
elif artype == "type_ace":
    report["archive_type"] = "ace"
    print(f"{infoS} Archive Type: [bold green]Ace Archive")
    arch_analyzer.ace_file_analysis()
else:
    err_exit(f"{errorS} Archive type not supported.")

if EMIT_REPORT:
    save_report("archive", report)
