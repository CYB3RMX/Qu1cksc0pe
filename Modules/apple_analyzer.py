#!/usr/bin/python3

import hashlib
import math
import os
import re
import sys
import json

from utils.helpers import err_exit, get_argv, save_report

try:
    from wh1tem0cha import Wh1teM0cha
except Exception:
    err_exit("Error: >wh1tem0cha< module not found.")

try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< module not found.")

try:
    from analysis.multiple.multi import chk_wlist, yara_rule_scanner
except Exception:
    def chk_wlist(s):
        return True
    yara_rule_scanner = None

try:
    from analysis.multiple.go_binary_parser import GolangParser
    _GOLANG_PARSER_AVAILABLE = True
except Exception:
    _GOLANG_PARSER_AVAILABLE = False

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Sc0pe path
try:
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Legends
infoS  = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Mach-O / FAT magic bytes
_MACHO_MAGIC = {
    0xFEEDFACE: "Mach-O 32-bit",
    0xCEFAEDFE: "Mach-O 32-bit (reversed)",
    0xFEEDFACF: "Mach-O 64-bit",
    0xCFFAEDFE: "Mach-O 64-bit (reversed)",
    0xCAFEBABE: "FAT/Universal Binary",
    0xBEBAFECA: "FAT/Universal Binary (reversed)",
}

# Dylibs that warrant attention in security analysis
_SUSPICIOUS_DYLIB_FRAGMENTS = [
    "/inject", "/Substrate", "/MobileSubstrate", "/TweakInject",
    "/pspawn_payload", "/libhooker", "/SSLKillSwitch",
    "/FridaGadget", "/frida-gadget", "/cycript",
    "/libssl", "/libcrypto", "/libssh", "/libresolv",
]

_SYSTEM_DYLIB_PREFIXES = (
    "/System/Library/", "/usr/lib/", "/usr/local/lib/",
)

# Dangerous entitlements
_DANGEROUS_ENTITLEMENTS = {
    "com.apple.security.get-task-allow":
        "Allows debuggers to attach (suspicious in release build)",
    "com.apple.security.cs.allow-dyld-environment-variables":
        "Allows DYLD env variable injection (code injection risk)",
    "com.apple.security.cs.disable-library-validation":
        "Disables library validation (allows unsigned dylib loading)",
    "com.apple.security.cs.allow-unsigned-executable-memory":
        "Allows unsigned executable memory (JIT / shellcode)",
    "com.apple.security.cs.disable-executable-page-protection":
        "Disables executable page protection (critical sandbox weakening)",
    "task_for_pid-allow":
        "Allows task_for_pid on any process (root-level process control)",
    "com.apple.system-task-ports":
        "Access to system task ports (privileged kernel interaction)",
    "com.apple.private.security.no-sandbox":
        "Sandboxing disabled (full filesystem/network access)",
    "com.apple.private.tcc.manager":
        "TCC manager entitlement (privacy controls bypass)",
    "com.apple.security.temporary-exception.mach-lookup.global-name":
        "Exception: global Mach service lookup",
    "com.apple.private.admin.writeconfig":
        "Can write system configuration (admin privilege)",
    "com.apple.rootless.install":
        "Can install to SIP-protected paths",
    "com.apple.private.kernel.override-cpumon":
        "Can override CPU monitoring",
}

# Suspicious string patterns grouped by behaviour category
_SUSPICIOUS_STRING_PATTERNS = {
    "Shell Execution": [
        rb"/bin/sh", rb"/bin/bash", rb"/bin/zsh", rb"/usr/bin/env",
        rb"sh -c ", rb"bash -c ", rb"zsh -c ",
        rb"osascript", rb"NSAppleScript",
        rb"/usr/bin/python", rb"python -c ",
        rb"perl -e ", rb"ruby -e ",
    ],
    "Download/Staging": [
        rb"curl ", rb"curl\x00", rb"/usr/bin/curl",
        rb"wget ", rb"/usr/bin/wget",
        rb"NSURLDownload", rb"URLSessionDownloadTask",
    ],
    "Persistence Paths": [
        rb"/Library/LaunchDaemons/", rb"/Library/LaunchAgents/",
        rb"~/Library/LaunchAgents/", rb"/Library/StartupItems/",
        rb"com.apple.launchd", rb"crontab",
    ],
    "Privilege Escalation": [
        rb"sudo ", rb"/usr/bin/sudo", rb"chmod +s", rb"chown root",
        rb"AuthorizationExecuteWithPrivileges", rb"STPrivilegedTask", rb"authopen",
    ],
    "Suspicious Paths": [
        rb"/tmp/", rb"/var/tmp/", rb"/private/tmp/",
        rb"/etc/passwd", rb"/private/etc/sudoers",
        rb"\.ssh/", rb"id_rsa", rb"authorized_keys", rb"/root/",
    ],
    "Reverse Shell / C2": [
        rb"/dev/tcp/", rb"nc -", rb"netcat", rb"bash -i ",
        rb"exec 5<>/dev/", rb"mkfifo", rb"mknod",
    ],
}

# Regex patterns
_URL_RE   = re.compile(rb"https?://[^\x00-\x1f\s\"'<>]{6,}")
_IP_RE    = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_EMAIL_RE = re.compile(rb"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,6}")
_B64_RE   = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")
_BTC_RE   = re.compile(rb"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE   = re.compile(rb"\b0x[a-fA-F0-9]{40}\b")
_XMR_RE   = re.compile(rb"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Risk scoring weights
_RISK_WEIGHTS = {
    "unsigned":             3,
    "dangerous_entitlement":2,
    "suspicious_dylib":     2,
    "c2_artifact":          5,
    "anti_analysis":        3,
    "privilege_escalation": 3,
    "reverse_shell":        4,
    "yara_match":           4,
    "suspicious_ip":        1,
    "base64_blob":          2,
    "crypto_address":       2,
    "download_staging":     2,
    "persistence":          3,
}


def _to_text(v):
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore")
        except Exception:
            return str(v)
    return str(v)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_suspicious_dylib(lib_name):
    for frag in _SUSPICIOUS_DYLIB_FRAGMENTS:
        if frag.lower() in lib_name.lower():
            return True
    if lib_name and not lib_name.startswith(_SYSTEM_DYLIB_PREFIXES) and lib_name.startswith("/"):
        return True
    return False


class AppleAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        with open(self.target_file, "rb") as f:
            self._target_binary_buff = f.read()
        self.wmocha_object = None
        self.categ_patterns = {}
        self._risk_score    = 0
        self._risk_reasons  = []
        self.report = {
            "filename":               self.target_file,
            "analysis_type":          "OSX",
            "target_os":              "OSX",
            "target_type":            "",
            "file_hashes":            {},
            "binary_info":            {},
            "entrypoint":             None,
            "application_identifier": None,
            "code_signature":         {},
            "entitlements":           {},
            "dyld_info":              {},
            "dysymtab_info":          {},
            "data_in_code":           {},
            "is_go_binary":           False,
            "golang":                 {"detected": False, "findings_by_category": {}},
            "segments":               [],
            "sections":               [],
            "section_anomalies":      [],
            "dynamic_libraries":      [],
            "weak_dynamic_libraries": [],
            "matched_rules":          [],
            "special_artifacts":      {},
            "extracted_urls":         [],
            "extracted_ips":          [],
            "extracted_emails":       [],
            "crypto_addresses":       {},
            "suspicious_strings":     {},
            "base64_blobs":           [],
            "categorized_patterns":   {},
            "risk_score":             0,
            "risk_level":             "",
            "risk_reasons":           [],
            "statistics":             {"category_pattern_counts": {}},
            "errors":                 [],
        }

    # ------------------------------------------------------------------
    # Internal risk helpers
    # ------------------------------------------------------------------

    def _add_risk(self, weight_key, reason, count=1):
        points = _RISK_WEIGHTS.get(weight_key, 1) * count
        self._risk_score += points
        self._risk_reasons.append(reason)

    # ------------------------------------------------------------------
    # Target-type detection
    # ------------------------------------------------------------------

    def _detect_magic(self):
        if len(self._target_binary_buff) < 4:
            return None
        magic = int.from_bytes(self._target_binary_buff[:4], "little")
        return _MACHO_MAGIC.get(magic)

    def _check_ipa_file(self):
        markers = (b"Payload/", b"META-INF/", b".plist")
        return sum(1 for m in markers if m in self._target_binary_buff) > 0

    def _check_macho_binary(self):
        wm = Wh1teM0cha(self.target_file)
        try:
            wm.get_binary_info()
            self.wmocha_object = wm
            return True
        except Exception:
            return False

    def check_target_type(self):
        magic_label = self._detect_magic()
        if magic_label:
            print(f"{infoS} Detected format: [bold green]{magic_label}[white]")
            self.report["binary_info"]["format"] = magic_label

        if self._check_macho_binary():
            self.report["target_type"] = "mach-o"
            self.analyze_macho_binary()
        elif self._check_ipa_file():
            self.report["target_type"] = "ipa"
            print(f"{infoS} This feature will release coming soon!")
            self.report["errors"].append("ipa_analysis_not_implemented")
        else:
            print(f"{errorS} Unknown file type!")
            self.report["target_type"] = "unknown"
            self.report["errors"].append("unknown_file_type")

    # ------------------------------------------------------------------
    # File hashes
    # ------------------------------------------------------------------

    def _compute_file_hashes(self):
        data = self._target_binary_buff
        hashes = {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        htable = Table()
        htable.add_column("[bold green]Algorithm", justify="center")
        htable.add_column("[bold green]Hash", justify="center")
        for algo, val in hashes.items():
            htable.add_row(algo.upper(), val)
        print(htable)
        self.report["file_hashes"] = hashes

    # ------------------------------------------------------------------
    # Library analysis
    # ------------------------------------------------------------------

    def _parse_lib_list(self, lib_dict, column_label):
        parsed = []
        if lib_dict:
            table = Table()
            table.add_column(f"[bold green]{column_label}", justify="center")
            table.add_column("[bold green]Note", justify="center")
            for lib in lib_dict:
                lib_name = _to_text(lib.get("libname", ""))
                parsed.append(lib_name)
                if _is_suspicious_dylib(lib_name):
                    table.add_row(f"[bold red]{lib_name}[white]", "[bold red]Suspicious[white]")
                    self._add_risk("suspicious_dylib", f"Suspicious dylib: {lib_name}")
                else:
                    table.add_row(lib_name, "")
            print(table)
        return parsed

    def parse_libraries(self):
        return self._parse_lib_list(
            self.wmocha_object.get_dylib_names() or [], "Dynamic Libraries"
        )

    def parse_weak_libraries(self):
        return self._parse_lib_list(
            self.wmocha_object.get_weak_dylib_names() or [], "Weak Dynamic Libraries"
        )

    # ------------------------------------------------------------------
    # String-based IOC extraction
    # ------------------------------------------------------------------

    def _analyze_strings(self):
        try:
            raw_strings = self.wmocha_object.get_strings() or []
        except Exception:
            return

        urls, ips, emails, b64_blobs = [], [], [], []
        crypto = {"BTC": [], "ETH": [], "XMR": []}
        suspicious = {cat: [] for cat in _SUSPICIOUS_STRING_PATTERNS}
        seen = {"url": set(), "ip": set(), "email": set(), "b64": set()}

        for s in raw_strings:
            raw = s if isinstance(s, bytes) else s.encode()

            for m in _URL_RE.findall(raw):
                val = _to_text(m)
                if val not in seen["url"]:
                    try:
                        if chk_wlist(val.lower()):
                            seen["url"].add(val)
                            urls.append(val)
                    except Exception:
                        pass

            for m in _IP_RE.findall(raw):
                val = _to_text(m)
                if val not in seen["ip"] and not val.startswith(("127.", "0.", "169.254.", "255.")):
                    seen["ip"].add(val)
                    ips.append(val)

            for m in _EMAIL_RE.findall(raw):
                val = _to_text(m)
                if val not in seen["email"]:
                    seen["email"].add(val)
                    emails.append(val)

            for m in _B64_RE.findall(raw):
                val = _to_text(m)
                if val not in seen["b64"]:
                    seen["b64"].add(val)
                    b64_blobs.append(val)

            for m in _BTC_RE.findall(raw):
                val = _to_text(m)
                if val not in crypto["BTC"]:
                    crypto["BTC"].append(val)
            for m in _ETH_RE.findall(raw):
                val = _to_text(m)
                if val not in crypto["ETH"]:
                    crypto["ETH"].append(val)
            for m in _XMR_RE.findall(raw):
                val = _to_text(m)
                if val not in crypto["XMR"]:
                    crypto["XMR"].append(val)

            for category, patterns in _SUSPICIOUS_STRING_PATTERNS.items():
                for pat in patterns:
                    if pat in raw:
                        entry = _to_text(raw[:120].rstrip())
                        if entry not in suspicious[category]:
                            suspicious[category].append(entry)
                        break

        # --- Print & risk ---
        if urls:
            t = Table()
            t.add_column("[bold green]Extracted URLs", justify="center")
            for u in urls: t.add_row(u)
            print(t)

        if ips:
            t = Table()
            t.add_column("[bold green]Extracted IP Addresses", justify="center")
            for ip in ips: t.add_row(ip)
            print(t)
            self._add_risk("suspicious_ip", f"Embedded IP addresses ({len(ips)})", min(len(ips), 3))

        if emails:
            t = Table()
            t.add_column("[bold green]Extracted Email Addresses", justify="center")
            for e in emails: t.add_row(e)
            print(t)

        for category, hits in suspicious.items():
            if hits:
                t = Table()
                t.add_column(f"[bold yellow]Suspicious Strings – {category}", justify="center")
                for h in hits[:20]: t.add_row(f"[bold red]{h}[white]")
                print(t)
                wkey = {
                    "Reverse Shell / C2": "reverse_shell",
                    "Privilege Escalation": "privilege_escalation",
                    "Download/Staging": "download_staging",
                    "Persistence Paths": "persistence",
                }.get(category, "suspicious_ip")
                self._add_risk(wkey, f"Suspicious strings – {category}")

        if b64_blobs:
            t = Table()
            t.add_column("[bold green]Possible Base64 Blobs", justify="center")
            for blob in b64_blobs[:10]:
                t.add_row(f"[bold yellow]{blob[:80]}{'…' if len(blob)>80 else ''}[white]")
            print(t)
            self._add_risk("base64_blob", "Large base64 blobs found (possible payload)")

        for coin, addrs in crypto.items():
            if addrs:
                t = Table()
                t.add_column(f"[bold green]{coin} Addresses", justify="center")
                for a in addrs: t.add_row(f"[bold yellow]{a}[white]")
                print(t)
                self._add_risk("crypto_address", f"Crypto addresses ({coin}) found")

        if not any([urls, ips, emails, any(suspicious.values()), b64_blobs, any(crypto.values())]):
            print(f"{errorS} No notable strings found.")

        self.report["extracted_urls"]     = urls
        self.report["extracted_ips"]      = ips
        self.report["extracted_emails"]   = emails
        self.report["suspicious_strings"] = {k: v for k, v in suspicious.items() if v}
        self.report["base64_blobs"]       = b64_blobs[:20]
        self.report["crypto_addresses"]   = {k: v for k, v in crypto.items() if v}

    # ------------------------------------------------------------------
    # Entitlement analysis
    # ------------------------------------------------------------------

    def _analyze_entitlements(self):
        try:
            plists = self.wmocha_object.get_plists() or []
        except Exception as exc:
            self.report["errors"].append(f"entitlements_error:{exc}")
            print(f"{errorS} Could not read code signature blob (unsigned binary?).")
            return

        entitlements = {}
        dangerous_found = {}

        for tree in plists:
            try:
                root = tree.getroot()
                dict_el = root.find("dict")
                if dict_el is None:
                    continue
                children = list(dict_el)
                i = 0
                while i < len(children) - 1:
                    if children[i].tag == "key":
                        key = children[i].text or ""
                        val_el = children[i + 1]
                        if val_el.tag in ("true", "false"):
                            value = val_el.tag
                        elif val_el.tag == "string":
                            value = val_el.text or ""
                        elif val_el.tag == "array":
                            value = [c.text for c in val_el if c.text]
                        else:
                            value = val_el.tag
                        entitlements[key] = value
                        if key in _DANGEROUS_ENTITLEMENTS:
                            dangerous_found[key] = _DANGEROUS_ENTITLEMENTS[key]
                    i += 1
            except Exception:
                continue

        if entitlements:
            t = Table()
            t.add_column("[bold green]Entitlement Key",  justify="center")
            t.add_column("[bold green]Value",            justify="center")
            t.add_column("[bold green]Risk",             justify="center")
            for key, val in entitlements.items():
                if key in _DANGEROUS_ENTITLEMENTS:
                    t.add_row(
                        f"[bold red]{key}[white]", str(val),
                        f"[bold red]{_DANGEROUS_ENTITLEMENTS[key]}[white]"
                    )
                else:
                    t.add_row(key, str(val), "")
            print(t)

        for key, desc in dangerous_found.items():
            self._add_risk("dangerous_entitlement", f"Dangerous entitlement: {key}")

        if dangerous_found:
            print(f"\n[bold red][!][white] [bold yellow]{len(dangerous_found)} dangerous entitlement(s) detected![white]")
        elif not entitlements:
            print(f"{errorS} No entitlements found.")

        self.report["entitlements"] = entitlements

    # ------------------------------------------------------------------
    # Application identifier
    # ------------------------------------------------------------------

    def _analyze_app_identifier(self):
        try:
            app_id = self.wmocha_object.application_identifier()
            if app_id:
                print(f"[bold magenta]>>>>[white] Application Identifier: [bold green]{app_id}")
                self.report["application_identifier"] = app_id
        except Exception:
            pass

    # ------------------------------------------------------------------
    # DYLD / DYSYMTAB / LC_DATA_IN_CODE
    # ------------------------------------------------------------------

    def _analyze_dyld(self):
        try:
            dyld = self.wmocha_object.get_dyld_info() or {}
            if dyld:
                dyld_out = {k: _to_text(v) for k, v in dyld.items()}
                self.report["dyld_info"] = dyld_out
                t = Table()
                t.add_column("[bold green]DYLD Info Field", justify="center")
                t.add_column("[bold green]Value",           justify="center")
                for k, v in dyld_out.items(): t.add_row(k, v)
                print(t)
        except Exception:
            pass

        try:
            dysym = self.wmocha_object.get_dysymtab_info() or {}
            if dysym:
                dysym_out = {k: _to_text(v) for k, v in dysym.items()}
                self.report["dysymtab_info"] = dysym_out
                t = Table()
                t.add_column("[bold green]DYSYMTAB Field", justify="center")
                t.add_column("[bold green]Value",          justify="center")
                for k, v in dysym_out.items(): t.add_row(k, v)
                print(t)
        except Exception:
            pass

        try:
            dic = self.wmocha_object.get_data_in_code() or {}
            if dic:
                dic_out = {k: _to_text(v) for k, v in dic.items()}
                self.report["data_in_code"] = dic_out
                datasize = int(dic_out.get("datasize", b"0").replace(b"", 0) if isinstance(dic_out.get("datasize"), bytes) else dic_out.get("datasize", "0x0"), 16)
                if datasize > 0:
                    print(f"{infoS} LC_DATA_IN_CODE: dataoff=[bold green]{dic_out.get('dataoff')}[white] datasize=[bold green]{dic_out.get('datasize')}[white]")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Section anomaly detection
    # ------------------------------------------------------------------

    def _detect_section_anomalies(self, sec_report):
        anomalies = []
        t = Table()
        t.add_column("[bold green]Section",   justify="center")
        t.add_column("[bold green]Anomaly",   justify="center")
        t.add_column("[bold green]Detail",    justify="center")
        found = False

        # Known-benign section names
        _NORMAL_SECTIONS = {
            "__text", "__stubs", "__stub_helper", "__cstring", "__const",
            "__data", "__bss", "__common", "__got", "__la_symbol_ptr",
            "__nl_symbol_ptr", "__mod_init_func", "__mod_term_func",
            "__objc_methnames", "__objc_classnames", "__objc_classrefs",
            "__objc_selrefs", "__objc_protolist", "__objc_imageinfo",
            "__objc_const", "__objc_ivar", "__objc_data", "__swift5_types",
            "__swift5_protos", "__swift5_proto", "__swift5_reflstr",
            "__unwind_info", "__eh_frame", "__compact_unwind",
            "__gosymtab", "__gopclntab", "__go_buildinfo",
            "__info_plist", "__code_signature",
        }

        for sec in sec_report:
            sec_name = sec.get("name", "")
            size_hex = sec.get("size", "0x0")
            offset_hex = sec.get("offset", "0x0")

            # Try reading section data for entropy
            try:
                size_val = int(size_hex, 16) if size_hex.startswith("0x") else int(size_hex)
                offset_val = int(offset_hex, 16) if offset_hex.startswith("0x") else int(offset_hex)
            except Exception:
                size_val, offset_val = 0, 0

            # 1. High entropy section (possible encryption/packing)
            if 0 < size_val <= 8 * 1024 * 1024 and offset_val > 0:
                try:
                    sec_data = self._target_binary_buff[offset_val:offset_val + size_val]
                    ent = _entropy(sec_data)
                    if ent > 7.2 and sec_name not in ("__text", "__stubs"):
                        anomalies.append({"section": sec_name, "anomaly": "High Entropy",
                                          "detail": f"{ent:.2f}/8.0 (encrypted/packed?)"})
                        t.add_row(sec_name, "[bold yellow]High Entropy[white]",
                                  f"[bold yellow]{ent:.2f}/8.0[white]")
                        found = True
                except Exception:
                    pass

            # 2. Unusual section name (not in known list)
            clean_name = sec_name.strip()
            if clean_name and clean_name not in _NORMAL_SECTIONS:
                anomalies.append({"section": sec_name, "anomaly": "Unknown Section Name",
                                  "detail": sec_name})
                t.add_row(sec_name, "[bold red]Unknown Section Name[white]", sec_name)
                found = True

            # 3. Suspiciously large section size (> 50 MB could indicate bloating)
            if size_val > 50 * 1024 * 1024:
                anomalies.append({"section": sec_name, "anomaly": "Oversized Section",
                                  "detail": f"{size_val // (1024*1024)} MB"})
                t.add_row(sec_name, "[bold red]Oversized Section[white]",
                          f"[bold red]{size_val // (1024*1024)} MB[white]")
                found = True

        if found:
            print(t)
        else:
            print(f"{errorS} No section anomalies detected.")

        self.report["section_anomalies"] = anomalies

    # ------------------------------------------------------------------
    # YARA scanning
    # ------------------------------------------------------------------

    def _scan_yara(self):
        if yara_rule_scanner is None:
            print(f"{errorS} YARA scanner not available.")
            return

        osx_rules = f"{sc0pe_path}{path_seperator}Systems{path_seperator}OSX{path_seperator}YaraRules_OSX"
        multi_rules = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}YaraRules_Multiple"

        matched_any = False
        for rulepath in (osx_rules, multi_rules):
            hit = yara_rule_scanner(
                rulepath, self.target_file, self.report,
                quiet_nomatch=True, quiet_errors=True
            )
            if hit:
                matched_any = True
                self._add_risk("yara_match", f"YARA rule matched ({os.path.basename(rulepath)})")

        if not matched_any:
            print(f"{errorS} No YARA rules matched.")

    # ------------------------------------------------------------------
    # C2 / special artifact detection
    # ------------------------------------------------------------------

    def _detect_special_artifacts(self):
        spec_path = (f"{sc0pe_path}{path_seperator}Systems{path_seperator}"
                     f"Multiple{path_seperator}special_artifact_patterns.json")
        try:
            with open(spec_path) as f:
                special = json.load(f)
        except Exception:
            return

        t = Table()
        t.add_column("[bold green]Artifact",    justify="center")
        t.add_column("[bold green]Pattern",     justify="center")
        t.add_column("[bold green]Occurrences", justify="center")
        found = {}
        hit_count = 0

        for artifact_name, data in special.items():
            for pat in data.get("patterns", []):
                try:
                    matches = re.findall(pat.encode(), self._target_binary_buff)
                except Exception:
                    matches = []
                if matches:
                    t.add_row(f"[bold red]{artifact_name}[white]",
                              pat, f"[bold red]{len(matches)}[white]")
                    found.setdefault(artifact_name, []).append(pat)
                    hit_count += 1

        if hit_count:
            print(t)
            for name in found:
                self._add_risk("c2_artifact", f"C2/tool artifact detected: {name}")
        else:
            print(f"{errorS} No special artifact patterns found.")

        self.report["special_artifacts"] = found

    # ------------------------------------------------------------------
    # Go binary deep analysis
    # ------------------------------------------------------------------

    def _analyze_go_binary_deep(self):
        if not _GOLANG_PARSER_AVAILABLE:
            print(f"{errorS} GolangParser not available.")
            return
        try:
            gp = GolangParser(self.target_file)
            gp.golang_analysis_main()
            go_report = gp.record_analysis_summary()
            self.report["golang"]["analysis_performed"] = True
            self.report["golang"]["findings_by_category"] = (
                go_report if isinstance(go_report, dict) else {}
            )
            # Surface category counts
            if isinstance(go_report, dict):
                counts = {k: len(v) for k, v in go_report.items() if v}
                self.report["golang"]["finding_counts"] = counts
                if counts:
                    t = Table()
                    t.add_column("[bold green]Go Category", justify="center")
                    t.add_column("[bold green]Findings",    justify="center")
                    for cat, cnt in counts.items():
                        t.add_row(cat, str(cnt))
                    print(t)
        except Exception as exc:
            self.report["errors"].append(f"golang_analysis_error:{exc}")

    # ------------------------------------------------------------------
    # Pattern-based category scan
    # ------------------------------------------------------------------

    def _perform_pattern_analysis(self):
        cats_path = (f"{sc0pe_path}{path_seperator}Systems{path_seperator}"
                     f"OSX{path_seperator}osx_sym_categories.json")
        with open(cats_path) as f:
            osx_patterns = json.load(f)

        for key in osx_patterns:
            if key not in self.categ_patterns:
                self.categ_patterns[key] = []
            for pattern in osx_patterns[key].get("patterns", []):
                try:
                    hit = re.findall(str(pattern).encode(), self._target_binary_buff)
                except Exception:
                    hit = []
                if hit and pattern not in self.categ_patterns[key]:
                    self.categ_patterns[key].append(pattern)

        self._categ_parser()
        self._print_statistics()
        self.report["categorized_patterns"] = {k: v for k, v in self.categ_patterns.items() if v}

        # Risk from high-signal categories
        for cat in ("Anti-Analysis", "Privilege Escalation", "Screen/Input Capture",
                    "Keychain/Credential Access"):
            if self.categ_patterns.get(cat):
                self._add_risk(
                    "anti_analysis" if "Anti" in cat else "privilege_escalation",
                    f"Pattern category hit: {cat}"
                )

    def _categ_parser(self):
        for key, patterns in self.categ_patterns.items():
            if patterns:
                t = Table()
                t.add_column(f"Patterns about [bold green]{key}", justify="center")
                for p in patterns:
                    t.add_row(f"[bold red]{p}")
                print(t)

    def _print_statistics(self):
        print(f"\n[bold green]->[white] Statistics for: [bold green][i]{self.target_file}[/i]")
        t = Table()
        t.add_column("Categories",         justify="center")
        t.add_column("Number of Patterns", justify="center")
        category_counts = {}
        _HIGH_SIGNAL = {"Cryptography/SSL Handling", "Information Gathering",
                        "Anti-Analysis", "Privilege Escalation",
                        "Keychain/Credential Access", "Screen/Input Capture"}
        for key, patterns in self.categ_patterns.items():
            if patterns:
                count = len(patterns)
                category_counts[key] = count
                if key in _HIGH_SIGNAL:
                    t.add_row(f"[bold yellow]{key}", f"[bold red]{count}")
                else:
                    t.add_row(key, str(count))
        self.report["statistics"]["category_pattern_counts"] = category_counts
        print(t)

    # ------------------------------------------------------------------
    # Risk score finalisation
    # ------------------------------------------------------------------

    def _finalise_risk_score(self):
        score = self._risk_score
        if score <= 3:
            level = "[bold green]Low[white]"
            level_plain = "Low"
        elif score <= 7:
            level = "[bold yellow]Medium[white]"
            level_plain = "Medium"
        elif score <= 14:
            level = "[bold red]High[white]"
            level_plain = "High"
        else:
            level = "[bold white on red]Critical[white]"
            level_plain = "Critical"

        print(f"\n[bold green]->[white] Risk Assessment for: [bold green][i]{self.target_file}[/i]")
        t = Table()
        t.add_column("[bold green]Risk Score", justify="center")
        t.add_column("[bold green]Risk Level", justify="center")
        t.add_row(str(score), level)
        print(t)

        if self._risk_reasons:
            rt = Table()
            rt.add_column("[bold green]Contributing Factors", justify="center")
            for r in self._risk_reasons:
                rt.add_row(f"[bold yellow]{r}[white]")
            print(rt)

        self.report["risk_score"]   = score
        self.report["risk_level"]   = level_plain
        self.report["risk_reasons"] = self._risk_reasons

    # ------------------------------------------------------------------
    # Main analysis orchestrator
    # ------------------------------------------------------------------

    def analyze_macho_binary(self):
        # ── File hashes ───────────────────────────────────────────────
        print(f"{infoS} Computing file hashes...")
        self._compute_file_hashes()

        # ── Binary info ──────────────────────────────────────────────
        print(f"\n{infoS} Binary Information")
        binary_info = self.wmocha_object.get_binary_info() or {}
        bin_info_out = dict(self.report["binary_info"])   # keep format key
        for key in binary_info:
            value = _to_text(binary_info[key])
            bin_info_out[str(key)] = value
            print(f"[bold magenta]>>>>[white] {key}: [bold green]{value}")

        try:
            ep = self.wmocha_object.get_entrypoint()
            if ep is not None:
                ep_str = _to_text(ep)
                bin_info_out["entrypoint"] = ep_str
                self.report["entrypoint"] = ep_str
                print(f"[bold magenta]>>>>[white] Entrypoint: [bold green]{ep_str}")
        except Exception:
            pass

        self._analyze_app_identifier()
        self.report["binary_info"] = bin_info_out

        # ── Code signature ───────────────────────────────────────────
        print(f"\n{infoS} Checking code signature...")
        try:
            cs_info = self.wmocha_object.code_signature_info() or {}
            cs_out  = {k: _to_text(v) for k, v in cs_info.items()}
            self.report["code_signature"] = cs_out
            t = Table()
            t.add_column("[bold green]Code Signature Field", justify="center")
            t.add_column("[bold green]Value",                justify="center")
            for k, v in cs_out.items(): t.add_row(k, v)
            print(t)
        except Exception:
            print(f"{errorS} No code signature found (binary may be unsigned).")
            self.report["code_signature"] = {}
            self._add_risk("unsigned", "Binary is unsigned")

        # ── Entitlements ─────────────────────────────────────────────
        print(f"\n{infoS} Analyzing entitlements...")
        self._analyze_entitlements()

        # ── Segments ─────────────────────────────────────────────────
        print(f"\n{infoS} Parsing segment information...")
        t = Table()
        for col in ("name", "offset", "cmd", "cmdsize", "vmaddr", "vmsize", "filesize"):
            t.add_column(f"[bold green]{col}", justify="center")
        segments   = self.wmocha_object.get_segments() or []
        seg_report = []
        for seg in segments:
            seg_name = _to_text(seg.get("segment_name", ""))
            try:
                si = self.wmocha_object.segment_info(seg_name)
            except Exception as exc:
                self.report["errors"].append(f"segment_info_error:{seg_name}:{exc}")
                continue
            row = {
                "name":     seg_name,
                "offset":   _to_text(si.get("offset",   "")),
                "cmd":      _to_text(si.get("cmd",       "")),
                "cmdsize":  _to_text(si.get("cmdsize",   "")),
                "vmaddr":   _to_text(si.get("vmaddr",    "")),
                "vmsize":   _to_text(si.get("vmsize",    "")),
                "filesize": _to_text(si.get("filesize",  "")),
            }
            seg_report.append(row)
            t.add_row(*row.values())
        self.report["segments"] = seg_report
        print(t)

        # ── Sections ─────────────────────────────────────────────────
        print(f"\n{infoS} Analyzing sections...")
        t = Table()
        for col in ("name", "segment", "offset", "size"):
            t.add_column(f"[bold green]{col}", justify="center")
        sections   = self.wmocha_object.get_sections() or []
        sec_report = []
        is_go_binary = False
        for sec in sections:
            sec_name = _to_text(sec.get("section_name", ""))
            try:
                si = self.wmocha_object.section_info(sec_name)
                seg_name = _to_text(si.get("segment_name", ""))
                offset   = _to_text(si.get("offset", ""))
                size     = _to_text(si.get("size",   ""))
                sec_report.append({"name": sec_name, "segment": seg_name,
                                   "offset": offset, "size": size})
                go_markers = ("__gosymtab", "__gopclntab", "__go_buildinfo")
                if any(g in sec_name for g in go_markers):
                    is_go_binary = True
                    t.add_row(f"[bold red]{sec_name}[white]", seg_name, offset, size)
                else:
                    t.add_row(sec_name, seg_name, offset, size)
            except Exception:
                continue

        self.report["sections"]     = sec_report
        self.report["is_go_binary"] = is_go_binary
        self.report["golang"]["detected"] = is_go_binary
        if is_go_binary:
            print(f"\n{infoS} [bold yellow]Go binary detected[white] (__gosymtab / __gopclntab / __go_buildinfo)")
        print(t)

        # ── Section anomaly detection ─────────────────────────────────
        print(f"\n{infoS} Detecting section anomalies...")
        self._detect_section_anomalies(sec_report)

        # ── Libraries ────────────────────────────────────────────────
        print(f"\n{infoS} Analyzing libraries...")
        self.report["dynamic_libraries"] = self.parse_libraries()

        print(f"\n{infoS} Analyzing weak libraries...")
        self.report["weak_dynamic_libraries"] = self.parse_weak_libraries()

        # ── DYLD / DYSYMTAB / LC_DATA_IN_CODE ────────────────────────
        print(f"\n{infoS} Parsing DYLD / DYSYMTAB / LC_DATA_IN_CODE...")
        self._analyze_dyld()

        # ── YARA scanning ─────────────────────────────────────────────
        print(f"\n{infoS} Running YARA rules...")
        self._scan_yara()

        # ── C2 / special artifact detection ───────────────────────────
        print(f"\n{infoS} Performing special artifact detection...")
        self._detect_special_artifacts()

        # ── String-based IOC extraction ───────────────────────────────
        print(f"\n{infoS} Extracting and scanning strings for IOCs...")
        self._analyze_strings()

        # ── Go binary deep analysis ───────────────────────────────────
        if is_go_binary:
            print(f"\n{infoS} Running Go binary deep analysis...")
            self._analyze_go_binary_deep()

        # ── Pattern category scan ─────────────────────────────────────
        print(f"\n{infoS} Performing pattern scan...")
        self._perform_pattern_analysis()

        # ── Risk score ────────────────────────────────────────────────
        self._finalise_risk_score()


def main():
    if len(sys.argv) < 2:
        err_exit("Usage: apple_analyzer.py <file> [save_report=True|False]")

    target_file = sys.argv[1]
    apa = AppleAnalyzer(target_file=target_file)
    apa.check_target_type()
    if get_argv(2) == "True":
        save_report("osx", apa.report)


if __name__ == "__main__":
    main()
