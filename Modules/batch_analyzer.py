#!/usr/bin/python3

import hashlib
import ipaddress
import os
import re
from collections import OrderedDict

try:
    # Module execution (python -m Modules.batch_analyzer)
    from .utils.helpers import err_exit, get_argv, save_report
    from .analysis.multiple.multi import yara_rule_scanner
except ImportError:
    # Raw execution (python Modules/batch_analyzer.py)
    from utils.helpers import err_exit, get_argv, save_report
    from analysis.multiple.multi import yara_rule_scanner

try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< module not found.")


TARGET_FILE = str(get_argv(1, "")).strip()
if not TARGET_FILE:
    err_exit("[bold white on red]Target file not found!\n")
EMIT_REPORT = str(get_argv(2, "False")).strip().lower() == "true"

infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

CATEGORY_PATTERNS = OrderedDict(
    {
        "Execution": [
            r"\bcmd\.exe\b",
            r"\bpowershell(?:\.exe)?\b",
            r"\brundll32\b",
            r"\bregsvr32\b",
            r"\bmshta\b",
            r"\bwscript\b",
            r"\bcscript\b",
            r"\bstart\b",
            r"\bcall\b",
        ],
        "Persistence": [
            r"\bschtasks\b",
            r"\\currentversion\\run\b",
            r"\\currentversion\\runonce\b",
            r"\bstartup\b",
            r"\breg\s+add\b",
            r"\bsc\s+create\b",
        ],
        "Defense Evasion": [
            r"\bvssadmin\b",
            r"\bwevtutil\b",
            r"\bwmic\b",
            r"\bbcdedit\b",
            r"\bnetsh\b",
            r"\bdel\s+/f\b",
            r"\berase\b",
        ],
        "Download/Network": [
            r"\bcurl\b",
            r"\bwget\b",
            r"\bbitsadmin\b",
            r"\bcertutil\b",
            r"\bftp\b",
            r"\btftp\b",
            r"https?://",
        ],
        "Obfuscation": [
            r"\bsetlocal\s+enabledelayedexpansion\b",
            r"![a-z0-9_]+!",
            r"\^",
            r"\bfor\s+/f\b",
            r"\bbase64\b",
            r"-enc\b",
            r"%[a-z0-9_]+%",
        ],
    }
)


def _safe_decode(data):
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="ignore")


def _calc_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _normalize_line(line):
    return re.sub(r"\s+", " ", str(line or "").strip())


def _is_comment_or_empty(line):
    s = _normalize_line(line)
    if not s:
        return True
    lower = s.lower()
    if lower.startswith("rem "):
        return True
    if lower == "rem":
        return True
    if lower.startswith("::"):
        return True
    return False


def _unique(values, limit=200):
    out = []
    seen = set()
    for raw in values:
        val = str(raw or "").strip()
        if not val:
            continue
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(val)
        if len(out) >= limit:
            break
    return out


def _extract_urls(text):
    urls = []
    for raw in URL_RE.findall(text):
        candidate = str(raw).strip().rstrip(".,;:)]}>\"'")
        if candidate:
            urls.append(candidate)
    return _unique(urls, limit=200)


def _extract_ips(text):
    ips = []
    for raw in IP_RE.findall(text):
        try:
            ip_obj = ipaddress.ip_address(raw)
            if ip_obj.is_unspecified:
                continue
            ips.append(str(ip_obj))
        except Exception:
            continue
    return _unique(ips, limit=200)


def _scan_categories(lines):
    out = OrderedDict((key, []) for key in CATEGORY_PATTERNS.keys())
    compiled = {
        key: [re.compile(pat, re.IGNORECASE) for pat in patterns]
        for key, patterns in CATEGORY_PATTERNS.items()
    }

    for line in lines:
        norm = _normalize_line(line)
        if _is_comment_or_empty(norm):
            continue
        for key, patterns in compiled.items():
            for cre in patterns:
                if cre.search(norm):
                    out[key].append(norm)
                    break
    for key in list(out.keys()):
        out[key] = _unique(out[key], limit=120)
    return out


def _scan_yara(target_file):
    rep = {"matched_rules": []}
    try:
        hit = yara_rule_scanner(
            "/Systems/Windows/YaraRules_Windows/",
            target_file,
            rep,
            quiet_nomatch=True,
            header_label="",
            quiet_errors=True,
            print_matches=False,
            print_nomatch=False,
        )
        if not hit:
            return []
        return rep.get("matched_rules", [])
    except Exception:
        return []


def _print_summary(categories, urls, ips, matched_rules):
    summary = Table(title="* Batch Script Analysis Summary *", title_style="bold italic cyan", title_justify="center")
    summary.add_column("[bold green]Category", justify="center")
    summary.add_column("[bold green]Count", justify="center")
    for key, values in categories.items():
        if values:
            summary.add_row(key, str(len(values)))
    summary.add_row("Extracted URLs", str(len(urls)))
    summary.add_row("Extracted IP Addresses", str(len(ips)))
    summary.add_row("Matched YARA Rules", str(len(matched_rules)))
    print(summary)


def _print_category_details(categories):
    has_any = False
    for key, values in categories.items():
        if not values:
            continue
        has_any = True
        table = Table(title=f"* {key} *", title_style="bold italic cyan", title_justify="center")
        table.add_column("[bold green]Matched Lines", justify="left")
        for line in values[:30]:
            table.add_row(line)
        print(table)
    if not has_any:
        print(f"{errorS} No suspicious batch command pattern detected.")


def analyze():
    if not os.path.isfile(TARGET_FILE):
        err_exit("[bold white on red]Target file not found.\n")

    try:
        raw_data = open(TARGET_FILE, "rb").read()
    except Exception:
        err_exit("[bold white on red]An error occured while opening target file.\n")

    print(f"{infoS} Performing [bold green]Batch Script[white] analysis...")
    text = _safe_decode(raw_data)
    all_lines = text.splitlines()
    categories = _scan_categories(all_lines)
    urls = _extract_urls(text)
    ips = _extract_ips(text)
    matched_rules = _scan_yara(TARGET_FILE)

    _print_summary(categories, urls, ips, matched_rules)
    _print_category_details(categories)

    if EMIT_REPORT:
        md5, sha1, sha256 = _calc_hashes(TARGET_FILE)
        interesting = []
        for values in categories.values():
            interesting.extend(values)
        report = {
            "target_type": "batch_script",
            "analysis_mode": "static_pattern_scan",
            "filename": TARGET_FILE,
            "hash_md5": md5,
            "hash_sha1": sha1,
            "hash_sha256": sha256,
            "total_lines": len(all_lines),
            "non_empty_lines": sum(1 for x in all_lines if not _is_comment_or_empty(x)),
            "categories": {k: v for k, v in categories.items() if v},
            "interesting_string_patterns": _unique(interesting, limit=220),
            "extracted_urls": urls,
            "extracted_ips": ips,
            "matched_rules": matched_rules,
        }
        save_report("batch", report)


if __name__ == "__main__":
    analyze()
