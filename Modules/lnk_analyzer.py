#!/usr/bin/python3

import datetime
import hashlib
import ipaddress
import os
import re
import struct
from collections import OrderedDict

try:
    from .utils.helpers import err_exit, get_argv, save_report
    from .analysis.multiple.multi import yara_rule_scanner
except ImportError:
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
IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_RE = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")

# --- LNK binary constants (MS-SHLLINK) ---
LNK_MAGIC       = b'\x4C\x00\x00\x00'
LNK_HEADER_SIZE = 76

# LinkFlags
HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO          = 0x00000002
HAS_NAME               = 0x00000004
HAS_RELATIVE_PATH      = 0x00000008
HAS_WORKING_DIR        = 0x00000010
HAS_ARGUMENTS          = 0x00000020
HAS_ICON_LOCATION      = 0x00000040
IS_UNICODE             = 0x00000080
RUN_AS_USER            = 0x00002000

SHOW_COMMAND_MAP = {
    1: "Normal",
    2: "Minimized",
    3: "Maximized",
    7: "Minimized (hidden — no window activation)",
}

# Base names only — _find_lolbas matches both "name" and "name.exe"
LOLBAS = [
    "powershell", "cmd", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec",
    "wmic", "regasm", "installutil", "odbcconf", "pcalua",
    "forfiles", "schtasks", "reg", "regedit", "sc", "at",
]

CATEGORY_PATTERNS = OrderedDict({
    "Execution": [
        r"\bcmd(?:\.exe)?\b",
        r"\bpowershell(?:\.exe)?\b",
        r"\bmshta(?:\.exe)?\b",
        r"\bwscript(?:\.exe)?\b",
        r"\bcscript(?:\.exe)?\b",
        r"\brundll32(?:\.exe)?\b",
        r"\bregsvr32(?:\.exe)?\b",
        r"\biex\b",
        r"\binvoke-expression\b",
        r"\binvoke-webrequest\b",
        r"\bstart-process\b",
        r"(?:^|[\s,;|&])\/[ck]\s",
    ],
    "Persistence": [
        r"\bschtasks\b",
        r"\\currentversion\\run\b",
        r"\\currentversion\\runonce\b",
        r"\bstartup\b",
        r"\breg\s+add\b",
        r"\bsc\s+create\b",
        r"\\start menu\\programs\\startup",
        r"\bnet\s+user\b",
        r"\bnet\s+localgroup\b",
    ],
    "Defense Evasion": [
        r"-windowstyle\s+hidden",
        r"-w\s+hidden",
        r"\bbypass\b",
        r"-noprofile",
        r"-nop\b",
        r"-noninteractive",
        r"-executionpolicy\b",
        r"-ep\s+bypass",
        r"\bwmic\b",
        r"\bvssadmin\b",
        r"\bwevtutil\b",
        r"\bbcdedit\b",
        r"\bnetsh\b",
    ],
    "Download/Network": [
        r"\bdownloadstring\b",
        r"\bdownloadfile\b",
        r"\bwebclient\b",
        r"\binvoke-webrequest\b",
        r"\biwr\b",
        r"\bbitsadmin\b",
        r"\bcertutil\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"https?://",
        r"\bftp://",
        r"\\\\[a-z0-9_\-\.]+\\",
    ],
    "Obfuscation": [
        r"-enc(?:odedcommand)?\b",
        r"\bfrombase64string\b",
        r"\bbase64\b",
        r"\bchr\s*\(",
        r"\[char\]",
        r"\bcharcode\b",
        r"[A-Za-z0-9+/]{60,}={0,2}",
        r"%[a-zA-Z0-9_]{2,20}%",
        r"\$env:",
    ],
})


# --- LNK binary parser ---

def _filetime_to_str(ft):
    if ft == 0:
        return ""
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch + datetime.timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def _read_counted_str(data, offset, is_unicode):
    """Read a CountedString from StringData: 2-byte char count + chars."""
    if offset + 2 > len(data):
        return "", offset
    count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if is_unicode:
        byte_count = count * 2
        s = data[offset:offset + byte_count].decode("utf-16-le", errors="replace")
        return s, offset + byte_count
    else:
        s = data[offset:offset + count].decode("latin-1", errors="replace")
        return s, offset + count


def _parse_lnk(data):
    """
    Parse a Windows Shell Link (.lnk) binary.
    Returns dict of extracted fields, or None if not a valid LNK.
    """
    result = {
        "link_flags": 0,
        "file_attributes": 0,
        "creation_time": "",
        "access_time": "",
        "write_time": "",
        "target_file_size": 0,
        "icon_index": 0,
        "show_command": "",
        "show_command_raw": 0,
        "hotkey": "",
        "run_as_user": False,
        "target_path": "",
        "local_base_path": "",
        "network_share": "",
        "name": "",
        "relative_path": "",
        "working_dir": "",
        "arguments": "",
        "icon_location": "",
    }

    if len(data) < LNK_HEADER_SIZE:
        return None
    if data[:4] != LNK_MAGIC:
        return None

    link_flags = struct.unpack_from("<I", data, 20)[0]
    file_attrs  = struct.unpack_from("<I", data, 24)[0]
    ctime       = struct.unpack_from("<Q", data, 28)[0]
    atime       = struct.unpack_from("<Q", data, 36)[0]
    wtime       = struct.unpack_from("<Q", data, 44)[0]
    file_size   = struct.unpack_from("<I", data, 52)[0]
    icon_index  = struct.unpack_from("<I", data, 56)[0]
    show_cmd    = struct.unpack_from("<I", data, 60)[0]
    hotkey_raw  = struct.unpack_from("<H", data, 64)[0]

    result["link_flags"]       = link_flags
    result["file_attributes"]  = file_attrs
    result["creation_time"]    = _filetime_to_str(ctime)
    result["access_time"]      = _filetime_to_str(atime)
    result["write_time"]       = _filetime_to_str(wtime)
    result["target_file_size"] = file_size
    result["icon_index"]       = icon_index
    result["show_command_raw"] = show_cmd
    result["show_command"]     = SHOW_COMMAND_MAP.get(show_cmd, f"0x{show_cmd:08X}")
    result["run_as_user"]      = bool(link_flags & RUN_AS_USER)

    if hotkey_raw:
        vk  = hotkey_raw & 0xFF
        mod = (hotkey_raw >> 8) & 0xFF
        mod_str = ""
        if mod & 0x01: mod_str += "SHIFT+"
        if mod & 0x02: mod_str += "CTRL+"
        if mod & 0x04: mod_str += "ALT+"
        key_char = chr(vk) if 0x20 <= vk <= 0x7E else f"VK_{vk:02X}"
        result["hotkey"] = f"{mod_str}{key_char}"

    offset = LNK_HEADER_SIZE
    is_unicode = bool(link_flags & IS_UNICODE)

    # Skip LinkTargetIDList
    if link_flags & HAS_LINK_TARGET_IDLIST:
        if offset + 2 > len(data):
            return result
        idlist_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + idlist_size

    # Parse LinkInfo
    if link_flags & HAS_LINK_INFO:
        if offset + 4 > len(data):
            return result
        li_size  = struct.unpack_from("<I", data, offset)[0]
        li_start = offset
        if li_size >= 0x1C and offset + li_size <= len(data):
            li_flags       = struct.unpack_from("<I", data, li_start + 8)[0]
            local_base_off = struct.unpack_from("<I", data, li_start + 16)[0]
            net_rel_off    = struct.unpack_from("<I", data, li_start + 20)[0]
            common_path_off= struct.unpack_from("<I", data, li_start + 24)[0]

            # LocalBasePath (VolumeID path, flag bit 0)
            if (li_flags & 0x01) and local_base_off:
                pos = li_start + local_base_off
                end = data.find(b'\x00', pos)
                if end != -1:
                    result["local_base_path"] = data[pos:end].decode("latin-1", errors="replace")

            # CommonNetworkRelativeLink → NetworkShareName (flag bit 1)
            if (li_flags & 0x02) and net_rel_off:
                net_start = li_start + net_rel_off
                if net_start + 20 <= len(data):
                    net_name_off = struct.unpack_from("<I", data, net_start + 8)[0]
                    pos = net_start + net_name_off
                    end = data.find(b'\x00', pos)
                    if end != -1:
                        result["network_share"] = data[pos:end].decode("latin-1", errors="replace")

            # Assemble target_path = LocalBasePath + CommonPathSuffix
            if result["local_base_path"]:
                suffix_pos = li_start + common_path_off
                suffix_end = data.find(b'\x00', suffix_pos)
                if suffix_end != -1:
                    suffix = data[suffix_pos:suffix_end].decode("latin-1", errors="replace")
                    result["target_path"] = result["local_base_path"] + suffix
                else:
                    result["target_path"] = result["local_base_path"]
        offset += li_size

    # Parse StringData (order is fixed by spec)
    if link_flags & HAS_NAME:
        s, offset = _read_counted_str(data, offset, is_unicode)
        result["name"] = s

    if link_flags & HAS_RELATIVE_PATH:
        s, offset = _read_counted_str(data, offset, is_unicode)
        result["relative_path"] = s

    if link_flags & HAS_WORKING_DIR:
        s, offset = _read_counted_str(data, offset, is_unicode)
        result["working_dir"] = s

    if link_flags & HAS_ARGUMENTS:
        s, offset = _read_counted_str(data, offset, is_unicode)
        result["arguments"] = s

    if link_flags & HAS_ICON_LOCATION:
        s, offset = _read_counted_str(data, offset, is_unicode)
        result["icon_location"] = s

    return result


# --- Analysis helpers ---

def _calc_hashes(path):
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _unique(values, limit=200):
    out, seen = [], set()
    for raw in values:
        val = str(raw or "").strip()
        if not val or val.lower() in seen:
            continue
        seen.add(val.lower())
        out.append(val)
        if len(out) >= limit:
            break
    return out


def _extract_urls(text):
    return _unique(u.strip().rstrip(".,;:)]}>\"'") for u in URL_RE.findall(text))


def _extract_ips(text):
    ips = []
    for raw in IP_RE.findall(text):
        try:
            ip_obj = ipaddress.ip_address(raw)
            if not ip_obj.is_unspecified:
                ips.append(str(ip_obj))
        except Exception:
            continue
    return _unique(ips)


def _find_lolbas(text_fields):
    combined = " ".join(v for v in text_fields if v).lower()
    found = []
    for lol in LOLBAS:
        # Match both "name" and "name.exe" with a single pattern
        pat = r'\b' + re.escape(lol) + r'(?:\.exe)?\b'
        if re.search(pat, combined, re.IGNORECASE):
            found.append(lol)
    return found


def _scan_categories(lnk):
    """
    Scan each LNK string field independently against category patterns.
    Returns {category: [(field_label, full_field_value), ...]} so callers
    can display the complete content of the matched field — no context-window
    truncation.  Each field is listed at most once per category.
    """
    out = OrderedDict((k, []) for k in CATEGORY_PATTERNS.keys())
    compiled = {
        k: [re.compile(p, re.IGNORECASE) for p in patterns]
        for k, patterns in CATEGORY_PATTERNS.items()
    }

    # Fields scanned in priority order: (display label, lnk dict key)
    scan_fields = [
        ("Arguments",         "arguments"),
        ("Target Path",       "target_path"),
        ("Relative Path",     "relative_path"),
        ("Working Directory", "working_dir"),
        ("Network Share",     "network_share"),
        ("Icon Location",     "icon_location"),
        ("Name",              "name"),
    ]

    for key, patterns in compiled.items():
        seen = set()
        for label, lnk_key in scan_fields:
            value = lnk.get(lnk_key, "").strip()
            if not value or label in seen:
                continue
            for cre in patterns:
                if cre.search(value):
                    out[key].append((label, value))
                    seen.add(label)
                    break   # one match per field per category is enough

    return out


def _detect_suspicious(lnk, file_size):
    indicators = []

    # Hidden window (SW_SHOWMINNOACTIVE = 7) — very common in LNK malware
    if lnk.get("show_command_raw") == 7:
        indicators.append("ShowCommand=Minimized/Hidden (SW_SHOWMINNOACTIVE): execution window is invisible")

    # RunAsUser → elevated execution
    if lnk.get("run_as_user"):
        indicators.append("RunAsUser flag set: shortcut requests elevated (admin) execution")

    # Long arguments — embedded payload indicator
    args = lnk.get("arguments", "")
    if len(args) > 260:
        indicators.append(f"Excessively long arguments ({len(args)} chars): possible embedded payload or obfuscated command")

    # Base64 content in arguments
    if B64_RE.search(args):
        indicators.append("Base64-encoded string found in command line arguments")

    # Encoded PowerShell command
    if re.search(r"-enc(?:odedcommand)?", args, re.IGNORECASE):
        indicators.append("PowerShell encoded command (-EncodedCommand / -enc) detected in arguments")

    # Execution policy bypass
    if re.search(r"bypass", args, re.IGNORECASE):
        indicators.append("Execution policy bypass keyword detected in arguments")

    # Hidden window style in arguments text
    if re.search(r"-windowstyle\s+hidden|-w\s+hidden", args, re.IGNORECASE):
        indicators.append("Hidden window style flag in arguments: process will be invisible to user")

    # UNC path in arguments (remote resource reference)
    if re.search(r"\\\\[a-zA-Z0-9]", args):
        indicators.append("UNC path detected in arguments: may reference a remote resource")

    # Network share target
    if lnk.get("network_share"):
        indicators.append(f"Target points to network share: {lnk['network_share']}")

    # Target in temp/appdata
    target = lnk.get("target_path", "")
    if target and re.search(r"\\(?:temp|tmp|appdata|roaming)\\", target, re.IGNORECASE):
        indicators.append(f"Target path in temp/AppData directory: {target}")

    # Working dir in temp/appdata
    wd = lnk.get("working_dir", "")
    if wd and re.search(r"\\(?:temp|tmp|appdata|roaming)\\", wd, re.IGNORECASE):
        indicators.append(f"Working directory in temp/AppData: {wd}")

    # Icon spoofing: icon points to different binary than target
    icon = lnk.get("icon_location", "")
    if icon and target and icon.lower() != target.lower():
        if re.search(r"\\system32\\|\\windows\\", icon, re.IGNORECASE):
            indicators.append(f"Icon spoofing: icon from system binary ({icon}) while target is different")

    # Env variables in target path
    if re.search(r"%(?:temp|appdata|userprofile|comspec|windir|systemroot)%", target, re.IGNORECASE):
        indicators.append("Environment variable in target path: may evade static path detection")

    # Abnormally large LNK file (embedded content)
    if file_size > 50 * 1024:
        indicators.append(f"Unusually large LNK file ({file_size // 1024} KB): may contain an embedded payload")

    return indicators


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


# --- Output printers ---

def _print_lnk_fields(lnk):
    table = Table(
        title="* LNK File Properties *",
        title_style="bold italic cyan",
        title_justify="center",
    )
    table.add_column("[bold green]Property", justify="left", min_width=26, no_wrap=True)
    table.add_column("[bold green]Value",    justify="left", overflow="fold")

    rows = [
        ("Target Path",            lnk.get("target_path") or lnk.get("local_base_path") or ""),
        ("Arguments",              lnk.get("arguments") or ""),
        ("Working Directory",      lnk.get("working_dir") or ""),
        ("Network Share",          lnk.get("network_share") or ""),
        ("Relative Path",          lnk.get("relative_path") or ""),
        ("Icon Location",          lnk.get("icon_location") or ""),
        ("Name / Description",     lnk.get("name") or ""),
        ("Show Command",           lnk.get("show_command") or ""),
        ("Hotkey",                 lnk.get("hotkey") or ""),
        ("Run As User",            "Yes" if lnk.get("run_as_user") else "No"),
        ("Target File Size",       f"{lnk.get('target_file_size', 0)} bytes" if lnk.get("target_file_size") else ""),
        ("Creation Time",          lnk.get("creation_time") or ""),
        ("Access Time",            lnk.get("access_time") or ""),
        ("Write Time",             lnk.get("write_time") or ""),
    ]
    for prop, val in rows:
        if val and val not in ("No",):
            table.add_row(prop, val)
    print(table)


def _print_summary(indicators, lolbas, categories, urls, ips, matched_rules):
    summary = Table(
        title="* LNK Analysis Summary *",
        title_style="bold italic cyan",
        title_justify="center",
    )
    summary.add_column("[bold green]Category", justify="center")
    summary.add_column("[bold green]Count",    justify="center")

    for key, matches in categories.items():
        if matches:
            summary.add_row(key, str(len(matches)))
    summary.add_row("Suspicious Indicators", str(len(indicators)))
    summary.add_row("LOLBAS Detected",        str(len(lolbas)))
    summary.add_row("Extracted URLs",         str(len(urls)))
    summary.add_row("Extracted IP Addresses", str(len(ips)))
    summary.add_row("Matched YARA Rules",     str(len(matched_rules)))
    print(summary)


def _print_indicators(indicators):
    if not indicators:
        return
    table = Table(
        title="* Suspicious Indicators *",
        title_style="bold italic cyan",
        title_justify="center",
    )
    table.add_column("[bold green]Indicator", justify="left")
    for ind in indicators:
        table.add_row(ind)
    print(table)


def _print_lolbas(lolbas):
    if not lolbas:
        return
    table = Table(
        title="* LOLBAS Detected *",
        title_style="bold italic cyan",
        title_justify="center",
    )
    table.add_column("[bold green]Binary / Script", justify="left")
    for lol in lolbas:
        table.add_row(lol)
    print(table)


def _print_category_details(categories):
    has_any = False
    for key, matches in categories.items():
        if not matches:
            continue
        has_any = True
        table = Table(
            title=f"* {key} *",
            title_style="bold italic cyan",
            title_justify="center",
        )
        table.add_column("[bold green]Field", justify="left", min_width=18, no_wrap=True)
        table.add_column("[bold green]Value", justify="left", overflow="fold")
        for label, value in matches:
            table.add_row(label, value)
        print(table)
    if not has_any:
        print(f"{errorS} No suspicious command pattern detected in LNK fields.")


# --- Main entry point ---

def analyze():
    if not os.path.isfile(TARGET_FILE):
        err_exit("[bold white on red]Target file not found.\n")

    try:
        raw_data = open(TARGET_FILE, "rb").read()
    except Exception:
        err_exit("[bold white on red]An error occurred while opening target file.\n")

    lnk = _parse_lnk(raw_data)
    if lnk is None:
        err_exit(f"{errorS} File does not appear to be a valid Windows Shortcut (bad magic or truncated header).\n")

    file_size = len(raw_data)

    text_fields = [
        lnk.get("target_path",    ""),
        lnk.get("local_base_path",""),
        lnk.get("network_share",  ""),
        lnk.get("arguments",      ""),
        lnk.get("working_dir",    ""),
        lnk.get("name",           ""),
        lnk.get("icon_location",  ""),
        lnk.get("relative_path",  ""),
    ]
    combined = " ".join(f for f in text_fields if f)

    indicators    = _detect_suspicious(lnk, file_size)
    lolbas        = _find_lolbas(text_fields)
    categories    = _scan_categories(lnk)
    urls          = _extract_urls(combined)
    ips           = _extract_ips(combined)
    matched_rules = _scan_yara(TARGET_FILE)

    _print_lnk_fields(lnk)
    _print_summary(indicators, lolbas, categories, urls, ips, matched_rules)
    _print_indicators(indicators)
    _print_lolbas(lolbas)
    _print_category_details(categories)

    if EMIT_REPORT:
        md5, sha1, sha256 = _calc_hashes(TARGET_FILE)
        interesting = []
        for matches in categories.values():
            for _, value in matches:
                if value not in interesting:
                    interesting.append(value)
        report = {
            "target_type":           "lnk_file",
            "analysis_mode":         "static_analysis",
            "filename":              TARGET_FILE,
            "file_size":             file_size,
            "hash_md5":              md5,
            "hash_sha1":             sha1,
            "hash_sha256":           sha256,
            "target_path":           lnk.get("target_path",     ""),
            "local_base_path":       lnk.get("local_base_path", ""),
            "network_share":         lnk.get("network_share",   ""),
            "arguments":             lnk.get("arguments",       ""),
            "working_directory":     lnk.get("working_dir",     ""),
            "name":                  lnk.get("name",            ""),
            "relative_path":         lnk.get("relative_path",   ""),
            "icon_location":         lnk.get("icon_location",   ""),
            "show_command":          lnk.get("show_command",    ""),
            "hotkey":                lnk.get("hotkey",          ""),
            "run_as_user":           lnk.get("run_as_user",     False),
            "timestamps": {
                "creation": lnk.get("creation_time", ""),
                "access":   lnk.get("access_time",   ""),
                "write":    lnk.get("write_time",     ""),
            },
            "target_file_size_bytes":    lnk.get("target_file_size", 0),
            "suspicious_indicators":     indicators,
            "lolbas_detected":           lolbas,
            "categories":                {
                k: [{"field": lbl, "value": val} for lbl, val in v]
                for k, v in categories.items() if v
            },
            "interesting_string_patterns": _unique(interesting, limit=220),
            "extracted_urls":            urls,
            "extracted_ips":             ips,
            "matched_rules":             matched_rules,
        }
        save_report("lnk", report)


if __name__ == "__main__":
    analyze()
