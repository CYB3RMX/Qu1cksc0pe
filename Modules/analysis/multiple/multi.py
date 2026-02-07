import sys
import re
import hashlib
import subprocess
import yara
import os
from rich import print
from rich.table import Table

# Compatibility
path_seperator = "/"
strings_param = "-a"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Get whitelist domains for "chk_wlist" method
whitelist_domains = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r").read().split("\n")

# WHITELIST DOMAIN SCANNER
def chk_wlist(target_string):
    for pat in whitelist_domains:
        matched = re.findall(pat, target_string)
        if matched:
            return False # Whitelist found
    return True

# HASH CALCULATOR
def calc_hashes(filename, report_object):
    hashmd5 = hashlib.md5()
    hashsha1 = hashlib.sha1()
    hashsha256 = hashlib.sha256()
    try:
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashmd5.update(chunk)
        ff.close()
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashsha1.update(chunk)
        ff.close()
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashsha256.update(chunk)
        ff.close()
    except: # TODO: more specific; also: handle/raise!
        pass

    # OUTPUT
    print(f"[bold red]>>>>[white] MD5: [bold green]{hashmd5.hexdigest()}")
    print(f"[bold red]>>>>[white] SHA1: [bold green]{hashsha1.hexdigest()}")
    print(f"[bold red]>>>>[white] SHA256: [bold green]{hashsha256.hexdigest()}")
    report_object["hash_md5"] = hashmd5.hexdigest()
    report_object["hash_sha1"] = hashsha1.hexdigest()
    report_object["hash_sha256"] = hashsha256.hexdigest()

# PERFORM STRINGS
def perform_strings(filename):
    subprocess.run(f"strings {strings_param} \"{filename}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    if sys.platform != "win32":
        subprocess.run(f"strings {strings_param} -e l {filename} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    allstrs = open("temp.txt", "r").read().split("\n")
    return allstrs

# YARA RULE CACHE (rule_dir -> list[(rule_file, yara.Rules)])
_YARA_RULE_CACHE = {}
_YARA_RULE_CACHE_ERR = {}

def _resolve_rule_dir(rulepath):
    cleaned = str(rulepath or "").strip().strip('"').strip("'")
    cleaned = os.path.expandvars(os.path.expanduser(cleaned))
    if cleaned and os.path.isdir(cleaned):
        return os.path.abspath(cleaned)
    # Backwards-compat: treat as sc0pe_path-relative even if it starts with "/".
    rel = cleaned.lstrip("/\\")
    candidate = os.path.join(sc0pe_path, rel)
    if os.path.isdir(candidate):
        return os.path.abspath(candidate)
    return ""

def _load_yara_rules(rule_dir):
    if rule_dir in _YARA_RULE_CACHE:
        return _YARA_RULE_CACHE[rule_dir]

    compiled = []
    err = ""
    try:
        files = sorted(os.listdir(rule_dir))
    except Exception as e:
        err = f"rule_dir_unreadable: {e}"
        _YARA_RULE_CACHE[rule_dir] = []
        _YARA_RULE_CACHE_ERR[rule_dir] = err
        return []

    failed = 0
    for rf in files:
        if not rf.lower().endswith((".yara", ".yar")):
            continue
        full = os.path.join(rule_dir, rf)
        try:
            compiled.append((rf, yara.compile(filepath=full)))
        except Exception:
            failed += 1
            continue

    if not compiled:
        err = "no_rules_compiled"
        if failed:
            err = f"no_rules_compiled_failed={failed}"

    _YARA_RULE_CACHE[rule_dir] = compiled
    _YARA_RULE_CACHE_ERR[rule_dir] = err
    return compiled

# YARA SCANNER
def yara_rule_scanner(
    rulepath,
    filename,
    report_object,
    quiet_nomatch=False,
    header_label="",
    quiet_errors=False,
    detailed_key=None,
    print_matches=True,
    print_nomatch=True,
):
    """
    Shared YARA scanner with rule caching.

    Backwards-compatible args:
      yara_rule_scanner(rulepath, filename, report_object)

    Optional args:
      quiet_nomatch: suppress per-file "no match" message
      header_label: printed before matches (useful to label targets)
      quiet_errors: suppress rule-load errors
      detailed_key: report key for detailed per-target matches (default: None)

    Returns True if any rule matched; False otherwise.
    """
    yara_match_indicator = 0
    report_object.setdefault("matched_rules", [])
    if detailed_key:
        report_object.setdefault(detailed_key, [])

    rule_dir = _resolve_rule_dir(rulepath)
    if not rule_dir:
        if not quiet_errors:
            print(f"[bold white on red]YARA rule directory could not be resolved for: {rulepath}")
        return False

    compiled_rules = _load_yara_rules(rule_dir)
    if not compiled_rules:
        if not quiet_errors:
            err = _YARA_RULE_CACHE_ERR.get(rule_dir, "")
            print(f"[bold white on red]No YARA rules could be loaded from: {rule_dir} ({err})")
        return False

    # This array for holding and parsing easily matched rules
    yara_matches = []
    for _, rules in compiled_rules:
        try:
            tempmatch = rules.match(filename)
        except Exception:
            continue
        if tempmatch:
            for matched in tempmatch:
                if matched.strings:
                    yara_matches.append(matched)

    # Printing area
    if yara_matches != []:
        yara_match_indicator += 1
        for rul in yara_matches:
            report_object["matched_rules"].append({str(rul): []})
            detailed = {
                "target": filename,
                "rule": str(rul),
                "strings": []
            }
            if print_matches:
                yaraTable = Table()
                if header_label:
                    print(f"[bold magenta]>>>>[white] {header_label}[white]")
                    header_label = ""  # Print once.
                print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
                yaraTable.add_column("Offset", style="bold green", justify="center")
                yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
            for matched_pattern in rul.strings:
                if print_matches:
                    yaraTable.add_row(f"{hex(matched_pattern.instances[0].offset)}", f"{str(matched_pattern.instances[0].matched_data)}")
                try:
                    s = {"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": matched_pattern.instances[0].matched_data.decode("ascii")}
                except:
                    s = {"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": str(matched_pattern.instances[0].matched_data)}
                report_object["matched_rules"][-1][str(rul)].append(s)
                detailed["strings"].append(s)
            if detailed_key:
                report_object[detailed_key].append(detailed)
            if print_matches:
                print(yaraTable)
                print(" ")

    if yara_match_indicator == 0:
        if (not quiet_nomatch) and print_nomatch:
            print(f"[bold white on red]There is no rules matched for {filename}")
        return False
    return True
