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

# YARA SCANNER
def yara_rule_scanner(rulepath, filename, report_object):
    yara_match_indicator = 0
    finalpath = f"{sc0pe_path}{path_seperator}{rulepath}"
    allRules = os.listdir(finalpath)

    # This array for holding and parsing easily matched rules
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(f"{finalpath}{rul}")
            tempmatch = rules.match(filename)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        if matched not in yara_matches:
                            yara_matches.append(matched)
        except:
            continue

    # Printing area
    if yara_matches != []:
        yara_match_indicator += 1
        for rul in yara_matches:
            yaraTable = Table()
            print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
            yaraTable.add_column("Offset", style="bold green", justify="center")
            yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
            report_object["matched_rules"].append({str(rul): []})
            for matched_pattern in rul.strings:
                yaraTable.add_row(f"{hex(matched_pattern.instances[0].offset)}", f"{str(matched_pattern.instances[0].matched_data)}")
                try:
                    report_object["matched_rules"][-1][str(rul)].append({"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": matched_pattern.instances[0].matched_data.decode("ascii")})
                except:
                    report_object["matched_rules"][-1][str(rul)].append({"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": str(matched_pattern.instances[0].matched_data)})
            print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        print(f"[bold white on red]There is no rules matched for {filename}")