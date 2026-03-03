#!/usr/bin/python3

import os
import re
import sys
import json
import hashlib

# FIX: Import recursive_dir_scan from helpers instead of duplicating it.
from utils.helpers import err_exit, recursive_dir_scan

try:
    from rich import print
except ImportError:
    err_exit("Error: >rich< module not found.")

try:
    import pyaxmlparser
except ImportError:
    err_exit("Error: >pyaxmlparser< module not found.")

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
with open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r") as _ph:
    sc0pe_path = _ph.read().strip()

targetApk = sys.argv[1]

# Gathering data
with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}family.json") as _fam:
    fam_data = json.load(_fam)

# Minimum number of SourcePattern hits required to award a score point,
# reducing false positives from patterns that may appear in benign code.
_SOURCE_SCAN_MIN_HITS = 2

class AndroidFamilyDetect:
    def __init__(self):
        self.scoreDict = {
            "Hydra": 0,
            "FluBot": 0,
            "MoqHao": 0,
            "SharkBot": 0,
            "SpyNote/SpyMax": 0,
            "Sova": 0,
            "Cerberus": 0,
            "Anubis": 0,
            "EventBot": 0,
        }
        try:
            self.checktarg = pyaxmlparser.APK(targetApk)
            self.content = self.checktarg.get_activities()
            self.content += self.checktarg.get_services()
            self.content += self.checktarg.get_receivers()
        except Exception:
            self.checktarg = None
            self.content = None

    # Function for computing hashes
    def GetSHA256(self, file_name):
        hash_256 = hashlib.sha256()
        with open(file_name, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hash_256.update(chunk)
        return str(hash_256.hexdigest())

    # Function for detecting: Hydra MoqHao SharkBot families
    def HyMoqShark(self):
        for key in fam_data:
            try:
                for act_key in fam_data[key]:
                    if act_key == "SourcePatterns":
                        continue
                    for dat in fam_data[key][act_key]:
                        actreg = re.findall(dat, str(self.content))
                        if actreg:
                            self.scoreDict[key] += 1
            except Exception:
                continue

    # Helper function for parsing: FluBot family
    def ParseFlu(self, arrayz):
        counter = 0
        for el in arrayz:
            if el[0:2] == ".p" and len(el) == 10:
                counter += 1
        return counter

    # Function for detecting: FluBot family
    def FluBot(self):
        # Cache API results to avoid calling each getter twice
        activities = self.checktarg.get_activities()
        services = self.checktarg.get_services()
        receivers = self.checktarg.get_receivers()

        act = re.findall(r".p[a-z0-9]{0,9}", str(activities))
        if self.ParseFlu(act) != 0 and self.ParseFlu(act) == len(activities):
            self.scoreDict["FluBot"] += 1

        ser = re.findall(r".p[a-z0-9]{0,9}", str(services))
        if self.ParseFlu(ser) != 0 and self.ParseFlu(ser) == len(services):
            self.scoreDict["FluBot"] += 1

        rec = re.findall(r".p[a-z0-9]{0,9}", str(receivers))
        if self.ParseFlu(rec) != 0 and self.ParseFlu(rec) == len(receivers):
            self.scoreDict["FluBot"] += 1

    # Function for detecting: SpyNote family
    def SpyNote(self):
        source_files = recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}sources{path_seperator}")
        source_files += recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}resources{path_seperator}")
        occur1 = re.findall(r"SensorRestarterBroadcastReceiver", str(source_files))
        occur2 = re.findall(r"_ask_remove_", str(source_files))
        occur3 = re.findall(r"SimpleIME", str(source_files))
        if occur1 or occur2 or occur3:
            self.scoreDict["SpyNote/SpyMax"] += 1

        # Search for patterns
        patternz = {
            "/Config/sys/apps/tch": 0,
            "App Helper": 0,
            "SCDir": 0,
            "/Config/sys/apps/rc": 0,
            "/exit/chat/": 0,
            "root@": 0,
            "spymax.stub": 0
        }
        for ff in source_files:
            try:
                with open(ff, "r") as fh:
                    file_buffer = fh.read()
                for pat in patternz:
                    if re.findall(pat, file_buffer):
                        patternz[pat] += 1
            except Exception:
                continue

        # Check for occurences
        occount = sum(1 for v in patternz.values() if v != 0)
        if occount != 0:
            self.scoreDict["SpyNote/SpyMax"] += 1

    # Function for detecting families via decompiled source code patterns.
    # Reads every file under TargetAPK/sources/ once and checks all families'
    # SourcePatterns in a single pass to keep I/O overhead low.
    def SourceScan(self):
        source_files = recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}sources{path_seperator}")
        if not source_files:
            return

        # Collect families that declare SourcePatterns in family.json
        family_src_patterns = {
            fam: fam_data[fam]["SourcePatterns"]
            for fam in fam_data
            if "SourcePatterns" in fam_data[fam]
        }
        if not family_src_patterns:
            return

        hit_counts = {fam: 0 for fam in family_src_patterns}

        for ff in source_files:
            try:
                with open(ff, "r") as fh:
                    buf = fh.read()
                for fam, patterns in family_src_patterns.items():
                    for pat in patterns:
                        if re.search(re.escape(pat), buf):
                            hit_counts[fam] += 1
            except Exception:
                continue

        # Award points only when enough distinct patterns matched to be confident.
        for fam, count in hit_counts.items():
            if count >= _SOURCE_SCAN_MIN_HITS and fam in self.scoreDict:
                self.scoreDict[fam] += count

    # Function for detecting: Sova family
    def Sova(self):
        # Analyzing resources
        resource_data = {
            "nointernet.html": "9d647b7f81404d0744ebd1ead58bf8a6f3b6beb0a98583a907a00b38ff9843c2",
            "unique.html": "1b5f986ddee68791fffe37baa4c551feae8016a1b3964ede7e49ec697c3ce26b"
        }

        # Checking for existence
        ex_count = 0
        expected = [f"TargetAPK{path_seperator}resources{path_seperator}assets{path_seperator}nointernet.html", f"TargetAPK{path_seperator}resources{path_seperator}assets{path_seperator}unique.html"]
        for fl in expected:
            if os.path.exists(fl):
                target_hash = self.GetSHA256(fl)
                if target_hash == resource_data[os.path.basename(fl)]:
                    ex_count += 1
        if ex_count == 2:
            self.scoreDict["Sova"] += 1

        # After that we also must checking the activities, services, receivers etc.
        name_count = 0
        for act_key in fam_data["Sova"]:
            if act_key == "SourcePatterns":
                continue
            try:
                for value in fam_data["Sova"][act_key]:
                    chk = re.findall(value, str(self.content))
                    if chk:
                        name_count += 1
            except Exception:
                continue
        if name_count == 11:
            self.scoreDict["Sova"] += 1

    # Analyzer for malware family detection
    def CheckFamily(self):
        # Detect: SpyNote (file-system based, runs regardless of APK parse result)
        self.SpyNote()

        # Detect families via decompiled source code patterns (also file-system based)
        self.SourceScan()

        if self.content and self.checktarg:
            # Detect: Hydra, MoqHao, SharkBot
            self.HyMoqShark()

            # Detect: FluBot
            self.FluBot()

            # Detect: Sova
            self.Sova()

        # Checking statistics
        sort_score = sorted(self.scoreDict.items(), key=lambda ff: ff[1], reverse=True)
        if sort_score[0][1] != 0:
            print(f"\n[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
            # Show top candidates if multiple families scored
            runners_up = [(f, s) for f, s in sort_score[1:] if s > 0]
            if runners_up:
                print(f"{infoS} Other scored families: " + ", ".join(f"[bold yellow]{f}[white]({s})" for f, s in runners_up))
        else:
            print(f"{errorS} Couldn\'t detect malware family.")

# Execute
if os.path.exists("TargetAPK"):
    afd = AndroidFamilyDetect()
    afd.CheckFamily()
