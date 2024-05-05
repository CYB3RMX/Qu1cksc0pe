#!/usr/bin/python3

import os
import re
import sys
import json
import hashlib

from .utils import err_exit

try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

try:
    import pyaxmlparser
except:
    err_exit("Error: >pyaxmlparser< module not found.")

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Scores
scoreDict = {
    "Hydra": 0,
    "FluBot": 0,
    "MoqHao": 0,
    "SharkBot": 0,
    "SpyNote/SpyMax": 0,
    "Sova": 0
}

# Compatibility
homeD = os.path.expanduser("~")
path_seperator = "/"
setup_scr = "setup.sh"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
targetApk = sys.argv[1]

# Gathering data
fam_data = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}family.json"))

class AndroidFamilyDetect:
    def __init__(self):
        try:
            self.checktarg = pyaxmlparser.APK(targetApk)
            self.content = self.checktarg.get_activities()
            self.content += self.checktarg.get_services()
            self.content += self.checktarg.get_receivers()
        except:
            self.checktarg = None
            self.content = None

    def recursive_dir_scan(self, target_directory):
        fnames = []
        for root, d_names, f_names in os.walk(target_directory):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames

    # Function for computing hashes
    def GetSHA256(self, file_name):
        hash_256 = hashlib.sha256()
        with open(file_name, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hash_256.update(chunk)
        ff.close()
        return str(hash_256.hexdigest())

    # Function for detecting: Hydra MoqHao SharkBot families
    def HyMoqShark(self):
        # Family: Hydra, MoqHao, SharkBot
        for key in fam_data:
            try:
                for act_key in fam_data[key]:
                    for dat in fam_data[key][act_key]:
                        actreg = re.findall(dat, str(self.content))
                        if actreg != []:
                            scoreDict[key] += 1
            except:
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
        # Checking activity name patterns
        act = re.findall(r".p[a-z0-9]{0,9}", str(self.checktarg.get_activities()))
        if self.ParseFlu(act) != 0 and self.ParseFlu(act) == len(self.checktarg.get_activities()):
            scoreDict["FluBot"] += 1

        # Checking service name patterns
        ser = re.findall(r".p[a-z0-9]{0,9}", str(self.checktarg.get_services()))
        if self.ParseFlu(ser) != 0 and self.ParseFlu(ser) == len(self.checktarg.get_services()):
            scoreDict["FluBot"] += 1

        # Checking receiver name patterns
        rec = re.findall(r".p[a-z0-9]{0,9}", str(self.checktarg.get_receivers()))
        if self.ParseFlu(rec) != 0 and self.ParseFlu(rec) == len(self.checktarg.get_receivers()):
            scoreDict["FluBot"] += 1

    # Function for detecting: SpyNote family
    def SpyNote(self):
        # Checking for file names
        source_files = self.recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}sources{path_seperator}")
        source_files += self.recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}resources{path_seperator}")
        occur1 = re.findall(r"SensorRestarterBroadcastReceiver", str(source_files))
        occur2 = re.findall(r"_ask_remove_", str(source_files))
        occur3 = re.findall(r"SimpleIME", str(source_files))
        if occur1 != [] or occur2 != [] or occur3 != []:
            scoreDict["SpyNote/SpyMax"] += 1

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
                file_buffer = open(ff, "r").read()
                for pat in patternz:
                    occur = re.findall(pat, file_buffer)
                    if occur != []:
                        patternz[pat] += 1
            except:
                continue

        # Check for occurences
        occount = 0
        for key in patternz:
            if patternz[key] != 0:
                occount += 1

        if occount != 0:
            scoreDict["SpyNote/SpyMax"] += 1

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
                if target_hash == resource_data[fl.split("/")[3]]:
                    ex_count += 1
        if ex_count == 2:
            scoreDict["Sova"] += 1

        # After that we also must checking the activities, services, receivers etc.
        name_count = 0
        for act_key in fam_data["Sova"]:
            try:
                for value in fam_data["Sova"][act_key]:
                    chk = re.findall(value, str(self.content))
                    if chk != []:
                        name_count += 1
            except:
                continue
        if name_count == 11:
            scoreDict["Sova"] += 1

    # Analyzer for malware family detection
    def CheckFamily(self):
        # Detect: SpyNote
        self.SpyNote()
        if self.content and self.checktarg:
            # Detect: Hydra, MoqHao, SharkBot
            self.HyMoqShark()

            # Detect: FluBot
            self.FluBot()

            # Detect: Sova
            self.Sova()
        else:
            pass

        # Checking statistics
        sort_score = sorted(scoreDict.items(), key=lambda ff: ff[1], reverse=True)
        if sort_score[0][1] != 0:
            print(f"[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
        else:
            print(f"{errorS} Couldn\'t detect malware family.")

# Execute
if os.path.exists("TargetAPK"):
    afd = AndroidFamilyDetect()
    afd.CheckFamily()