#!/usr/bin/python3

import os
import re
import sys
import json
import hashlib

try:
    from rich import print
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Scores
scoreDict = {
    "Hydra": 0,
    "FluBot": 0,
    "MoqHao": 0,
    "SharkBot": 0,
    "SpyNote": 0,
    "Sova": 0
}

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
# Using helper library
if os.path.exists("/usr/lib/python3/dist-packages/sc0pe_helper.py"):
    from sc0pe_helper import Sc0peHelper
    sc0pehelper = Sc0peHelper(sc0pe_path)
else:
    print(f"{errorS} [bold green]sc0pe_helper[white] library not installed. You need to execute [bold green]setup.sh[white] script!")
    sys.exit(1)

# Gathering data
fam_data = json.load(open(f"{sc0pe_path}/Systems/Android/family.json"))

# Target APK file
targetApk = sys.argv[1]

# Parsing target apk file
checktarg = pyaxmlparser.APK(targetApk)
content = checktarg.get_activities()
content += checktarg.get_services()
content += checktarg.get_receivers()

# Function for computing hashes
def GetSHA256(file_name):
    hash_256 = hashlib.sha256()
    with open(file_name, "rb") as ff:
        for chunk in iter(lambda: ff.read(4096), b""):
            hash_256.update(chunk)
    ff.close()
    return str(hash_256.hexdigest())

# Function for detecting: Hydra MoqHao SharkBot families
def HyMoqShark():
    # Family: Hydra, MoqHao, SharkBot
    for key in fam_data:
        try:
            for act_key in fam_data[key]:
                for dat in fam_data[key][act_key]:
                    actreg = re.findall(dat, str(content))
                    if actreg != []:
                        scoreDict[key] += 1
        except:
            continue

# Helper function for parsing: FluBot family
def ParseFlu(arrayz):
    counter = 0
    for el in arrayz:
        if el[0:2] == ".p" and len(el) == 10:
            counter += 1
    return counter

# Function for detecting: FluBot family
def FluBot():
    # Checking activity name patterns
    act = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_activities()))
    if ParseFlu(act) != 0 and ParseFlu(act) == len(checktarg.get_activities()):
        scoreDict["FluBot"] += 1

    # Checking service name patterns
    ser = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_services()))
    if ParseFlu(ser) != 0 and ParseFlu(ser) == len(checktarg.get_services()):
        scoreDict["FluBot"] += 1

    # Checking receiver name patterns
    rec = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_receivers()))
    if ParseFlu(rec) != 0 and ParseFlu(rec) == len(checktarg.get_receivers()):
        scoreDict["FluBot"] += 1

# Function for detecting: SpyNote family
def SpyNote():
    # Checking for file names
    source_files = sc0pehelper.recursive_dir_scan(target_directory="TargetAPK/sources/")
    occur1 = re.findall(r"SensorRestarterBroadcastReceiver", str(source_files))
    occur2 = re.findall(r"_ask_remove_", str(source_files))
    occur3 = re.findall(r"SimpleIME", str(source_files))
    if occur1 != [] or occur2 != [] or occur3 != []:
        scoreDict["SpyNote"] += 1

    # Search for patterns
    patternz = {
        "/Config/sys/apps/tch": 0, 
        "App Helper": 0, 
        "SCDir": 0, 
        "/Config/sys/apps/rc": 0,
        "/exit/chat/": 0,
        "root@": 0
    }
    for ff in source_files:
        file_buffer = open(ff, "r").read()
        for pat in patternz:
            occur = re.findall(pat, file_buffer)
            if occur != []:
                patternz[pat] += 1

    # Check for occurences
    occount = 0
    for key in patternz:
        if patternz[key] != 0:
            occount += 1

    if occount != 0:
        scoreDict["SpyNote"] += 1

# Fnction for detecting: Sova family
def Sova():
    # Analyzing resources
    resource_data = {
        "nointernet.html": "9d647b7f81404d0744ebd1ead58bf8a6f3b6beb0a98583a907a00b38ff9843c2",
        "unique.html": "1b5f986ddee68791fffe37baa4c551feae8016a1b3964ede7e49ec697c3ce26b"
    }

    # Checking for existence
    ex_count = 0
    expected = ["TargetAPK/resources/assets/nointernet.html", "TargetAPK/resources/assets/unique.html"]
    for fl in expected:
        if os.path.exists(fl):
            target_hash = GetSHA256(fl)
            if target_hash == resource_data[fl.split("/")[3]]:
                ex_count += 1
    if ex_count == 2:
        scoreDict["Sova"] += 1

    # After that we also must checking the activities, services, receivers etc.
    name_count = 0
    for act_key in fam_data["Sova"]:
        try:
            for value in fam_data["Sova"][act_key]:
                chk = re.findall(value, str(content))
                if chk != []:
                    name_count += 1
        except:
            continue
    if name_count == 11:
        scoreDict["Sova"] += 1


# Analyzer for malware family detection
def CheckFamily():
    # Detect: Hydra, MoqHao, SharkBot
    HyMoqShark()

    # Detect: FluBot
    FluBot()

    # Detect: SpyNote
    SpyNote()

    # Detect: Sova
    Sova()

    # Checking statistics
    sort_score = sorted(scoreDict.items(), key=lambda ff: ff[1], reverse=True)
    if sort_score[0][1] != 0:
        print(f"[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
    else:
        print(f"{errorS} Couldn\'t detect malware family.")

# Execute
if os.path.exists("TargetAPK/"):
    CheckFamily()