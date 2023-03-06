#!/usr/bin/python3

import os
import re
import sys
import json

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
    "SpyNote": 0
}

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Gathering data
fam_data = json.load(open(f"{sc0pe_path}/Systems/Android/family.json"))

# Target APK file
targetApk = sys.argv[1]

# Parsing target apk file
checktarg = pyaxmlparser.APK(targetApk)
content = checktarg.get_activities()
content += checktarg.get_services()
content += checktarg.get_receivers()

# Helper function for code analyzer
def RecursiveDirScan(targetDir):
    fnames = []
    for root, d_names, f_names in os.walk(targetDir):
        for ff in f_names:
            fnames.append(os.path.join(root, ff))
    return fnames

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
    source_files = RecursiveDirScan("TargetAPK/sources/")
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


# Analyzer for malware family detection
def CheckFamily():
    # Detect: Hydra, MoqHao, SharkBot
    HyMoqShark()

    # Detect: FluBot
    FluBot()

    # Detect: SpyNote
    if os.path.exists("TargetAPK/"):
        SpyNote()

    # Checking statistics
    sort_score = sorted(scoreDict.items(), key=lambda ff: ff[1], reverse=True)
    if sort_score[0][1] != 0:
        print(f"[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
    else:
        print(f"{errorS} Couldn\'t detect malware family.")

# Execute
CheckFamily()