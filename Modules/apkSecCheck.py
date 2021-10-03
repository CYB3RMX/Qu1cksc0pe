#!/usr/bin/python3

import sys
import xml.etree.ElementTree as etr

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

def ManifestAnalysis():
    # Obtaining manifest file
    manifest_path = "TargetAPK/resources/AndroidManifest.xml"
    manifest_tree = etr.parse(manifest_path)
    manifest_root = manifest_tree.getroot()
    app_data = manifest_root.findall("application")

    # General information
    sec_dict = {
        "{http://schemas.android.com/apk/res/android}debuggable": "No entry found.",
        "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "No entry found.",
        "{http://schemas.android.com/apk/res/android}allowBackup": "No entry found."
    }

    # Check for values
    print(f"\n{infoS} Checking basic security options...")
    for sec in sec_dict:
        if sec in app_data[0].keys():
            if app_data[0].attrib[sec] == "false":
                sec_dict[sec] = f"{green}secure{white}"
            else:
                sec_dict[sec] = f"{red}insecure{white}"

    # Tables!!
    reportTable = PrettyTable()
    reportTable.field_names = [f"{yellow}Debuggable{white}", f"{yellow}AllowBackup{white}", f"{yellow}ClearTextTraffic{white}"]
    reportTable.add_row(
        [
            sec_dict['{http://schemas.android.com/apk/res/android}debuggable'],
            sec_dict['{http://schemas.android.com/apk/res/android}allowBackup'],
            sec_dict['{http://schemas.android.com/apk/res/android}usesCleartextTraffic']
        ]
    )
    print(reportTable)

    # Extracting wanted hardwares
    hard_indicator = 0
    print(f"\n{infoS} Extracting hardware permissions from {green}AndroidManifest.xml{white}...")
    for feat in manifest_root.findall("uses-feature"):
        try:
            if "hardware" in feat.attrib["{http://schemas.android.com/apk/res/android}name"]:
                print(f"{magenta}>>>{white} {feat.attrib['{http://schemas.android.com/apk/res/android}name'].replace('android.hardware.', '')}")
                hard_indicator += 1
        except:
            continue
    if hard_indicator == 0:
        print(f"{errorS} There is no entry about hardware permissions.")

    # Exported activities
    exp_indicator = 0
    print(f"\n{infoS} Searching for exported activities...")
    for tags in range(0, len(app_data[0])):
        if app_data[0][tags].tag == "activity":
            if "{http://schemas.android.com/apk/res/android}exported" in app_data[0][tags].keys():
                if app_data[0][tags].get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    print(f"{magenta}>>>{white} {app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name')}")
                    exp_indicator += 1
    if exp_indicator == 0:
        print(f"{errorS} There is no entry about exported activites.")

# Execution
ManifestAnalysis()