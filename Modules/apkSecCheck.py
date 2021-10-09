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
    try:
        manifest_path = "TargetAPK/resources/AndroidManifest.xml"
        manifest_tree = etr.parse(manifest_path)
        manifest_root = manifest_tree.getroot()
    except FileNotFoundError:
        print(f"{errorS} An error occured while parsing {green}AndroidManifest.xml{white}. Did your APK file decompiled correctly?")
        sys.exit(1)

    # Gathering informations
    app_data = manifest_root.findall("application")
    perm_data = manifest_root.findall("permission")

    # General information
    sec_dict = {
        "{http://schemas.android.com/apk/res/android}debuggable": "No entry found.",
        "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "No entry found.",
        "{http://schemas.android.com/apk/res/android}allowBackup": "No entry found.",
        "{http://schemas.android.com/apk/res/android}networkSecurityConfig": f"{red}Not found{white}"
    }

    # Check for values
    print(f"\n{infoS} Checking basic security options...")
    for sec in sec_dict:
        if sec in app_data[0].keys():
            if sec == "{http://schemas.android.com/apk/res/android}networkSecurityConfig":
                sec_dict[sec] = f"{green}Found{white}"
            else:
                if app_data[0].attrib[sec] == "false":
                    sec_dict[sec] = f"{green}Secure{white}"
                else:
                    sec_dict[sec] = f"{red}Insecure{white}"

    # Tables!!
    reportTable = PrettyTable()
    reportTable.field_names = [f"{yellow}Debuggable{white}", f"{yellow}AllowBackup{white}", f"{yellow}ClearTextTraffic{white}", f"{yellow}NetworkSecurityConfig{white}"]
    reportTable.add_row(
        [
            sec_dict['{http://schemas.android.com/apk/res/android}debuggable'],
            sec_dict['{http://schemas.android.com/apk/res/android}allowBackup'],
            sec_dict['{http://schemas.android.com/apk/res/android}usesCleartextTraffic'],
            sec_dict['{http://schemas.android.com/apk/res/android}networkSecurityConfig']
        ]
    )
    print(reportTable)

    # Check for permission flags
    permLevel = "No entry found."
    print(f"\n{infoS} Checking application permission flags...")
    try:
        if "{http://schemas.android.com/apk/res/android}protectionLevel" in perm_data[0].keys():
            if perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signature" or perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signatureOrSystem":
                permLevel = f"{green}{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}{white}"
            else:
                permLevel = f"{red}{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}{white}"
        permTable = PrettyTable()
        permTable.field_names = [f"{yellow}Permission{white}", f"{yellow}Flag{white}"]
        permTable.add_row(
            [
                perm_data[0].attrib["{http://schemas.android.com/apk/res/android}name"],
                permLevel
            ]
        )
        print(permTable)
    except IndexError:
        print(f"{errorS} There is no entry about permission flags.")

    # Exported activities
    exp_indicator = 0
    print(f"\n{infoS} Searching for exported activities...")

    # Pretty output
    actTable = PrettyTable()
    actTable.field_names = [f"{yellow}Activity{white}", f"{yellow}Exported{white}"]
    for tags in range(0, len(app_data[0])):
        if app_data[0][tags].tag == "activity":
            if "{http://schemas.android.com/apk/res/android}exported" in app_data[0][tags].keys():
                if app_data[0][tags].get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    actTable.add_row(
                        [
                            app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name'),
                            f"{red}{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}{white}"
                        ]
                    )
                    exp_indicator += 1
                else:
                    actTable.add_row(
                        [
                            app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name'),
                            f"{green}{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}{white}"
                        ]
                    )
                    exp_indicator += 1
    if exp_indicator == 0:
        print(f"{errorS} There is no entry about exported activites.")
    else:
        print(actTable)

    # Exported providers
    pro_indicator = 0
    print(f"\n{infoS} Searching for exported providers...")

    # Pretty output
    proTable = PrettyTable()
    proTable.field_names = [f"{yellow}Provider{white}", f"{yellow}Exported{white}"]
    for tags in range(0, len(app_data[0])):
        if app_data[0][tags].tag == "provider":
            if "{http://schemas.android.com/apk/res/android}exported" in app_data[0][tags].keys():
                if app_data[0][tags].get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    proTable.add_row(
                        [
                            app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name'),
                            f"{red}{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}{white}"
                        ]
                    )
                    pro_indicator += 1
                else:
                    proTable.add_row(
                        [
                            app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name'),
                            f"{green}{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}{white}"
                        ]
                    )
                    pro_indicator += 1
    if pro_indicator == 0:
        print(f"{errorS} There is no entry about exported providers.")
    else:
        print(proTable)

# Execution
ManifestAnalysis()