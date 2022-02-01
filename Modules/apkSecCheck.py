#!/usr/bin/python3

import sys
import xml.etree.ElementTree as etr

try:
    from rich.table import Table
    from rich.console import Console
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Rich console
r_console = Console()

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX

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
        "{http://schemas.android.com/apk/res/android}networkSecurityConfig": "Not found"
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
    reportTable = Table()
    reportTable.add_column("[bold yellow]Debuggable", justify="center")
    reportTable.add_column("[bold yellow]AllowBackup", justify="center")
    reportTable.add_column("[bold yellow]ClearTextTraffic", justify="center")
    reportTable.add_column("[bold yellow]NetworkSecurityConfig", justify="center")
    reportTable.add_row(
        str(sec_dict['{http://schemas.android.com/apk/res/android}debuggable']),
        str(sec_dict['{http://schemas.android.com/apk/res/android}allowBackup']),
        str(sec_dict['{http://schemas.android.com/apk/res/android}usesCleartextTraffic']),
        str(sec_dict['{http://schemas.android.com/apk/res/android}networkSecurityConfig'])
    )
    r_console.print(reportTable)

    # Check for permission flags
    permLevel = "No entry found."
    print(f"\n{infoS} Checking application permission flags...")
    try:
        if "{http://schemas.android.com/apk/res/android}protectionLevel" in perm_data[0].keys():
            if perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signature" or perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signatureOrSystem":
                permLevel = f"{green}{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}{white}"
            else:
                permLevel = f"{red}{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}{white}"

        permTable = Table()
        permTable.add_column("[bold yellow]Permission", justify="center")
        permTable.add_column("[bold yellow]Flag", justify="center")
        permTable.add_row(
            str(perm_data[0].attrib["{http://schemas.android.com/apk/res/android}name"]),
            str(permLevel)
        )
        r_console.print(permTable)
    except IndexError:
        print(f"{errorS} There is no entry about permission flags.")

    # Exported activities
    exp_indicator = 0
    print(f"\n{infoS} Searching for exported activities...")

    # Pretty output
    actTable = Table()
    actTable.add_column("[bold yellow]Activity", justify="center")
    actTable.add_column("[bold yellow]Exported", justify="center")
    for tags in range(0, len(app_data[0])):
        if app_data[0][tags].tag == "activity":
            if "{http://schemas.android.com/apk/res/android}exported" in app_data[0][tags].keys():
                if app_data[0][tags].get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    actTable.add_row(
                        str(app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name')),
                        f"[bold red]{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}"
                    )
                    exp_indicator += 1
                else:
                    actTable.add_row(
                        str(app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name')),
                        f"[bold green]{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}"
                    )
                    exp_indicator += 1
    if exp_indicator == 0:
        print(f"{errorS} There is no entry about exported activites.")
    else:
        r_console.print(actTable)

    # Exported providers
    pro_indicator = 0
    print(f"\n{infoS} Searching for exported providers...")

    # Pretty output
    proTable = Table()
    proTable.add_column("[bold yellow]Provider", justify="center")
    proTable.add_column("[bold yellow]Exported", justify="center")
    for tags in range(0, len(app_data[0])):
        if app_data[0][tags].tag == "provider":
            if "{http://schemas.android.com/apk/res/android}exported" in app_data[0][tags].keys():
                if app_data[0][tags].get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    proTable.add_row(
                        str(app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name')),
                        f"[bold red]{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}"
                    )
                    pro_indicator += 1
                else:
                    proTable.add_row(
                        str(app_data[0][tags].get('{http://schemas.android.com/apk/res/android}name')),
                        f"[bold green]{app_data[0][tags].get('{http://schemas.android.com/apk/res/android}exported')}"
                    )
                    pro_indicator += 1
    if pro_indicator == 0:
        print(f"{errorS} There is no entry about exported providers.")
    else:
        r_console.print(proTable)

# Execution
ManifestAnalysis()