#!/usr/bin/python3

import sys
import xml.etree.ElementTree as etr

from utils import err_exit

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
if sys.platform == "win32":
    path_seperator = "\\"
else:
    path_seperator = "/"

def ManifestAnalysis():
    # Obtaining manifest file
    try:
        manifest_path = f"TargetAPK{path_seperator}resources{path_seperator}AndroidManifest.xml"
        manifest_tree = etr.parse(manifest_path)
        manifest_root = manifest_tree.getroot()
    except FileNotFoundError:
        err_exit(f"{errorS} An error occured while parsing [bold green]AndroidManifest.xml[white]. Did your APK file decompiled correctly?")
    except:
        err_exit(f"{errorS} It looks like the target [bold green]AndroidManifest.xml[white] is corrupted!!")

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
                sec_dict[sec] = f"[bold green]Found"
            else:
                if app_data[0].attrib[sec] == "false":
                    sec_dict[sec] = f"[bold green]Secure"
                else:
                    sec_dict[sec] = f"[bold red]Insecure"

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
    print(reportTable)

    # Check for permission flags
    permLevel = "No entry found."
    print(f"\n{infoS} Checking application permission flags...")
    try:
        if "{http://schemas.android.com/apk/res/android}protectionLevel" in perm_data[0].keys():
            if perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signature" or perm_data[0].attrib["{http://schemas.android.com/apk/res/android}protectionLevel"] == "signatureOrSystem":
                permLevel = f"[bold green]{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}"
            else:
                permLevel = f"[bold red]{perm_data[0].attrib['{http://schemas.android.com/apk/res/android}protectionLevel']}"

        permTable = Table()
        permTable.add_column("[bold yellow]Permission", justify="center")
        permTable.add_column("[bold yellow]Flag", justify="center")
        permTable.add_row(
            str(perm_data[0].attrib["{http://schemas.android.com/apk/res/android}name"]),
            str(permLevel)
        )
        print(permTable)
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
        print(actTable)

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
        print(proTable)

# Execution
ManifestAnalysis()