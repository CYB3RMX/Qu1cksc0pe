#!/usr/bin/python3

import os
import re
import sys
import requests
import getpass
import importlib
import configparser
import importlib_metadata

try:
    from rich import print
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# User home detection
homeD = "/home"
if sys.platform == "darwin":
    homeD = "/Users"

# Commit
latest_commit = "01/02/2022"

# Checking for latest commits
print(f"{infoS} Checking for latest commit...")
user_agent = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"}
req = requests.get("https://raw.githubusercontent.com/CYB3RMX/Qu1cksc0pe/master/README.md", headers=user_agent)
if req.ok:
    match = re.findall(latest_commit, str(req.content))
    if match != []:
        print(f"[bold red]>>>[white] State: [bold green]Up to date[white]")
    else:
        print(f"[bold red]>>>[white] State: [bold red]Out of date[white]")
else:
    print(f"{errorS} Couldn\'t get latest commit data")

# Environment variables
sc0pe_path = open(".path_handler", "r").read()
username = getpass.getuser()
print(f"\n{infoS} Checking for environment...")
if username == "root":
    print(f"[bold red]>>>[white] Username: [bold red]root[white] (Not recommended!)")
else:
    print(f"[bold red]>>>[white] Username: [bold green]{username}[white]")
print(f"[bold red]>>>[white] Tool path: [bold green]{sc0pe_path}[white]\n")

# Resource checks
user_directory = f"{homeD}/{username}/sc0pe_Base"
resource = {"HashDB": "Malware Hash Database", 
            "sc0pe_VT_apikey.txt": "VirusTotal API key"}
print(f"{infoS} Checking for resources...")
for res in resource:
    if os.path.exists(f"{user_directory}/{res}"):
        print(f"[bold cyan][[bold green] FOUND[bold cyan] ][white] {resource[res]} | {res}")
    else:
        print(f"[bold cyan][[bold red] NOT FOUND[bold cyan] ][white] {resource[res]} | {res}")

# Python module checking zone
print(f"\n{infoS} Checking for python modules...")
requirements = ["puremagic", "androguard", "apkid", "tqdm",
                "oletools", "pefile", "quark", "pyaxmlparser", "yara",
                "prompt_toolkit", "frida", "exiftool", "rich"]
for mod in requirements:
    try:
        if importlib.util.find_spec(mod) is not None:
            if mod == "androguard" and importlib_metadata.version("androguard") != "3.4.0a1":
                print(f"[bold cyan][[bold red] INCOMPATIBLE VERSION[bold cyan] ][white] androguard\t|  Needed: [bold green]3.4.0a1[white]")
            elif mod == "quark":
                import quark
                if quark.__version__ != "21.8.1":
                    print(f"[bold cyan][[bold red] INCOMPATIBLE VERSION[bold cyan] ][white] quark\t|  Needed: [bold green]21.8.1[white]")
            elif mod == "prompt_toolkit" and importlib_metadata.version("prompt_toolkit") != "3.0.19":
                print(f"[bold cyan][[bold red] INCOMPATIBLE VERSION[bold cyan] ][white] prompt_toolkit\t|  Needed: [bold green]3.0.19[white]")
            else:
                print(f"[bold cyan][[bold green] FOUND[bold cyan] ][white] {mod}")
        else:
            print(f"[bold cyan][[bold red] NOT FOUND[bold cyan] ][white] {mod}")
    except:
        continue

# Binary checking zone
print(f"\n{infoS} Checking for binaries... (/usr/bin/)")
binary = ["/usr/bin/strings", "/usr/bin/readelf", "/usr/bin/jadx"]
for bb in binary:
    if os.path.exists(bb):
        print(f"[bold cyan][[bold green] FOUND[bold cyan] ][white] {bb.split('/')[3]}")
    else:
        print(f"[bold cyan][[bold red] NOT FOUND[bold cyan] ][white] {bb.split('/')[3]}")

# Configuration checking zone
print(f"\n{infoS} Checking for configurations...")
androconfs = configparser.ConfigParser()
windowsconf = configparser.ConfigParser()
androconfs.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
windowsconf.read(f"{sc0pe_path}/Systems/Windows/windows.conf")

# Android YARA rule path checks
if sc0pe_path in androconfs["Rule_PATH"]["rulepath"]:
    print(f"[bold red]>>>[white] Android YARA rule path: [bold green]{androconfs['Rule_PATH']['rulepath']}[white]")
else:
    print(f"[bold red]>>>[white] Android YARA rule path: [bold red]{androconfs['Rule_PATH']['rulepath']}[white]")

# Java decompiler path checks
if androconfs["Decompiler"]["decompiler"] == "/usr/bin/jadx":
    print(f"[bold red]>>>[white] Java decompiler path: [bold red]/usr/bin/jadx[white] (It is default. Use GitHub repository instead!)")
else:
    print(f"[bold red]>>>[white] Decompiler: [bold green]{androconfs['Decompiler']['decompiler']}[white]")

# Windows YARA rule path checks
if "/Systems" in windowsconf["Rule_PATH"]["rulepath"]:
    print(f"[bold red]>>>[white] Windows YARA rule path: [bold green]{windowsconf['Rule_PATH']['rulepath']}[white]")
else:
    print(f"[bold red]>>>[white] Windows YARA rule path: [bold red]{windowsconf['Rule_PATH']['rulepath']}[white]")
