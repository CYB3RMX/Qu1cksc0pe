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
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# User home detection
homeD = "/home"
if sys.platform == "darwin":
    homeD = "/Users"

# Commit
latest_commit = "14/01/2022"

# Checking for latest commits
print(f"{infoS} Checking for latest commit...")
user_agent = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"}
req = requests.get("https://raw.githubusercontent.com/CYB3RMX/Qu1cksc0pe/master/README.md", headers=user_agent)
if req.ok:
    match = re.findall(latest_commit, str(req.content))
    if match != []:
        print(f"{red}>>>{white} State: {green}Up to date{white}")
    else:
        print(f"{red}>>>{white} State: {red}Out of date{white}")
else:
    print(f"{errorS} Couldn\'t get latest commit data")

# Environment variables
sc0pe_path = open(".path_handler", "r").read()
username = getpass.getuser()
print(f"\n{infoS} Checking for environment...")
if username == "root":
    print(f"{red}>>>{white} Username: {red}root{white} (Not recommended!)")
else:
    print(f"{red}>>>{white} Username: {green}{username}{white}")
print(f"{red}>>>{white} Tool path: {green}{sc0pe_path}{white}\n")

# Resource checks
user_directory = f"{homeD}/{username}/sc0pe_Base"
resource = {"HashDB.json": "Malware Hash Database", 
            "sc0pe_VT_apikey.txt": "VirusTotal API key"}
print(f"{infoS} Checking for resources...")
for res in resource:
    if os.path.exists(f"{user_directory}/{res}"):
        print(f"{cyan}[{green} FOUND{cyan} ]{white} {resource[res]} | {res}")
    else:
        print(f"{cyan}[{red} NOT FOUND{cyan} ]{white} {resource[res]} | {res}")

# Python module checking zone
print(f"\n{infoS} Checking for python modules...")
requirements = ["puremagic", "androguard", "apkid", "prettytable", "tqdm",
                "oletools", "pefile", "quark", "pyaxmlparser", "yara",
                "prompt_toolkit", "frida", "exiftool"]
for mod in requirements:
    try:
        if importlib.util.find_spec(mod) is not None:
            if mod == "androguard" and importlib_metadata.version("androguard") != "3.4.0a1":
                print(f"{cyan}[{red} INCOMPATIBLE VERSION{cyan} ]{white} androguard\t|  Needed: {green}3.4.0a1{white}")
            elif mod == "quark":
                import quark
                if quark.__version__ != "21.8.1":
                    print(f"{cyan}[{red} INCOMPATIBLE VERSION{cyan} ]{white} quark\t|  Needed: {green}21.8.1{white}")
            elif mod == "prompt_toolkit" and importlib_metadata.version("prompt_toolkit") != "3.0.19":
                print(f"{cyan}[{red} INCOMPATIBLE VERSION{cyan} ]{white} prompt_toolkit\t|  Needed: {green}3.0.19{white}")
            else:
                print(f"{cyan}[{green} FOUND{cyan} ]{white} {mod}")
        else:
            print(f"{cyan}[{red} NOT FOUND{cyan} ]{white} {mod}")
    except:
        continue

# Binary checking zone
print(f"\n{infoS} Checking for binaries... (/usr/bin/)")
binary = ["/usr/bin/strings", "/usr/bin/readelf", "/usr/bin/jadx"]
for bb in binary:
    if os.path.exists(bb):
        print(f"{cyan}[{green} FOUND{cyan} ]{white} {bb.split('/')[3]}")
    else:
        print(f"{cyan}[{red} NOT FOUND{cyan} ]{white} {bb.split('/')[3]}")

# Configuration checking zone
print(f"\n{infoS} Checking for configurations...")
androconfs = configparser.ConfigParser()
windowsconf = configparser.ConfigParser()
androconfs.read(f"{sc0pe_path}/Systems/Android/libScanner.conf")
windowsconf.read(f"{sc0pe_path}/Systems/Windows/windows.conf")

# Android YARA rule path checks
if sc0pe_path in androconfs["Rule_PATH"]["rulepath"]:
    print(f"{red}>>>{white} Android YARA rule path: {green}{androconfs['Rule_PATH']['rulepath']}{white}")
else:
    print(f"{red}>>>{white} Android YARA rule path: {red}{androconfs['Rule_PATH']['rulepath']}{white}")

# Java decompiler path checks
if androconfs["Decompiler"]["decompiler"] == "/usr/bin/jadx":
    print(f"{red}>>>{white} Java decompiler path: {red}/usr/bin/jadx{white} (It is default. Use GitHub repository instead!)")
else:
    print(f"{red}>>>{white} Decompiler: {green}{androconfs['Decompiler']['decompiler']}{white}")

# Windows YARA rule path checks
if "/Systems" in windowsconf["Rule_PATH"]["rulepath"]:
    print(f"{red}>>>{white} Windows YARA rule path: {green}{windowsconf['Rule_PATH']['rulepath']}{white}")
else:
    print(f"{red}>>>{white} Windows YARA rule path: {red}{windowsconf['Rule_PATH']['rulepath']}{white}")
