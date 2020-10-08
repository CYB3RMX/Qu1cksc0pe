#!/usr/bin/python3

import requests
import os
import hashlib
import sys
import math

# Module for progressbar
try:
    from tqdm import tqdm
except:
    print("Module: >tqdm< not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# File handling
targetFile = str(sys.argv[1])

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"
thLevel = f"{cyan}[{red}Threat Level{cyan}]{white}"

def DatabaseCheck():
    if os.path.isfile("HashDB.sha1") == False:
        print(f"{errorS} Local signature database not found.")
        choose = str(input(f"{green}=>{white} Would you like to download it [Y/n]?: "))
        if choose == "Y" or choose == "y":
            local_database = "HashDB.zip"
            dbUrl = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/master/HashDB.sha1.zip"
            req = requests.get(dbUrl, stream=True)
            total_size = int(req.headers.get('content-length', 0))
            block_size = 1024
            wrote = 0
            print(f"\n{infoS} Downloading signature database please wait...")
            with open(local_database, 'wb') as ff:
                for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                    wrote = wrote + len(data)
                    ff.write(data)
            print(f"{infoS} Extracting file...")
            command = f"unzip {local_database} &>/dev/null; if [ $? -eq 0 ];then rm -rf HashDB.zip; echo '{foundS} Database downloaded successfully.'; else echo '{errorS} Error occured!'; exit 1; fi"
            os.system(command)
            sys.exit(0)
        else:
            print(f"\n{cyan}[{red}ERROR{cyan}]{white} Without local database '{green}--hashScan{white}' will not work.\n")
            sys.exit(1)

# Hashing with md5
def GetHash(targetFile):
    hashMd5 = hashlib.md5()
    with open(targetFile, "rb") as ff:
        for chunk in iter(lambda: ff.read(4096), b""):
            hashMd5.update(chunk)
    return hashMd5.hexdigest()

try:
    databaseFile = open("HashDB.sha1", "r").read().split('\n')
except:
    DatabaseCheck()

# Total hash checking
tot = 0
for _ in databaseFile:
    tot += 1

# Hashing
targetHash = GetHash(targetFile)
hashMe = hashlib.sha1(targetHash.encode())
finalHash = hashMe.hexdigest()

# Info
print(f"{infoS} Total Hashes: {green}{tot}{white}")
print(f"{infoS} File Name: {green}{targetFile}{white}")
print(f"{infoS} File Signature: {green}{finalHash}{white}")

# Scanning
if finalHash in databaseFile:
    print(f"\n{cyan}[{red}DANGER{cyan}]{white}: Target file's hash is in our local database.")
    print(f"{thLevel}: {red}Malicious{white}\n")
else:
    print(f"\n{thLevel}: {yellow}Unknown{white}\n")
    print(f"{cyan}[{yellow}INFO{cyan}]{white} Try '{green}--analyze{white}' or '{green}--vtFile{white}' instead.\n")