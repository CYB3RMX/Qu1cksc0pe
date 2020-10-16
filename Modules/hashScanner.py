#!/usr/bin/python3

import requests
import os
import hashlib
import sys
import math
import json

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

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
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
    if os.path.isfile("HashDB.json") == False:
        print(f"{errorS} Local signature database not found.")
        choose = str(input(f"{green}=>{white} Would you like to download it [Y/n]?: "))
        if choose == "Y" or choose == "y":
            local_database = "HashDB.json"
            dbUrl = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB.json"
            req = requests.get(dbUrl, stream=True)
            total_size = int(req.headers.get('content-length', 0))
            block_size = 1024
            wrote = 0
            print(f"\n{infoS} Downloading signature database please wait...")
            try:
                with open(local_database, 'wb') as ff:
                    for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                        wrote = wrote + len(data)
                        ff.write(data)
                sys.exit(0)
            except:
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
    with open("HashDB.json") as databaseFile:
        hashData = json.load(databaseFile)
except:
    DatabaseCheck()

# Hashing
targetHash = GetHash(targetFile)
hashMe = hashlib.sha1(targetHash.encode())
finalHash = hashMe.hexdigest()

# Creating answer table
answTable = PrettyTable()
answTable.field_names = [f"{green}Hash{white}", f"{green}Name{white}"]

# Total hashes
tot = 0
try:
    for hh in hashData:
        if hh['hash'] != "":
            tot += 1
except:
    pass

# Finding target hash
foundc = 0
try:
    for hashes in hashData:
        if hashes['hash'] == finalHash:
            answTable.add_row([f"{red}{finalHash}{white}", f"{red}{hashes['name']}{white}"])
            foundc += 1
            break
except:
    pass

# Printing informations
print(f"{infoS} Total Hashes: {green}{tot+1}{white}")
print(f"{infoS} File Name: {green}{targetFile}{white}")
print(f"{infoS} Target Hash: {green}{finalHash}{white}\n")
if foundc != 0:
    print(f"{answTable}\n")
else:
    print(f"{errorS} Target hash is not in our database.")
    print(f"{infoS} Try {green}--analyze{white} and {green}--vtFile{white} instead.\n")