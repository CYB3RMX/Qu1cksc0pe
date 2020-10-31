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
errorS = f"{cyan}[{red}!{cyan}]{white}"

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
            print(f"\n{cyan}[{red}ERROR{cyan}]{white} Without local database '{green}--hashscan{white}' will not work.\n")
            sys.exit(1)

# Hashing with md5
def GetHash(targetFile):
    hashMd5 = hashlib.md5()
    try:
        with open(targetFile, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashMd5.update(chunk)
    except:
        pass
    return hashMd5.hexdigest()

# Hashing md5 with sha1
def NextHash(targetHash):
    hashMe = hashlib.sha1(targetHash.encode())
    finalHash = hashMe.hexdigest()
    return finalHash

try:
    with open("HashDB.json") as databaseFile:
        hashData = json.load(databaseFile)
except:
    DatabaseCheck()

# Handling single scans
def NormalScan():
    # Hashing
    targetHash = GetHash(targetFile)
    hashToScan = NextHash(targetHash)
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
            if hashes['hash'] == hashToScan:
                answTable.add_row([f"{red}{hashToScan}{white}", f"{red}{hashes['name']}{white}"])
                foundc += 1
                break
    except:
        pass
    # Printing informations
    print(f"{infoS} Total Hashes: {green}{tot}{white}")
    print(f"{infoS} File Name: {green}{targetFile}{white}")
    print(f"{infoS} Target Hash: {green}{hashToScan}{white}\n")
    if foundc != 0:
        print(f"{answTable}\n")
    else:
        print(f"{errorS} Target hash is not in our database.")
        print(f"{infoS} Try {green}--analyze{white} and {green}--vtFile{white} instead.\n")

# Handling multiple scans
def MultipleScan():
    # Creating summary table
    mulansTable = PrettyTable()
    mulansTable.field_names = [f"{green}File Names{white}", f"{green}Hash{white}", f"{green}Name{white}"]
    # Handling folders
    if os.path.isdir(targetFile) == True:
        allFiles = os.listdir(targetFile)
        # How many files in that folder?
        filNum = 0
        for _ in allFiles:
            filNum += 1
        # Lets scan them!!
        multimalw = 0
        print(f"{infoS} Qu1cksc0pe scans that folder for malicious files. Please wait...")
        for tf in tqdm(range(0, filNum), desc="Scanning..."):
            if allFiles[tf] != '':
                scanme = f"{targetFile}/{allFiles[tf]}"
                targetHash = GetHash(scanme)
                hashToScan = NextHash(targetHash)
                # Finding target hash
                try:
                    for hashes in hashData:
                        if hashes['hash'] == hashToScan:
                            mulansTable.add_row([f"{red}{allFiles[tf]}{white}", f"{red}{hashToScan}{white}", f"{red}{hashes['name']}{white}"])
                            multimalw += 1
                except:
                    pass
        # Print all
        if multimalw != 0:
            print(f"\n{mulansTable}\n")
        else:
            print(f"\n{errorS} Nothing found.\n")

if __name__ == '__main__':
    if str(sys.argv[2]) == '--normal':
        NormalScan()
    elif str(sys.argv[2]) == '--multiscan':
        MultipleScan()
    else:
        pass