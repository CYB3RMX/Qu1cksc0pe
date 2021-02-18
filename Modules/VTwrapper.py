#!/usr/bin/python3

import os
import sys
import json
import hashlib

# Checking for colorama existence
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Checking for prettytable existence
try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

# Colors
yellow = Fore.LIGHTYELLOW_EX
green = Fore.LIGHTGREEN_EX
red = Fore.LIGHTRED_EX
white = Style.RESET_ALL
cyan = Fore.LIGHTCYAN_EX

# Legends
errorS = f"{cyan}[{red}!{cyan}]{white}"
infoS = f"{cyan}[{red}*{cyan}]{white}"

# Arguments
try:
    apikey = str(sys.argv[1])
except:
    print(f"{errorS} Please get your API key from -> {green}https://www.virustotal.com/{white}")
    sys.exit(1)
try:
    targetFile = str(sys.argv[2])
except:
    print(f"{errorS} Please enter your file.")
    sys.exit(1)

# An array for AV names
avArray = ['ALYac', 'APEX', 'AVG', 'Acronis', 'Ad-Aware', 
           'AegisLab', 'AhnLab-V3', 'Alibaba', 'Antiy-AVL', 
           'Arcabit', 'Avast', 'Avast-Mobile', 'Avira', 'Baidu', 
           'BitDefender', 'BitDefenderFalx', 'BitDefenderTheta', 
           'Bkav', 'CAT-QuickHeal', 'CMC', 'ClamAV', 'Comodo', 
           'CrowdStrike', 'Cybereason', 'Cylance', 'Cynet', 'Cyren', 
           'DrWeb', 'ESET-NOD32', 'Elastic', 'Emsisoft', 'F-Secure', 
           'FireEye', 'Fortinet', 'GData', 'Gridinsoft', 'Ikarus', 
           'Jiangmin', 'K7AntiVirus', 'K7GW', 'Kaspersky', 'Kingsoft',
           'MAX', 'Malwarebytes', 'MaxSecure', 'McAfee', 'McAfee-GW-Edition',
           'MicroWorld-eScan', 'Microsoft', 'NANO-Antivirus', 'Paloalto',
           'Panda', 'Qihoo-360', 'Rising', 'SUPERAntiSpyware', 'Sangfor',
           'SentinelOne', 'Sophos', 'Symantec', 'SymantecMobileInsight', 
           'TACHYON', 'Tencent', 'TotalDefense', 'Trapmine', 'TrendMicro', 
           'TrendMicro-HouseCall', 'Trustlook', 'VBA32', 'VIPRE', 'ViRobot', 
           'Webroot', 'Yandex', 'Zillya', 'ZoneAlarm', 'Zoner', 'eGambit'
]

# Function for calculate md5 hash for files
def Hasher(targetFile):
    finalHash = hashlib.md5(open(targetFile, "rb").read()).hexdigest()
    return finalHash

# Function for querying target file's hashes on VT with curl command
def CurlComm(targetFile):
    # TODO: Look for better solutions instead of os.system() !!
    print(f"\n{infoS} Sending query to VirusTotal API...")
    targetHash = Hasher(targetFile)
    command = f'curl -s -X GET --url https://www.virustotal.com/api/v3/files/{targetHash} --header "x-apikey: {apikey}" > report.txt'
    os.system(command)

# Function for parsing report.txt
def ReportParser():
    if os.path.exists("report.txt"):
        print(f"{infoS} Parsing the scan report...")
        data = open("report.txt", "r")
        parser = json.loads(data.read())
        os.remove("report.txt") # Clear everything !!
        
        # Detections
        detect = 0
        antiTable = PrettyTable()
        antiTable.field_names = [f"{green}Detected By{white}", f"{green}Results{white}"]
        for av in avArray:
            if "data" in parser.keys():
                if av in parser["data"]["attributes"]["last_analysis_results"].keys():
                    if parser["data"]["attributes"]["last_analysis_results"][av]["result"] is not None:
                        detect += 1
                        antiTable.add_row([av, parser["data"]["attributes"]["last_analysis_results"][av]["result"]])
            else:
                print(f"\n{errorS} Nothing found harmfull about that file.")
                sys.exit(0)
        print(f"\n{infoS} Detection: {red}{detect}{white}/{red}{len(avArray)}{white}")
        print(antiTable)

# Execution area
CurlComm(targetFile)
ReportParser()