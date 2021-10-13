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
magenta = Fore.LIGHTMAGENTA_EX

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
        print(f"{infoS} Parsing the scan report...\n")
        data = open("report.txt", "r")
        parser = json.loads(data.read())
        os.remove("report.txt") # Clear everything !!

        # Threat Categories
        threatTable = PrettyTable()
        threatTable.field_names = [f"{green}Threat Categories{white}", f"{green}Count{white}"]
        if "data" in parser.keys():
            if "popular_threat_classification" in parser["data"]["attributes"].keys():
                if "suggested_threat_label" in parser["data"]["attributes"]["popular_threat_classification"].keys():
                    print(f"\n{infoS} Potential Threat Label: " + f'{red}{parser["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]}{white}')

                # Counting threat category
                if "popular_threat_category" in parser["data"]["attributes"]["popular_threat_classification"].keys():
                    for th in range(0, len(parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"])):
                        threatTable.add_row([f'{red}{parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"][th]["value"]}{white}',f'{red}{parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"][th]["count"]}{white}'])
                print(threatTable)

                # Counting threat names
                nameTable = PrettyTable()
                nameTable.field_names = [f"{green}Threat Names{white}",f"{green}Count{white}"]
                if "popular_threat_name" in parser["data"]["attributes"]["popular_threat_classification"].keys():
                    for th in range(0, len(parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"])):
                        nameTable.add_row([f'{red}{parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"][th]["value"]}{white}',f'{red}{parser["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"][th]["count"]}{white}'])
                print(nameTable)
        
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

        # Behavior analysis
        if "data" in parser.keys():
            if "crowdsourced_ids_results" in parser["data"]["attributes"].keys():
                print(f"\n{infoS} CrowdSourced IDS Reports")
                print("+","-"*60,"+")
                try:
                    for crowd in range(0, len(parser["data"]["attributes"]["crowdsourced_ids_results"])):
                        if "alert_context" in parser["data"]["attributes"]["crowdsourced_ids_results"][crowd].keys():
                            print(f"{magenta}=> {white}Alert: {green}{crowd+1}{white}")
                            for alrt in range(0, len(parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_context"])):
                                for repo in parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_context"][alrt]:
                                    if repo == "ja3":
                                        pass
                                    else:
                                        sanitized = f"{repo}".replace("_", " ").upper()
                                        print(f'{magenta}-----> {white}{sanitized}: {parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_context"][alrt][repo]}')
                            if parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_severity"] == "high":
                                print(f'{magenta}---> {white}Alert Severity: {red}{parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_severity"]}')
                            elif parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_severity"] == "medium":
                                print(f'{magenta}---> {white}Alert Severity: {yellow}{parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_severity"]}')
                            else:
                                print(f'{magenta}---> {white}Alert Severity: {cyan}{parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["alert_severity"]}')
                            print(f'{magenta}---> {white}Rule Category: {parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["rule_category"]}')
                            print(f'{magenta}---> {white}Rule Message: {parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["rule_msg"]}')
                            print(f'{magenta}---> {white}Rule Source: {parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["rule_source"]}')
                            print(f'{magenta}---> {white}Rule URL: {parser["data"]["attributes"]["crowdsourced_ids_results"][crowd]["rule_url"]}\n')
                except:
                    pass
                if "crowdsourced_ids_stats" in parser["data"]["attributes"].keys():
                    print(f"\n{infoS} Alert Summary: {green}{targetFile}{white}")
                    crowdTable = PrettyTable()
                    crowdTable.field_names = [f"{green}Alert Level{white}", f"{green}Number of Alerts{white}"]
                    for alrtlvl in parser["data"]["attributes"]["crowdsourced_ids_stats"]:
                        sant = f"{alrtlvl}".upper()
                        if alrtlvl == "high":
                            crowdTable.add_row([f"{red}{sant}{white}", f'{parser["data"]["attributes"]["crowdsourced_ids_stats"][alrtlvl]}'])
                        elif alrtlvl == "medium":
                            crowdTable.add_row([f"{yellow}{sant}{white}", f'{parser["data"]["attributes"]["crowdsourced_ids_stats"][alrtlvl]}'])
                        elif alrtlvl == "low":
                            crowdTable.add_row([f"{cyan}{sant}{white}", f'{parser["data"]["attributes"]["crowdsourced_ids_stats"][alrtlvl]}'])
                        else:
                            crowdTable.add_row([f"{white}{sant}", f'{parser["data"]["attributes"]["crowdsourced_ids_stats"][alrtlvl]}'])
                    print(f"{crowdTable}\n")
            else:
                print(f"\n{errorS} There is no IDS reports for target file.\n")

# Execution area
CurlComm(targetFile)
ReportParser()