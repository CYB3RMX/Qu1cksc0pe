#!/usr/bin/python3

import re
import sys
import hashlib
import requests

from utils import err_exit

# Checking for rich existence
try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Arguments
try:
    apikey = str(sys.argv[1])
except:
    err_exit("[blink bold white on red]Please get your API key from [white]-> [bold green][a]https://www.virustotal.com/[/a]")
try:
    targetFile = sys.argv[2]
except:
    err_exit("\n[bold white on red]Please enter your file!!\n")

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

# Function for querying target file's hashes on VT
def DoRequest(targetFile):
    print(f"\n{infoS} Querying the target hash to the VirusTotal API...")
    # Building request
    request_headers = {"x-apikey": apikey}
    targetHash = Hasher(targetFile)
    vt_data = requests.get(f"https://www.virustotal.com/api/v3/files/{targetHash}", headers=request_headers)
    if vt_data.ok:
        return vt_data.json()
    else:
        return None

# Function for parsing report.txt
def ReportParser(reportStr):
    if reportStr is not None:
        print(f"{infoS} Parsing the scan report...\n")

        # Threat Categories
        threatTable = Table()
        threatTable.add_column("[bold green]Threat Categories", justify="center")
        threatTable.add_column("[bold green]Count", justify="center")
        if "data" in reportStr.keys():
            if "popular_threat_classification" in reportStr["data"]["attributes"].keys():
                if "suggested_threat_label" in reportStr["data"]["attributes"]["popular_threat_classification"].keys():
                    print(f"\n{infoS} Potential Threat Label: " + f'[bold red]{reportStr["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]}[white]')

                # Counting threat category
                if "popular_threat_category" in reportStr["data"]["attributes"]["popular_threat_classification"].keys():
                    for th in range(0, len(reportStr["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"])):
                        threatTable.add_row(
                            f"[bold red]{reportStr['data']['attributes']['popular_threat_classification']['popular_threat_category'][th]['value']}",
                            f"[bold red]{reportStr['data']['attributes']['popular_threat_classification']['popular_threat_category'][th]['count']}"
                        )
                print(threatTable)

                # Counting threat names
                nameTable = Table()
                nameTable.add_column("[bold green]Threat Names", justify="center")
                nameTable.add_column("[bold green]Count", justify="center")
                if "popular_threat_name" in reportStr["data"]["attributes"]["popular_threat_classification"].keys():
                    for th in range(0, len(reportStr["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"])):
                        nameTable.add_row(
                            f"[bold red]{reportStr['data']['attributes']['popular_threat_classification']['popular_threat_name'][th]['value']}",
                            f"[bold red]{reportStr['data']['attributes']['popular_threat_classification']['popular_threat_name'][th]['count']}"
                        )
                print(nameTable)
        
        # Detections
        detect = 0
        antiTable = Table()
        antiTable.add_column("[bold green]Detected By", justify="center")
        antiTable.add_column("[bold green]Results", justify="center")
        for av in avArray:
            if "data" in reportStr.keys():
                if av in reportStr["data"]["attributes"]["last_analysis_results"].keys():
                    if reportStr["data"]["attributes"]["last_analysis_results"][av]["result"] is not None:
                        detect += 1
                        antiTable.add_row(av, reportStr["data"]["attributes"]["last_analysis_results"][av]["result"])
            else:
                err_exit(f"\n{errorS} Nothing found harmfull about that file.", arg_override=0)
        print(f"\n{infoS} Detection: [bold red]{detect}[white]/[bold red]{len(avArray)}[white]")
        print(antiTable)

        # Behavior analysis
        if "data" in reportStr.keys():
            if "crowdsourced_ids_results" in reportStr["data"]["attributes"].keys():
                idsTable = Table(title="\n* CrowdSourced IDS Reports *", title_justify="center", title_style="bold cyan")
                idsTable.add_column("Alert Number", justify="center")
                idsTable.add_column("SRC IP", justify="center")
                idsTable.add_column("SRC Port", justify="center")
                idsTable.add_column("DST IP", justify="center")
                idsTable.add_column("DST Port", justify="center")
                idsTable.add_column("Alert Severity", justify="center")
                idsTable.add_column("Rule Category", justify="center")
                idsTable.add_column("Rule Source", justify="center")
                for crowd in range(0, len(reportStr["data"]["attributes"]["crowdsourced_ids_results"])):
                    try:
                        ids_alert = reportStr["data"]["attributes"]["crowdsourced_ids_results"][crowd]
                        rule_categ = ids_alert["rule_category"]
                        severity = ids_alert["alert_severity"]
                        rule_source = ids_alert["rule_source"]
                        if "alert_context" in ids_alert.keys():
                            for mycontext in ids_alert["alert_context"]:
                                # Look for source ip address
                                if "src_ip" in mycontext.keys():
                                    ip_address = mycontext["src_ip"]
                                else:
                                    ip_address = "none"

                                # Look for source ports
                                if "src_port" in mycontext.keys():
                                    portnum = mycontext["src_port"]
                                else:
                                    portnum = "none"

                                # Look for destination ip address
                                if "dest_ip" in mycontext.keys():
                                    dest_address = mycontext["dest_ip"]
                                else:
                                    dest_address = "none"

                                # Look for destination ports
                                if "dest_port" in mycontext.keys():
                                    dest_port = mycontext["dest_port"]
                                else:
                                    dest_port = "none"

                            # Adding to table with alert_severity classification
                            if severity == "high":
                                idsTable.add_row(str(crowd+1), str(ip_address), str(portnum), str(dest_address), str(dest_port), f"[bold red]{severity}", str(rule_categ), str(rule_source))
                            elif severity == "medium":
                                idsTable.add_row(str(crowd+1), str(ip_address), str(portnum), str(dest_address), str(dest_port), f"[bold yellow]{severity}", str(rule_categ), str(rule_source))
                            elif severity == "low":
                                idsTable.add_row(str(crowd+1), str(ip_address), str(portnum), str(dest_address), str(dest_port), f"[bold cyan]{severity}", str(rule_categ), str(rule_source))
                            else:
                                idsTable.add_row(str(crowd+1), str(ip_address), str(portnum), str(dest_address), str(dest_port), str(severity), str(rule_categ), str(rule_source))
                    except:
                        continue
                # Print results
                print(idsTable)

                if "crowdsourced_ids_stats" in reportStr["data"]["attributes"].keys():
                    print(f"\n{infoS} Alert Summary: [bold green]{targetFile}[white]")
                    crowdTable = Table()
                    crowdTable.add_column("[bold green]Alert Level", justify="center")
                    crowdTable.add_column("[bold green]Number of Alerts", justify="center")
                    for alrtlvl in reportStr["data"]["attributes"]["crowdsourced_ids_stats"]:
                        sant = f"{alrtlvl}".upper()
                        if alrtlvl == "high":
                            crowdTable.add_row(f"[bold red]{sant}", f"[bold red]{reportStr['data']['attributes']['crowdsourced_ids_stats'][alrtlvl]}")
                        elif alrtlvl == "medium":
                            crowdTable.add_row(f"[bold yellow]{sant}", f"[bold yellow]{reportStr['data']['attributes']['crowdsourced_ids_stats'][alrtlvl]}")
                        elif alrtlvl == "low":
                            crowdTable.add_row(f"[bold cyan]{sant}", f"[bold cyan]{reportStr['data']['attributes']['crowdsourced_ids_stats'][alrtlvl]}")
                        else:
                            crowdTable.add_row(str(sant), f'{reportStr["data"]["attributes"]["crowdsourced_ids_stats"][alrtlvl]}')
                    print(crowdTable)
                    print(" ")
            else:
                print("\n[bold white on red]There is no IDS reports for target file.\n")
    else:
        print(f"{errorS} There is no report about the target hash. You need to upload it!")

# Execution area
reportstr = DoRequest(targetFile)
ReportParser(reportstr)