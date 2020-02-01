#!/usr/bin/python3

# Colors
yellow='\u001b[93m'
green='\u001b[92m'
red='\u001b[91m'
white='\u001b[0m'
cyan='\u001b[96m'

# Necessary libs
import os,sys,requests

# Arguments
try:
    apik = str(sys.argv[1])
    targetFile = str(sys.argv[2])
except:
    print("{}[{}!{}]{} Please get your api key from -> {}https://www.virustotal.com/{}".format(cyan,red,cyan,white,green,white))
    sys.exit(1)
    
# A simple AV database for querying
avArray = ["DrWeb", "MicroWorld-eScan", "FireEye", "CAT-QuickHeal",
           "McAfee", "VIPRE", "SUPERAntiSpyware", "Sangfor",
           "K7AntiVirus", "Alibaba", "K7GW", "CrowdStrike", "Arcabit", "Invincea",
           "BitDefenderTheta", "Cyren", "TotalDefense", "Zoner",
           "TrendMicro-HouseCall", "Paloalto", "ClamAV", "Kaspersky", "BitDefender",
           "NANO-Antivirus", "ViRobot", "Rising", "Ad-Aware", "Emsisoft", "Comodo",
           "F-Secure", "Baidu", "Zillya", "TrendMicro", "McAfee-GW-Edition", "Trapmine",
           "CMC", "Sophos", "Ikarus", "F-Prot", "Jiangmin", "eGambit", "Avira", "Fortinet",
           "Antiy-AVL", "Kingsoft", "Endgame", "Microsoft", "AegisLab", "ZoneAlarm", "Avast-Mobile",
           "TACHYON", "AhnLab-V3", "Acronis", "MAX", "VBA32", "Malwarebytes", "Panda",
           "APEX", "ESET-NOD32", "Tencent", "Yandex", "SentinelOne", "MaxSecure", "GData", "Webroot",
           "AVG", "Cybereason", "Avast", "Qihoo-360", "Symantec"]

# This array is for parsing the scan reports
avState = ["detected", "version", "result", "update"]

# File scan function
def FileScan():
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {'apikey': apik}
    filee = {'file': (targetFile, open(targetFile, 'rb'))}
    print("\n{}[{}+{}]{} Sending query to VirusTotal api...".format(yellow,green,yellow,white))
    scanRequest = requests.post(url, files=filee, params=params)
    print("{}[{}+{}]{} Query sent. Just wait a couple of seconds...".format(yellow,green,yellow,white))
    os.system("sleep 5")
    fData = scanRequest.json()
    resource = fData['resource']
    url1 = "https://www.virustotal.com/vtapi/v2/file/report"
    params1 = {'apikey': apik, 'resource': resource}
    print("{}[{}+{}]{} Getting the scan report please wait...".format(yellow,green,yellow,white))
    scanReport = requests.get(url1, params=params1)
    report = scanReport.json()

    # A dictionary for detected AV
    detect = {}
    for av in avArray:
        try:
            if str(report['scans'][av]["detected"]) == "True":
                detect.update({av: report['scans'][av]})
            else:
                pass
        except:
            continue

    # Printing and parsing the data
    if detect == {}:
        print("\n{}[{}!{}]{} Nothing found harmfull about that file.".format(yellow,red,yellow,white))
    else:
        for aa in detect:
            print("\n{}{}".format(green,aa))
            print("\u001b[93m#"*30)
            for avs in avState:
                print("{}{}: {}{}".format(red, avs.upper(), white, detect[aa][avs]))
        print("")

# Execution area
if __name__ == '__main__':
    FileScan()
