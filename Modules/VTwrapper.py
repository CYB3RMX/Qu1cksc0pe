#!/usr/bin/python3

# Colors
yellow='\u001b[1;93m'
green='\u001b[1;92m'
red='\u001b[1;91m'
white='\u001b[0m'
cyan='\u001b[1;96m'

# Necessary libs
import os,sys,requests

# Arguments
try:
    apik = str(sys.argv[1])
    argument = str(sys.argv[2])
except:
    print(f"{cyan}[{red}!{cyan}]{white} Please get your API key from -> {green}https://www.virustotal.com/{white}")
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
allAvs = len(avArray)

# A simple website array for url scanner
phishArray = ["Botvrij.eu","Feodo Tracker", "CLEAN MX", "DNS8", "NotMining",
              "VX Vault", "securolytics", "Tencent", "MalwarePatrol", "MalSilo",
              "Comodo Valkyrie Verdict", "PhishLabs", "EmergingThreats", "Sangfor",
              "K7AntiVirus", "Spam404", "Virusdie External Site Scan", "Artists Against 419",
              "IPsum", "Cyren", "Quttera", "CINS Army", "AegisLab WebGuard", "MalwareDomainList",
              "Lumu", "zvelo", "Google Safebrowsing", "Kaspersky", "BitDefender", "GreenSnow",
              "G-Data", "OpenPhish", "Malware Domain Blocklist", "AutoShun", "Trustwave",
              "Web Security Guard", "CyRadar", "desenmascara.me", "ADMINUSLabs", "Malwarebytes hpHosts", "Dr.Web", "AlienVault", "Emsisoft", "Spamhaus", "malwares.com URL checker",
              "Phishtank", "EonScope", "Malwared", "Avira", "Cisco Talos IP Blacklist", "CyberCrime",
              "Antiy-AVL", "Forcepoint ThreatSeeker", "SCUMWARE.org", "Certego", "Yandex Safebrowsing", "ESET", "Threatsourcing", "URLhaus", "SecureBrain", "Nucleon",
              "PREBYTES", "Sophos", "Blueliv", "BlockList", "Netcraft", "CRDF", "ThreatHive",
              "BADWARE.INFO", "FraudScore", "Quick Heal", "Rising", "StopBadware", "Sucuri SiteCheck",
              "Fortinet", "StopForumSpam", "ZeroCERT", "Baidu-International", "Phishing Database"]
allFish = len(phishArray)

# This array is for parsing the scan reports
avState = ["detected", "version", "result", "update"]
webState = ["detected", "result"]

# File scan function
score = 0

def FileScan():
    global score
    # Checking file
    try:
        targetFile = str(sys.argv[3])
    except:
        print(f"{cyan}[{red}!{cyan}]{white} Please enter your file.")
        sys.exit(1)

    try:
        # Building scan request
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        params = {'apikey': apik}
        filee = {'file': (targetFile, open(targetFile, 'rb'))}
        print(f"\n{cyan}[{red}+{cyan}]{white} Sending query to VirusTotal API...")
        scanRequest = requests.post(url, files=filee, params=params)
        print(f"{cyan}[{red}+{cyan}]{white} Query sent. Just wait a couple of seconds...")
        os.system("sleep 5")
        fData = scanRequest.json()
        resource = fData['resource']

        # Building report request
        url1 = "https://www.virustotal.com/vtapi/v2/file/report"
        params1 = {'apikey': apik, 'resource': resource}
        print(f"{cyan}[{red}+{cyan}]{white} Getting the scan report please wait...")
        scanReport = requests.get(url1, params=params1)
        report = scanReport.json()
    except:
        print(f"{cyan}[{red}!{cyan}]{white} Program terminated.")
        sys.exit(1)

    # A dictionary for detected AV
    detect = {}
    for av in avArray:
        try:
            if str(report['scans'][av]["detected"]) == "True":
                score +=1
                detect.update({av: report['scans'][av]})
            else:
                pass
        except:
            continue

    # Printing and parsing the data
    if detect == {}:
        print(f"\n{cyan}[{red}!{cyan}]{white} Nothing found harmfull about that file.")
    else:
        print(f"\n{cyan}[{red}*{cyan}]{white} Detection: {red}{score}{white}/{red}{allAvs}")
        for aa in detect:
            print(f"\n{green}{aa}")
            print("\u001b[93m#"*30)
            for avs in avState:
                print("{}{}: {}{}".format(red, avs.upper(), white, detect[aa][avs]))
        print("")

# URL scanner
def UrlScan():
    global score
    # Just handling errors
    try:
        targetUrl = str(input(f"{green}=>{white} Enter URL: "))
    except:
        print(f"{cyan}[{red}!{cyan}]{white} Program terminated.")
        sys.exit(1)

    # Building scan request
    try:
        url = "https://www.virustotal.com/vtapi/v2/url/scan"
        myParams = {'apikey':apik, 'url':targetUrl}
        print(f"\n{cyan}[{red}+{cyan}]{white} Sending query to VirusTotal API...")
        urlReq = requests.post(url, data=myParams)
        print(f"{cyan}[{red}+{cyan}]{white} Query sent. Just wait a couple of seconds...")
        os.system("sleep 5")
        UData = urlReq.json()
        resource = UData['resource']

        # Building report request
        url1 = "https://www.virustotal.com/vtapi/v2/url/report"
        myNewParams = {'apikey': apik, 'resource': resource}
        print(f"{cyan}[{red}+{cyan}]{white} Getting the scan report please wait...")
        urlReport = requests.get(url1, params=myNewParams)
        report = urlReport.json()
    except:
        print(f"{cyan}[{red}!{cyan}]{white} Program terminated.")
        sys.exit(1)

    # A dictionary for detected Scanners
    detect = {}
    for web in phishArray:
        try:
            if str(report['scans'][web]["detected"]) == "True":
                score +=1
                detect.update({web: report['scans'][web]})
            else:
                pass
        except:
            continue

    # Printing and parsing the data
    if detect == {}:
        print(f"\n{cyan}[{red}!{cyan}]{white} Nothing found harmfull about that URL.")
    else:
        print(f"\n{cyan}[{red}*{cyan}]{white} Detection: {red}{score}{white}/{red}{allFish}")
        for ww in detect:
            print(f"\n{green}{ww}")
            print("\u001b[93m#"*30)
            for webs in webState:
                print("{}{}: {}{}".format(red,webs.upper(),white,detect[ww][webs]))
        print(" ")

# Execution area
if __name__ == '__main__':
    if argument == '--vtFile':
        FileScan()
    elif argument == '--vtUrl':
        UrlScan()
    else:
        pass