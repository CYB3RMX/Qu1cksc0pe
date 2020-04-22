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
    argument = str(sys.argv[2])
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

# This array is for parsing the scan reports
avState = ["detected", "version", "result", "update"]

# File scan function
def FileScan():
    # Checking file
    try:
        targetFile = str(sys.argv[3])
    except:
        print("{}[{}!{}]{} Please enter your file.".format(cyan,red,cyan,white))
        sys.exit(1)

    try:
        # Building scan request
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        params = {'apikey': apik}
        filee = {'file': (targetFile, open(targetFile, 'rb'))}
        print("\n{}[{}+{}]{} Sending query to VirusTotal api...".format(yellow,green,yellow,white))
        scanRequest = requests.post(url, files=filee, params=params)
        print("{}[{}+{}]{} Query sent. Just wait a couple of seconds...".format(yellow,green,yellow,white))
        os.system("sleep 5")
        fData = scanRequest.json()
        resource = fData['resource']

        # Building report request
        url1 = "https://www.virustotal.com/vtapi/v2/file/report"
        params1 = {'apikey': apik, 'resource': resource}
        print("{}[{}+{}]{} Getting the scan report please wait...".format(yellow,green,yellow,white))
        scanReport = requests.get(url1, params=params1)
        report = scanReport.json()
    except:
        print("{}[{}!{}]{} Program terminated.".format(cyan,red,cyan,white))
        sys.exit(1)

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

# URL scanner
def UrlScan():
    # Just handling errors
    try:
        targetUrl = str(input("{}=>{} Enter URL: ".format(green,white)))
    except:
        print("{}[{}!{}]{} Program terminated.".format(cyan,red,cyan,white))
        sys.exit(1)

    # Building scan request
    try:
        url = "https://www.virustotal.com/vtapi/v2/url/scan"
        myParams = {'apikey':apik, 'url':targetUrl}
        print("\n{}[{}+{}]{} Sending query to VirusTotal api...".format(yellow,green,yellow,white))
        urlReq = requests.post(url, data=myParams)
        print("{}[{}+{}]{} Query sent. Just wait a couple of seconds...".format(yellow,green,yellow,white))
        os.system("sleep 5")
        UData = urlReq.json()
        resource = UData['resource']

        # Building report request
        url1 = "https://www.virustotal.com/vtapi/v2/url/report"
        myNewParams = {'apikey': apik, 'resource': resource}
        print("{}[{}+{}]{} Getting the scan report please wait...".format(yellow,green,yellow,white))
        urlReport = requests.get(url1, params=myNewParams)
        report = urlReport.json()
    except:
        print("{}[{}!{}]{} Program terminated.".format(cyan,red,cyan,white))
        sys.exit(1)

    # A dictionary for detected Scanners
    detect = {}
    for web in phishArray:
        try:
            if str(report['scans'][web]["detected"]) == "True":
                detect.update({web: report['scans'][web]})
            else:
                pass
        except:
            continue

    # Printing and parsing the data
    if detect == {}:
        print("\n{}[{}!{}]{} Nothing found harmfull about that URL.".format(yellow,red,yellow,white))
    else:
        for ww in detect:
            print("\n{}{}".format(green,ww))
            print("\u001b[93m#"*30)
            print("{}DETECTED: {}{}".format(red, white, detect[ww]))
        print(" ")

# Execution area
if __name__ == '__main__':
    if argument == '--vtFile':
        FileScan()
    elif argument == '--vtUrl':
        UrlScan()
    else:
        pass
