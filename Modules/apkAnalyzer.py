#!/usr/bin/python3

import json,sys,os

# Module handling
try:
    from androguard.core.bytecodes.apk import APK
except:
    print("Error: >androguard< module not found.")
    sys.exit(1)

try:
    from prettytable import PrettyTable
except:
    print("Error: >prettytable< module not found.")
    sys.exit(1)

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
yellow = Fore.LIGHTYELLOW_EX

# necessary variables
danger = 0
normal = 0

# Permission analyzer
def Analyzer(parsed):
    global danger
    global normal
    statistics = PrettyTable()

    # Getting blacklisted permissions
    with open("Systems/Android/perms.json", "r") as f:
        permissions = json.load(f)

    apkPerms = parsed.get_permissions()
    permArr = []

    # Getting target APK file's permissions
    for p in range(len(permissions)):
        permArr.append(permissions[p]["permission"])

    # Parsing permissions
    statistics.field_names = [f"{green}Permissions{white}", f"{green}State{white}"]
    for pp in apkPerms:
        if pp.split(".")[-1] in permArr:
            statistics.add_row([f"{pp}", f"{red}Risky{white}"])
            danger += 1
        else:
            statistics.add_row([f"{pp}", f"{yellow}Info{white}"])
            normal += 1

    # If there is no permission:
    if danger == 0 and normal == 0:
        print(f"{cyan}[{red}!{cyan}]{white} Not any permissions found.")
    else:
        print(statistics)

# Analyzing more deeply
def DeepScan(parsed):
    
    # Getting features
    featStat = PrettyTable()
    featStat.field_names = [f"{green}Features{white}"]
    features = parsed.get_features()
    if features != []:
        for ff in features:
            featStat.add_row([ff])
        print(featStat)
    else:
        pass
    
    # Activities
    activeStat = PrettyTable()
    activeStat.field_names = [f"{green}Activities{white}"]
    actos = parsed.get_activities()
    if actos != []:
        for aa in actos:
            activeStat.add_row([aa])
        print(activeStat)
    else:
        pass
    
    # Services
    servStat = PrettyTable()
    servStat.field_names = [f"{green}Services{white}"]
    servv = parsed.get_services()
    if servv != []:
        for ss in servv:
            servStat.add_row([ss])
        print(servStat)
    else:
        pass
    
    # Receivers
    recvStat = PrettyTable()
    recvStat.field_names = [f"{green}Receivers{white}"]
    receive = parsed.get_receivers()
    if receive != []:
        for rr in receive:
            recvStat.add_row([rr])
        print(recvStat)
    else:
        pass
    
    # Providers
    provStat = PrettyTable()
    provStat.field_names = [f"{green}Providers{white}"]
    provids = parsed.get_providers()
    if provids != []:
        for pp in provids:
            provStat.add_row([pp])
        print(provStat)
    else:
        pass

# APK string analyzer
def Detailed(targetAPK):

    # Extracting all strings to better analysis
    print(f"\n{cyan}[{red}*{cyan}]{white} Extracting strings from file...")
    print("+","-"*40,"+")
    try:
        command = 'aapt dump strings {} | cut -f2 -d ":" > apkStr.txt'.format(targetAPK)
        os.system(command)
        command = './Modules/apkStranalyzer.sh'
        os.system(command)
        print("+","-"*40,"+")
    except:
        print(f"{cyan}[{red}!{cyan}]{white} Error: aapt tool not found.")
        sys.exit(1)

# Execution
if __name__ == '__main__':
    try:
        # Getting and parsing target APK
        targetAPK = str(sys.argv[1])
        parsed = APK(targetAPK)
        
        # Permissions side
        Analyzer(parsed)
        
        # Deep scanner
        DeepScan(parsed)
        
        # Strings side
        Detailed(targetAPK)
    except:
        print(f"{cyan}[{red}!{cyan}]{white} An error occured.")