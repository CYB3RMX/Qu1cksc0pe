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

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

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

    # Getting and parsing target APK
    targetAPK = str(sys.argv[1])
    parsed = APK(targetAPK)

    # Permissions side
    Analyzer(parsed)

    # Strings side
    Detailed(targetAPK)

    # Statistics zone
    summary = PrettyTable()
    print(f"\n{cyan}[{red}*{cyan}]{white} All Permissions: {danger+normal}")

    # Printing all
    summary.field_names = [f"{green}Permission States{white}", f"{green}Number of Permissions{white}"]
    summary.add_row([f"{red}Risky{white}", f"{danger}"])
    summary.add_row([f"{yellow}Info{white}", f"{normal}"])
    print(summary)
    if danger > normal:
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {red}Malicious{white}")
    elif danger == normal and danger > 0:
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {yellow}Suspicious{white}")
    else:
        print(f"{cyan}[{red}Threat Level{cyan}]{white}: {green}Clean{white}")
