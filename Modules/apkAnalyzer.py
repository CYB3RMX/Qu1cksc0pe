#!/usr/bin/python3

try:
    from androguard.core.bytecodes.apk import APK
except:
    print("Error: >androguard< module not found.")

import json,sys,os

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

danger = 0
normal = 0
def Analyzer(parsed):
    global danger
    global normal
    with open("Systems/Android/perms.json", "r") as f:
        permissions = json.load(f)

    apkPerms = parsed.get_permissions()
    permArr = []

    for p in range(len(permissions)):
        permArr.append(permissions[p]["permission"])

    for pp in apkPerms:
        if pp.split(".")[-1] in permArr:
            print(f"{cyan}({red}RISKY{cyan})-> {white}{pp}")
            danger += 1
        else:
            print(f"{cyan}({yellow}INFO{cyan})-> {white}{pp}")
            normal += 1

    # If there is no permission:
    if danger == 0 and normal == 0:
        print(f"{cyan}[{red}!{cyan}]{white} Not any permissions found.")

    print(f"{yellow}+","-"*53,f"+{white}")

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
    targetAPK = str(sys.argv[1])
    parsed = APK(targetAPK)
    print(f"{yellow}+","-"*20,f"{green}PERMISSIONS{yellow}","-"*20,"+")
    Analyzer(parsed)
    Detailed(targetAPK)

    # Statistics zone
    print(f"\n{yellow}+----- {green}STATISTICS{yellow} -----+{white}")
    print("Permissions: {}".format(danger+normal))
    print(f"RISKY: {danger}")
    print(f"Normal: {normal}")
    if danger > normal:
        print(f"State: {red}Malicious{white}")
    elif danger == normal and danger > 0:
        print(f"State: {yellow}Suspicious{white}")
    else:
        print(f"State: {green}Clean{white}")
    print(f"{yellow}+----------------------+{white}\n")
