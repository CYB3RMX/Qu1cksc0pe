#!/usr/bin/python3

try:
    from androguard.core.bytecodes.apk import APK
except:
    print("Error: >androguard< module not found.")

import json,sys

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

def Analyzer(parsed):
    danger = 0
    normal = 0
    with open("Systems/Android/perms.json", "r") as f:
        permissions = json.load(f)

    apkPerms = parsed.get_permissions()
    permArr = []

    for p in range(len(permissions)):
        permArr.append(permissions[p]["permission"])

    for pp in apkPerms:
        if pp.split(".")[-1] in permArr:
            print(f"{cyan}({red}DANGEROUS{cyan})-> {white}{pp}")
            danger += 1
        else:
            print(f"{cyan}({yellow}INFO{cyan})-> {white}{pp}")
            normal += 1

    print("+","-"*40,"+")
    print("\n+----- STATISTICS -----+")
    print("Permissions: {}".format(danger+normal))
    print(f"Dangerous: {danger}")
    print(f"Normal: {normal}")
    if danger > normal:
        print(f"State: {red}Malicious{white}")
    elif danger == normal:
        print(f"State: {yellow}Suspicious{white}")
    else:
        print(f"State: {green}Clean{white}")
    print("+----------------------+\n")

if __name__ == '__main__':
    targetAPK = str(sys.argv[1])
    parsed = APK(targetAPK)
    print("+","-"*40,"+")
    Analyzer(parsed)
