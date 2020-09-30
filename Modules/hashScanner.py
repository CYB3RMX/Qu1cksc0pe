#!/usr/bin/python3

import requests,os,hashlib,sys,math

# Module for progressbar
try:
    from tqdm import tqdm
except:
    print("Module: >tqdm< not found.")
    sys.exit(1)

# File handling
targetFile = str(sys.argv[1])

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

def DatabaseCheck():
    if os.path.isfile("HashDB.sha1") == False:
        print(f"{cyan}[{red}!{cyan}]{white} Local signature database not found.")
        choose = str(input(f"{green}=>{white} Would you like to download it [Y/n]?: "))
        if choose == "Y" or choose == "y":
            local_database = "HashDB.zip"
            dbUrl = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/master/HashDB.sha1.zip"
            req = requests.get(dbUrl, stream=True)
            total_size = int(req.headers.get('content-length', 0))
            block_size = 1024
            wrote = 0
            print(f"\n{cyan}[{red}*{cyan}]{white} Downloading signature database please wait...")
            with open(local_database, 'wb') as ff:
                for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                    wrote = wrote + len(data)
                    ff.write(data)
            print(f"{cyan}[{red}*{cyan}]{white} Extracting file...")
            command = f"unzip {local_database} &>/dev/null; if [ $? -eq 0 ];then rm -rf HashDB.zip; echo '{cyan}[{red}+{cyan}]{white} Database downloaded successfully.'; else echo '{cyan}[{red}!{cyan}]{white} Error occured!'; exit 1; fi"
            os.system(command)
            sys.exit(0)
        else:
            print(f"\n{cyan}[{red}ERROR{cyan}]{white} Without local database '{green}--hashScan{white}' will not work.\n")
            sys.exit(1)

# Hashing with md5
def GetHash(targetFile):
    hashMd5 = hashlib.md5()
    with open(targetFile, "rb") as ff:
        for chunk in iter(lambda: ff.read(4096), b""):
            hashMd5.update(chunk)
    return hashMd5.hexdigest()

try:
    databaseFile = open("HashDB.sha1", "r").read().split('\n')
except:
    DatabaseCheck()

# Total hash checking
tot = 0
for _ in databaseFile:
    tot += 1

# Hashing
targetHash = GetHash(targetFile)
hashMe = hashlib.sha1(targetHash.encode())
finalHash = hashMe.hexdigest()
    
# Info
print(f"{cyan}[{red}*{cyan}]{white} Total Hashes: {green}{tot}{white}")
print(f"{cyan}[{red}*{cyan}]{white} File Name: {green}{targetFile}{white}")
print(f"{cyan}[{red}*{cyan}]{white} File Signature: {green}{finalHash}{white}")

# Scanning
if finalHash in databaseFile:
    print(f"\n{cyan}[{red}DANGER{cyan}]{white}: Target file's hash is in our local database.")
    print(f"{cyan}[{red}Threat Level{cyan}]{white}: {red}Malicious{white}\n")
else:
    print(f"\n{cyan}[{red}Threat Level{cyan}]{white}: {yellow}Unknown{white}\n")
    print(f"{cyan}[{yellow}INFO{cyan}]{white} Try '{green}--analyze{white}' or '{green}--vtFile{white}' instead.\n")