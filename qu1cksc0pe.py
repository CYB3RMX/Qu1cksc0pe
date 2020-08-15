#!/usr/bin/env python3

# module checking
try:
    import os,sys,argparse
except:
    print("Missing modules detected!")
    sys.exit(1)
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Colors
red = '\u001b[1;91m'
cyan = '\u001b[1;96m'
white = '\u001b[0m'
green = '\u001b[1;92m'
yellow = '\u001b[1;93m'

# handling arguments
args = []

def scope():
    # Argument crating and parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("--file",required=False,help="Select a suspicious file.")
    parser.add_argument("--analyze",required=False,help="Analyze target file.",action="store_true")
    parser.add_argument("--vtFile",required=False,help="Scan your file with VirusTotal API.",action="store_true")
    parser.add_argument("--vtUrl",required=False,help="Scan your URL with VirusTotal API.",action="store_true")
    parser.add_argument("--metadata",required=False,help="Get exif/metadata information.",action="store_true")
    parser.add_argument("--domain",required=False,help="Extract URLs and IP addresses from file.",action="store_true")
    parser.add_argument("--packer",required=False,help="Check if your file is packed with common packers.",action="store_true")
    parser.add_argument("--key_init",required=False,help="Enter your VirusTotal API key.",action="store_true")
    parser.add_argument("--update",required=False,help="Check for updates.",action="store_true")
    args = parser.parse_args()

    # Getting all strings from the file
    if args.file:
        command = "strings -a {} > temp.txt".format(args.file)
        os.system(command)
    
    # Analyze the target file
    if args.analyze:
        print(f"{cyan}[{red}*{cyan}]{white} Analyzing: {green}{args.file}{white}")
        fileType = str(pr.magic_file(args.file))
        if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
            print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Windows{white}\n")
            command = "./Modules/winAnalyzer.py {}".format(args.file)
            os.system(command)
        elif "ELF" in fileType:
            print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Linux\n{white}")
            command = "readelf -a {} > Modules/elves.txt".format(args.file)
            os.system(command)
            command = "./Modules/elfAnalyzer.py {}".format(args.file)
            os.system(command)
        elif "PK" in fileType:
            print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Android\n{white}")
            command = "./Modules/apkAnalyzer.py {}".format(args.file)
            os.system(command)
        else:
            print(f"{cyan}[{red}!{cyan}]{white} Target OS could not identified. Make sure your file extension is Windows(exe,dll,msi),Linux(ELF) or Android(APK)")
            sys.exit(1)

    # metadata
    if args.metadata:
        print(f"{cyan}[{red}+{cyan}]{white} Exif/Metadata information")
        command = "exiftool {}".format(args.file)
        print("+","-"*50,"+")
        os.system(command)
        print("+","-"*50,"+")

    # VT File scanner
    if args.vtFile:

        # if there is no key quit
        try:
            directory = "Modules/.apikey.txt"
            apik = open(directory, "r").read().split("\n")
        except:
            print(f"{cyan}[{red}!{cyan}]{white} Use --key_init to enter your key.")
            sys.exit(1)

        # if key is not valid quit
        if apik[0] == '' or apik[0] == None or len(apik[0]) != 64:
            print(f"{cyan}[{red}!{cyan}]{white} Please get your API key from -> {green}https://www.virustotal.com/{white}")
            sys.exit(1)
        else: 
            print(f"\n{cyan}[{red}+{cyan}]{white} VirusTotal Scan")
            print("+","-"*50,"+")
            command = "./Modules/VTwrapper.py {} --vtFile {}".format(apik[0],args.file)
            os.system(command)
            print("+","-"*50,"+")

    # VT URL scanner
    if args.vtUrl:

        # if there is no key quit
        try:
            directory = "Modules/.apikey.txt"
            apik = open(directory, "r").read().split("\n")
        except:
            print(f"{cyan}[{red}!{cyan}]{white} Use --key_init to enter your key.")
            sys.exit(1)

        # if key is not valid quit
        if apik[0] == '' or apik[0] == None or len(apik[0]) != 64:
            print(f"{cyan}[{red}!{cyan}]{white} Please get your API key from -> {green}https://www.virustotal.com/{white}")
            sys.exit(1)
        else:
            print(f"\n{cyan}[{red}+{cyan}]{white} VirusTotal Scan")
            print("+","-"*50,"+")
            command = "./Modules/VTwrapper.py {} --vtUrl".format(apik[0])
            os.system(command)
            print("+","-"*50,"+")

    # packer detection
    if args.packer:
        print(f"{cyan}[{red}*{cyan}]{white} Looking for packers...")
        command = "./Modules/packerAnalyzer.py {}".format(args.file)
        os.system(command)
        
    # domain extraction
    if args.domain:
        command = "./Modules/domainCatcher.sh {}".format(args.file)
        os.system(command)

    # entering VT API key
    if args.key_init:
        apikey = str(input(f"{cyan}[{red}+{cyan}]{white} Enter your VirusTotal API key: "))
        command = "echo '{}' > Modules/.apikey.txt".format(apikey)
        os.system(command)
        print(f"{cyan}[{red}+{cyan}]{white} Your VirusTotal API key saved.")

    # Update checking
    if args.update:
        command = "./Modules/updateCheck.sh"
        os.system(command)

# Exectuion area
os.system("./Modules/banners.sh")
try:
    scope()
    os.system("if [ -e temp.txt ];then rm -f temp.txt; fi")
except:
    os.system("if [ -e temp.txt ];then rm -f temp.txt; fi")
