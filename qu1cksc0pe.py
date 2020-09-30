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

# Banner
os.system("./Modules/banners.sh")

# Argument crating, parsing and handling
args = []
parser = argparse.ArgumentParser()
parser.add_argument("--file",required=False,help="Select a suspicious file.")
parser.add_argument("--analyze",required=False,help="Analyze target file.",action="store_true")
parser.add_argument("--multiple",required=False, nargs='+', help="Analyze multiple files.")
parser.add_argument("--hashScan",required=False,help="Scan target file's hash in local database.",action="store_true")
parser.add_argument("--vtFile",required=False,help="Scan your file with VirusTotal API.",action="store_true")
parser.add_argument("--vtUrl",required=False,help="Scan your URL with VirusTotal API.",action="store_true")
parser.add_argument("--metadata",required=False,help="Get exif/metadata information.",action="store_true")
parser.add_argument("--domain",required=False,help="Extract URLs and IP addresses from file.",action="store_true")
parser.add_argument("--packer",required=False,help="Check if your file is packed with common packers.",action="store_true")
parser.add_argument("--key_init",required=False,help="Enter your VirusTotal API key.",action="store_true")
parser.add_argument("--update",required=False,help="Check for updates.",action="store_true")
args = parser.parse_args()

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{cyan}[{red}*{cyan}]{white} Analyzing: {green}{analyzeFile}{white}")
    fileType = str(pr.magic_file(analyzeFile))
    
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Windows{white}\n")
        command = "./Modules/winAnalyzer.py {}".format(analyzeFile)
        os.system(command)
    
    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Linux{white}\n")
        command = "readelf -a {} > Modules/elves.txt".format(analyzeFile)
        os.system(command)
        command = "./Modules/linAnalyzer.py {}".format(analyzeFile)
        os.system(command)
    
    # MacOSX Analysis
    elif "Mach-O" in fileType:
        print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}OSX{white}\n")
        command = "./Modules/osXAnalyzer.py {}".format(analyzeFile)
        os.system(command)
    
    # Android Analysis
    elif "PK" in fileType:
        print(f"{cyan}[{red}*{cyan}]{white} Target OS: {green}Android\n{white}")
        command = "./Modules/apkAnalyzer.py {}".format(analyzeFile)
        os.system(command)
    else:
        print(f"{cyan}[{red}!{cyan}]{white} Target OS could not identified. Make sure your file is an correct executable.")
        sys.exit(1)

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file
    if args.file:
        command = f"if [ -e {args.file} ];then strings --all {args.file} > temp.txt; else echo 'Error: Target file not found!'; exit 1;  fi"
        os.system(command)

    # Analyze the target file
    if args.analyze:
        BasicAnalyzer(analyzeFile=args.file)
    
    # Multiple file analysis
    if args.multiple:
        try:
            listOfFiles = list(args.multiple)
            for oneFile in listOfFiles:
                if oneFile != '':
                    command = f"if [ -e {oneFile} ];then strings --all {oneFile} > temp.txt; else echo 'Target file: {oneFile} not found!'; exit 1;  fi"
                    os.system(command)
                    BasicAnalyzer(analyzeFile=oneFile)
                    print("+","*"*40,"+\n")
                else:
                    continue
        except:
            print(f"{cyan}[{red}!{cyan}]{white} An error occured while parsing the files.")
            sys.exit(1)
    
    # Hash Scanning
    if args.hashScan:
        command = f"if [ -e {args.file} ];then ./Modules/hashScanner.py {args.file}; else echo 'Target file: {args.file} not found!'; exit 1; fi"
        os.system(command)

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
try:
    Qu1cksc0pe()
    os.system("if [ -e temp.txt ];then rm -f temp.txt; fi")
except:
    os.system("if [ -e temp.txt ];then rm -f temp.txt; fi")