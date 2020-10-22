#!/usr/bin/env python3

# module checking
try:
    import os
    import sys
    import argparse
except:
    print("Missing modules detected!")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Testing colorama existence
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

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Banner
os.system("./Modules/banners.py")

# Argument crating, parsing and handling
args = []
parser = argparse.ArgumentParser()
parser.add_argument("--file", required=False,
                    help="Specify a file to scan or analyze.")
parser.add_argument("--folder", required=False,
                    help="Specify a folder to scan or analyze.")
parser.add_argument("--analyze", required=False,
                    help="Analyze target file.", action="store_true")
parser.add_argument("--multiple", required=False, nargs='+',
                    help="Analyze multiple files.")
parser.add_argument("--hashscan", required=False,
                    help="Scan target file's hash in local database.",
                    action="store_true")
parser.add_argument("--multihash", required=False, nargs='+',
                    help="Scan multiple file's hashes in local database.")
parser.add_argument("--vtFile", required=False,
                    help="Scan your file with VirusTotal API.",
                    action="store_true")
parser.add_argument("--vtUrl", required=False,
                    help="Scan your URL with VirusTotal API.",
                    action="store_true")
parser.add_argument("--metadata", required=False,
                    help="Get exif/metadata information.",
                    action="store_true")
parser.add_argument("--domain", required=False,
                    help="Extract URLs and IP addresses from file.",
                    action="store_true")
parser.add_argument("--packer", required=False,
                    help="Check if your file is packed with common packers.",
                    action="store_true")
parser.add_argument("--key_init", required=False,
                    help="Enter your VirusTotal API key.", action="store_true")
args = parser.parse_args()

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{infoS} Analyzing: {green}{analyzeFile}{white}")
    fileType = str(pr.magic_file(analyzeFile))
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{infoS} Target OS: {green}Windows{white}\n")
        command = f"python3 Modules/winAnalyzer.py {analyzeFile}"
        os.system(command)
    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: {green}Linux{white}\n")
        command = f"readelf -a {analyzeFile} > Modules/elves.txt"
        os.system(command)
        command = f"python3 Modules/linAnalyzer.py {analyzeFile}"
        os.system(command)
    # MacOSX Analysis
    elif "Mach-O" in fileType:
        print(f"{infoS} Target OS: {green}OSX{white}\n")
        command = f"python3 Modules/osXAnalyzer.py {analyzeFile}"
        os.system(command)
    # Android Analysis
    elif "PK" in fileType or "Android" in fileType:
        print(f"{infoS} Target OS: {green}Android{white}\n")
        command = f"python3 Modules/apkAnalyzer.py {analyzeFile}"
        os.system(command)
    else:
        print(f"{infoS} File Type: {green}Non Executable{white}\n")
        command = f"python3 Modules/nonExecAnalyzer.py {analyzeFile}"
        os.system(command)

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file
    if args.file:
        command = f"strings --all {args.file} > temp.txt"
        os.system(command)
    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--analyze{white} argument is not supported for folder analyzing.")
            sys.exit(1)
    # Multiple file analysis
    if args.multiple:
        try:
            listOfFiles = list(args.multiple)
            for oneFile in listOfFiles:
                if oneFile != '':
                    command = f"strings --all {oneFile} > temp.txt"
                    os.system(command)
                    BasicAnalyzer(analyzeFile=oneFile)
                    print("+", "*"*40, "+\n")
                else:
                    continue
        except:
            print(f"{errorS} An error occured while parsing the files.")
            sys.exit(1)
    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 Modules/hashScanner.py {args.file} --normal"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"python3 Modules/hashScanner.py {args.folder} --multiscan"
            os.system(command)
    # Multi hash scanning
    if args.multihash:
        try:
            listOfFiles = list(args.multihash)
            for oneFile in listOfFiles:
                if oneFile != '':
                    command = f"python3 Modules/hashScanner.py {oneFile} --normal"
                    os.system(command)
                else:
                    continue
        except:
            print(f"{errorS} An error occured while parsing the files.")
            sys.exit(1)
    # metadata
    if args.metadata:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Exif/Metadata information")
            command = f"exiftool {args.file}"
            print("+", "-"*50, "+")
            os.system(command)
            print("+", "-"*50, "+")
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} That argument has not supported for folder scanning.")
            sys.exit(1)
    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = "Modules/.apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                print(f"{errorS} Use --key_init to enter your key.")
                sys.exit(1)
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                print(f"{errorS} Please get your API key from -> {green}https://www.virustotal.com/{white}")
                sys.exit(1)
            else:
                print(f"\n{infoS} VirusTotal Scan")
                print("+", "-"*50, "+")
                command = f"python3 Modules/VTwrapper.py {apik[0]} --vtFile {args.file}"
                os.system(command)
                print("+", "-"*50, "+")
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} If you want to get banned from VirusTotal then do that :).")
            sys.exit(1)
    # VT URL scanner
    if args.vtUrl:
        # if there is no key quit
        try:
            directory = "Modules/.apikey.txt"
            apik = open(directory, "r").read().split("\n")
        except:
            print(f"{errorS} Use --key_init to enter your key.")
            sys.exit(1)
        # if key is not valid quit
        if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
            print(f"{errorS} Please get your API key from -> {green}https://www.virustotal.com/{white}")
            sys.exit(1)
        else:
            print(f"\n{infoS} VirusTotal Scan")
            print("+", "-"*50, "+")
            command = f"python3 Modules/VTwrapper.py {apik[0]} --vtUrl"
            os.system(command)
            print("+", "-"*50, "+")
    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 Modules/packerAnalyzer.py {args.file} --single"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"python3 Modules/packerAnalyzer.py {args.folder} --multiscan"
            os.system(command)
    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            command = "python3 Modules/domainCatcher.py"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} That argument has not supported for folder scanning.")
            sys.exit(1)
    # entering VT API key
    if args.key_init:
        try:
            apikey = str(input(f"{foundS} Enter your VirusTotal API key: "))
            apifile = open("Modules/.apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print(f"{errorS} Program terminated by user.")
# Exectuion area
try:
    Qu1cksc0pe()
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")
except:
    if os.path.exists("temp.txt"):
        os.remove("temp.txt")