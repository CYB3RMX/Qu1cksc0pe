#!/usr/bin/env python3

# module checking
try:
    import os
    import sys
    import argparse
    import getpass
    import configparser
except:
    print("Missing modules detected!")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

# Testing pyaxmlparser existence
try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Testing colorama existence
try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

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

# Gathering username
username = getpass.getuser()

# Is Qu1cksc0pe installed??
if os.path.exists("/usr/bin/qu1cksc0pe") == True and os.path.exists(f"/etc/qu1cksc0pe.conf") == True:
    # Parsing new path and write into handler
    sc0peConf = configparser.ConfigParser()
    sc0peConf.read(f"/etc/qu1cksc0pe.conf")
    sc0pe_path = str(sc0peConf["Qu1cksc0pe_PATH"]["sc0pe"])
    path_handler = open(".path_handler", "w")
    path_handler.write(sc0pe_path)
    path_handler.close()
else:
    # Parsing current path and write into handler
    sc0pe_path = str(os.getcwd())
    path_handler = open(".path_handler", "w")
    path_handler.write(sc0pe_path)
    path_handler.close()
    libscan = configparser.ConfigParser()

    # Parsing android libscanner configuration file
    libscan.read("Systems/Android/libScanner.conf")
    libscan["Rule_PATH"]["rulepath"] = f"{sc0pe_path}/Systems/Android/YaraRules/"
    with open("Systems/Android/libScanner.conf", "w") as ff:
        libscan.write(ff)

# Banner
os.system(f"python3 {sc0pe_path}/Modules/banners.py")

# User home detection
homeD = "/home"
if sys.platform == "darwin":
    homeD = "/Users"

# Argument crating, parsing and handling
args = []
parser = argparse.ArgumentParser()
parser.add_argument("--file", required=False,
                    help="Specify a file to scan or analyze.")
parser.add_argument("--folder", required=False,
                    help="Specify a folder to scan or analyze.")
parser.add_argument("--analyze", required=False,
                    help="Analyze target file.", action="store_true")
parser.add_argument("--docs", required=False, help="Analyze document files.",
                    action="store_true")
parser.add_argument("--runtime", required=False,
                    help="Analyze APK files dynamically.", action="store_true")
parser.add_argument("--hashscan", required=False,
                    help="Scan target file's hash in local database.",
                    action="store_true")
parser.add_argument("--resource", required=False,
                    help="Analyze resources in target file", action="store_true")
parser.add_argument("--sigcheck", required=False,
                    help="Scan file signatures in target file.", action="store_true")
parser.add_argument("--vtFile", required=False,
                    help="Scan your file with VirusTotal API.",
                    action="store_true")
parser.add_argument("--lang", required=False,
                    help="Detect programming language.",
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
parser.add_argument("--console", required=False,
                    help="Use Qu1cksc0pe on interactive shell.", action="store_true")
parser.add_argument("--install", required=False,
                    help="Install or Uninstall Qu1cksc0pe.", action="store_true")
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
        command = f"python3 {sc0pe_path}/Modules/winAnalyzer.py {analyzeFile}"
        os.system(command)

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: {green}Linux{white}\n")
        command = f"readelf -a {analyzeFile} > elves.txt"
        os.system(command)
        command = f"python3 {sc0pe_path}/Modules/linAnalyzer.py {analyzeFile}"
        os.system(command)

    # MacOSX Analysis
    elif "Mach-O" in fileType:
        print(f"{infoS} Target OS: {green}OSX{white}\n")
        command = f"python3 {sc0pe_path}/Modules/osXAnalyzer.py {analyzeFile}"
        os.system(command)

    # Android Analysis
    elif "PK" in fileType and "Java archive" in fileType:
        look = pyaxmlparser.APK(analyzeFile)
        if look.is_valid_APK() == True:
            print(f"{infoS} Target OS: {green}Android{white}")
            command = f"apkid -j {args.file} > apkid.json"
            os.system(command)
            command = f"python3 {sc0pe_path}/Modules/apkAnalyzer.py {analyzeFile}"
            os.system(command)
            if os.path.exists("apkid.json"):
                os.remove("apkid.json")
            # APP Security
            choice = str(input(f"\n{infoS} Do you want to check target app\'s security? This process will take a while.[Y/n]: "))
            if choice == "Y" or choice == "y":
                os.system(f"python3 {sc0pe_path}/Modules/apkSecCheck.py")
            else:
                pass
        else:
            print(f"{errorS} Qu1cksc0pe doesn\'t support archive analysis for now ;)")
            sys.exit(1)
    else:
        print(f"{errorS} File type not supported. Make sure you are analyze executable files or document files.")
        print(f"{errorS} If you want to scan document files try {green}--docs{white} argument.")
        sys.exit(1)

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            if os.path.exists("/usr/bin/strings"):
                allA = "--all"
                if sys.platform == "darwin":
                    allA = "-a"
                command = f"strings {allA} {args.file} > temp.txt"
                os.system(command)
            else:
                print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                sys.exit(1)
        else:
            print(f"{errorS} Target file not found.\n")
            sys.exit(1)

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--analyze{white} argument is not supported for folder analyzing.")
            sys.exit(1)

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: {green}{args.file}{white}")
            command = f"python3 {sc0pe_path}/Modules/nonExecAnalyzer.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--docs{white} argument is not supported for folder analysis.")
            sys.exit(1)

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/hashScanner.py {args.file} --normal"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"python3 {sc0pe_path}/Modules/hashScanner.py {args.folder} --multiscan"
            os.system(command)

    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/sigChecker.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--sigcheck{white} argument is not supported for folder analyzing.")
            sys.exit(1)

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/resourceChecker.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--resource{white} argument is not supported for folder analyzing.")
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

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/languageDetect.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} {green}--lang{white} argument is not supported for folder analyzing.")
            sys.exit(1)

    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = f"{homeD}/{username}/sc0pe_Base/sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                print(f"{errorS} Use --key_init to enter your key.")
                sys.exit(1)
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                print(f"{errorS} Please get your API key from -> {green}https://www.virustotal.com/{white}")
                sys.exit(1)
            else:
                command = f"python3 {sc0pe_path}/Modules/VTwrapper.py {apik[0]} {args.file}"
                os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} If you want to get banned from VirusTotal then do that :).")
            sys.exit(1)

    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/packerAnalyzer.py {args.file} --single"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"python3 {sc0pe_path}/Modules/packerAnalyzer.py {args.folder} --multiscan"
            os.system(command)

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/domainCatcher.py"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print(f"{errorS} That argument has not supported for folder scanning.")
            sys.exit(1)

    # Dynamic APK analyzer
    if args.runtime:
        command = f"python3 {sc0pe_path}/Modules/androidRuntime.py"
        os.system(command)

    # Interactive shell
    if args.console:
        command = f"python3 {sc0pe_path}/Modules/console.py"
        os.system(command)

    # entering VT API key
    if args.key_init:
        try:
            if os.path.exists(f"{homeD}/{username}/sc0pe_Base/"):
                pass
            else:
                os.system(f"mkdir {homeD}/{username}/sc0pe_Base/")

            apikey = str(input(f"{foundS} Enter your VirusTotal API key: "))
            apifile = open(f"{homeD}/{username}/sc0pe_Base/sc0pe_VT_apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print(f"{errorS} Program terminated by user.")

    # Install Qu1cksc0pe on your system!!
    if args.install:
        print(f"{infoS} Checking permissions...")
        if os.getuid() == 0:
            print(f"{infoS} User: {green}root{white}\n")
            print(f"{cyan}[{red}1{cyan}]{white} Install Qu1cksc0pe.")
            print(f"{cyan}[{red}2{cyan}]{white} Uninstall Qu1cksc0pe")
            choose = int(input(f"\n{green}>>>>{white} "))
            if choose == 1:
                print(f"\n{infoS} Looks like we have permission to install. Let\'s begin...")

                # Configurating Qu1cksc0pe's config file
                print(f"{infoS} Creating configuration file in {green}/etc{white} directory")
                conFile = configparser.ConfigParser()
                conFile["Qu1cksc0pe_PATH"] = {"sc0pe": "/opt/Qu1cksc0pe"}
                with open (f"/etc/qu1cksc0pe.conf", "w") as cfile:
                    conFile.write(cfile)
                os.system(f"chown {username}:{username} /etc/qu1cksc0pe.conf")

                # Copying Qu1cksc0pe's to /opt directory
                print(f"{infoS} Copying files to {green}/opt{white} directory.")
                os.system("cd ../ && cp -r Qu1cksc0pe /opt/")
                os.system(f"chown {username}:{username} /opt/Qu1cksc0pe")

                # Configurating ApkAnalyzer module's config file
                print(f"{infoS} Configurating {green}libScanner.conf{white} file.")
                libscan = configparser.ConfigParser()
                libscan.read("/opt/Qu1cksc0pe/Systems/Android/libScanner.conf")
                libscan["Rule_PATH"]["rulepath"] = f"/opt/Qu1cksc0pe/Systems/Android/YaraRules/"
                with open("/opt/Qu1cksc0pe/Systems/Android/libScanner.conf", "w") as ff:
                    libscan.write(ff)

                # Copying qu1cksc0pe.py file into /usr/bin/
                print(f"{infoS} Copying {green}qu1cksc0pe.py{white} to {green}/usr/bin/{white} directory.")
                os.system("cp qu1cksc0pe.py /usr/bin/qu1cksc0pe && chmod +x /usr/bin/qu1cksc0pe")
                print(f"{infoS} Installation completed.")
            elif choose == 2:
                print(f"\n{infoS} Looks like we have permission to uninstall. Let\'s begin...")
                print(f"{infoS} Removing {green}/usr/bin/qu1cksc0pe{white} file.")
                os.system("rm -rf /usr/bin/qu1cksc0pe")
                print(f"{infoS} Removing {green}/etc/qu1cksc0pe.conf{white} file.")
                os.system("rm -rf /etc/qu1cksc0pe.conf")
                print(f"{infoS} Removing {green}/opt/Qu1cksc0pe{white} directory.")
                os.system("rm -rf /opt/Qu1cksc0pe")
                print(f"{infoS} Uninstallation completed.")
            else:
                print(f"\n{errorS} Wrong option. Quitting!!")
                sys.exit(1)
        else:
            print(f"{errorS} Please use this argument as {green}root{white}")
            sys.exit(1)

# Exectuion area
try:
    Qu1cksc0pe()
    # Cleaning up...
    junkFiles = ["temp.txt", ".path_handler", "elves.txt", ".target-file.txt", ".target-folder.txt"]
    for junk in junkFiles:
        if os.path.exists(junk):
            os.remove(junk)

    if os.path.exists("TargetAPK/"):
        os.system("rm -rf TargetAPK/")
except:
    junkFiles = ["temp.txt", ".path_handler", "elves.txt", ".target-file.txt", ".target-folder.txt"]
    for junk in junkFiles:
        if os.path.exists(junk):
            os.remove(junk)

    if os.path.exists("TargetAPK/"):
        os.system("rm -rf TargetAPK/")
