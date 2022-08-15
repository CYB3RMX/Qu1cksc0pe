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

# Testing rich existence
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
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

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

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
parser.add_argument("--console", required=False,
                    help="Use Qu1cksc0pe on interactive shell.", action="store_true")
parser.add_argument("--db_update", required=False,
                    help="Update malware hash database.", action="store_true")
parser.add_argument("--docs", required=False, help="Analyze document files.",
                    action="store_true")
parser.add_argument("--domain", required=False,
                    help="Extract URLs and IP addresses from file.",
                    action="store_true")
parser.add_argument("--hashscan", required=False,
                    help="Scan target file's hash in local database.",
                    action="store_true")
parser.add_argument("--health", required=False,
                    help="Check for dependencies and configurations.",
                    action="store_true")
parser.add_argument("--install", required=False,
                    help="Install or Uninstall Qu1cksc0pe.", action="store_true")
parser.add_argument("--key_init", required=False,
                    help="Enter your VirusTotal API key.", action="store_true")
parser.add_argument("--lang", required=False,
                    help="Detect programming language.",
                    action="store_true")
parser.add_argument("--metadata", required=False,
                    help="Get exif/metadata information.",
                    action="store_true")
parser.add_argument("--mitre", required=False,
                    help="Generate MITRE ATT&CK table for target sample (Windows samples for now.).",
                    action="store_true")
parser.add_argument("--packer", required=False,
                    help="Check if your file is packed with common packers.",
                    action="store_true")
parser.add_argument("--resource", required=False,
                    help="Analyze resources in target file", action="store_true")
parser.add_argument("--report", required=False,
                    help="Export analysis reports into a file (JSON Format for now).", action="store_true")
parser.add_argument("--runtime", required=False,
                    help="Analyze APK files dynamically.", action="store_true")
parser.add_argument("--watch", required=False,
                    help="Perform emulation against executable files.", action="store_true")
parser.add_argument("--sigcheck", required=False,
                    help="Scan file signatures in target file.", action="store_true")
parser.add_argument("--vtFile", required=False,
                    help="Scan your file with VirusTotal API.",
                    action="store_true")
args = parser.parse_args()

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{infoS} Analyzing: [bold green]{analyzeFile}[white]")
    fileType = str(pr.magic_file(analyzeFile))
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{infoS} Target OS: [bold green]Windows[white]\n")
        if args.report:
            command = f"python3 {sc0pe_path}/Modules/winAnalyzer.py {analyzeFile} True"
        else:
            command = f"python3 {sc0pe_path}/Modules/winAnalyzer.py {analyzeFile} False"
        os.system(command)

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: [bold green]Linux[white]\n")
        if args.report:
            command = f"python3 {sc0pe_path}/Modules/linAnalyzer.py {analyzeFile} True"
        else:
            command = f"python3 {sc0pe_path}/Modules/linAnalyzer.py {analyzeFile} False"
        os.system(command)

    # MacOSX Analysis
    elif "Mach-O" in fileType:
        print(f"{infoS} Target OS: [bold green]OSX[white]\n")
        command = f"python3 {sc0pe_path}/Modules/osXAnalyzer.py {analyzeFile}"
        os.system(command)

    # Android Analysis
    elif "PK" in fileType and "Java archive" in fileType:
        look = pyaxmlparser.APK(analyzeFile)
        if look.is_valid_APK() == True:
            print(f"{infoS} Target OS: [bold green]Android[white]")
            command = f"apkid -j {args.file} > apkid.json"
            os.system(command)
            if args.report:
                command = f"python3 {sc0pe_path}/Modules/apkAnalyzer.py {analyzeFile} True"
            else:
                command = f"python3 {sc0pe_path}/Modules/apkAnalyzer.py {analyzeFile} False"
            os.system(command)
            if os.path.exists("apkid.json"):
                os.remove("apkid.json")
            # APP Security
            choice = str(input(f"\n{infoC} Do you want to check target app\'s security? This process will take a while.[Y/n]: "))
            if choice == "Y" or choice == "y":
                os.system(f"python3 {sc0pe_path}/Modules/apkSecCheck.py")
            else:
                pass
        else:
            print("\n[bold white on red]Qu1cksc0pe doesn\'t support archive analysis for now ;)\n")
            sys.exit(1)
    else:
        print("\n[bold white on red]File type not supported. Make sure you are analyze executable files or document files.")
        print("[bold]>>> If you want to scan document files try [bold green][i]--docs[/i] [white]argument.")
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
                print("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
                sys.exit(1)
        else:
            print("[bold white on red]Target file not found!\n")
            sys.exit(1)

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--analyze[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            command = f"python3 {sc0pe_path}/Modules/nonExecAnalyzer.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")
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
            print("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/resourceChecker.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--resource[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # metadata
    if args.metadata:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/metadata.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--metadata[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # MITRE ATT&CK
    if args.mitre:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/mitre.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--mitre[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/languageDetect.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--lang[/blink] argument is not supported for folder analyzing!\n")
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
                print("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
                sys.exit(1)
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                print("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
                sys.exit(1)
            else:
                command = f"python3 {sc0pe_path}/Modules/VTwrapper.py {apik[0]} {args.file}"
                os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")
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
            print("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Dynamic APK analyzer
    if args.runtime:
        command = f"python3 {sc0pe_path}/Modules/androidRuntime.py"
        os.system(command)

    # Strace
    if args.watch:
        # Handling --file argument
        if args.file is not None:
            command = f"python3 {sc0pe_path}/Modules/emulator.py {args.file}"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--watch[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Interactive shell
    if args.console:
        command = f"python3 {sc0pe_path}/Modules/console.py"
        os.system(command)

    # Dependency checker
    if args.health:
        command = f"python3 {sc0pe_path}/Modules/checkHealth.py"
        os.system(command)

    # Database update
    if args.db_update:
        command = f"python3 {sc0pe_path}/Modules/hashScanner.py --db_update"
        os.system(command)

    # entering VT API key
    if args.key_init:
        try:
            if os.path.exists(f"{homeD}/{username}/sc0pe_Base/"):
                pass
            else:
                os.system(f"mkdir {homeD}/{username}/sc0pe_Base/")

            apikey = str(input(f"{infoC} Enter your VirusTotal API key: "))
            apifile = open(f"{homeD}/{username}/sc0pe_Base/sc0pe_VT_apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated by user.\n")

    # Install Qu1cksc0pe on your system!!
    if args.install:
        print(f"{infoS} Checking permissions...")
        if os.getuid() == 0:
            print(f"{infoS} User: [bold green]root[white]\n")
            print(f"[bold cyan][[bold red]1[bold cyan]][white] Install Qu1cksc0pe.")
            print(f"[bold cyan][[bold red]2[bold cyan]][white] Uninstall Qu1cksc0pe")
            choose = int(input(f"\n{green}>>>>{white} "))
            if choose == 1:
                print(f"\n{infoS} Looks like we have permission to install. Let\'s begin...")

                # Installing python dependencies...
                print(f"{infoS} Installing Python dependencies...")
                os.system("pip3 install -r requirements.txt")

                # Configurating Qu1cksc0pe's config file
                print(f"{infoS} Creating configuration file in [bold green]/etc[white] directory")
                conFile = configparser.ConfigParser()
                conFile["Qu1cksc0pe_PATH"] = {"sc0pe": "/opt/Qu1cksc0pe"}
                with open (f"/etc/qu1cksc0pe.conf", "w") as cfile:
                    conFile.write(cfile)
                os.system(f"chown {username}:{username} /etc/qu1cksc0pe.conf")

                # Copying Qu1cksc0pe's to /opt directory
                print(f"{infoS} Copying files to [bold green]/opt[white] directory.")
                os.system("cd ../ && cp -r Qu1cksc0pe /opt/")
                os.system(f"chown {username}:{username} /opt/Qu1cksc0pe")

                # Configurating ApkAnalyzer module's config file
                print(f"{infoS} Configurating [bold green]libScanner.conf[white] file.")
                libscan = configparser.ConfigParser()
                libscan.read("/opt/Qu1cksc0pe/Systems/Android/libScanner.conf")
                libscan["Rule_PATH"]["rulepath"] = f"/opt/Qu1cksc0pe/Systems/Android/YaraRules/"
                with open("/opt/Qu1cksc0pe/Systems/Android/libScanner.conf", "w") as ff:
                    libscan.write(ff)

                # Copying qu1cksc0pe.py file into /usr/bin/
                print(f"{infoS} Copying [bold green]qu1cksc0pe.py[white] to [bold green]/usr/bin/[white] directory.")
                os.system("cp qu1cksc0pe.py /usr/bin/qu1cksc0pe && chmod +x /usr/bin/qu1cksc0pe")
                print(f"{infoS} Installation completed.")
            elif choose == 2:
                print(f"\n{infoS} Looks like we have permission to uninstall. Let\'s begin...")
                print(f"{infoS} Removing [bold green]/usr/bin/qu1cksc0pe[white] file.")
                os.system("rm -rf /usr/bin/qu1cksc0pe")
                print(f"{infoS} Removing [bold green]/etc/qu1cksc0pe.conf[white] file.")
                os.system("rm -rf /etc/qu1cksc0pe.conf")
                print(f"{infoS} Removing [bold green]/opt/Qu1cksc0pe[white] directory.")
                os.system("rm -rf /opt/Qu1cksc0pe")
                print(f"{infoS} Uninstallation completed.")
            else:
                print("\n[bold white on red]Wrong option. Quitting!!\n")
                sys.exit(1)
        else:
            print("\n[bold white on red]Please use this argument as [blink]root[/blink]!!\n")
            sys.exit(1)

# Exectuion area
try:
    Qu1cksc0pe()
    # Cleaning up...
    junkFiles = ["temp.txt", ".path_handler", ".target-file.txt", ".target-folder.txt"]
    for junk in junkFiles:
        if os.path.exists(junk):
            os.remove(junk)

    if os.path.exists("TargetAPK/"):
        os.system("rm -rf TargetAPK/")

except:
    junkFiles = ["temp.txt", ".path_handler", ".target-file.txt", ".target-folder.txt"]
    for junk in junkFiles:
        if os.path.exists(junk):
            os.remove(junk)

    if os.path.exists("TargetAPK/"):
        os.system("rm -rf TargetAPK/")
