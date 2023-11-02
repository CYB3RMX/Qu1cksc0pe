#!/usr/bin/env python3

# module checking
try:
    import os
    import sys
    import argparse
    import getpass
    import configparser
    import subprocess
    import distutils.spawn
except:
    print("Missing modules detected!")
    sys.exit(1)

# Check python version
if sys.version_info[0] == 2:
    print(f"{errorS} Looks like you are using Python 2. But we need Python 3!")
    sys.exit(1)

# Testing rich existence
try:
    from rich import print
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

# Get python binary
if distutils.spawn.find_executable("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Make Qu1cksc0pe work on Windows, Linux, OSX
homeD = os.path.expanduser("~")
py_version = sys.version_info[1]
path_seperator = "/"
allA = "--all" # strings parameter
sc0pe_helper_path = "/usr/lib/python3/dist-packages/sc0pe_helper.py"
setup_scr = "setup.sh"
if sys.platform == "darwin":
    allA = "-a"
elif sys.platform == "win32":
    path_seperator = "\\"
    allA = "-a"
    sc0pe_helper_path = f"{homeD}\\appdata\\local\\programs\\python\\python3{py_version}\\lib\\site-packages\\sc0pe_helper.py"
    setup_scr = "setup.ps1"
else:
    pass

# Is Qu1cksc0pe installed??
if os.name != "nt":
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
else:
    sc0pe_path = str(os.getcwd())
    path_handler = open(".path_handler", "w")
    path_handler.write(sc0pe_path)
    path_handler.close()
    libscan = configparser.ConfigParser()

# Using helper library
if os.path.exists(sc0pe_helper_path):
    from sc0pe_helper import Sc0peHelper
    sc0pehelper = Sc0peHelper(sc0pe_path)
else:
    print(f"{errorS} [bold green]sc0pe_helper[white] library not installed. You need to execute [bold green]{setup_scr}[white] script!")
    sys.exit(1)

# Banner
os.system(f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}banners.py")

# Argument crating, parsing and handling
parser = argparse.ArgumentParser()
parser.add_argument("--file", required=False,
                    help="Specify a file to scan or analyze.")
parser.add_argument("--folder", required=False,
                    help="Specify a folder to scan or analyze.")
parser.add_argument("--analyze", required=False,
                    help="Analyze target file.", action="store_true")
parser.add_argument("--archive", required=False, help="Analyze archive files.",
                    action="store_true")
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
parser.add_argument("--setup_venv", required=False,
                    help="Setup Python virtual environment automatically.", action="store_true")
parser.add_argument("--install", required=False,
                    help="Install or Uninstall Qu1cksc0pe.", action="store_true")
parser.add_argument("--key_init", required=False,
                    help="Enter your VirusTotal API key.", action="store_true")
parser.add_argument("--lang", required=False,
                    help="Detect programming language.",
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
parser.add_argument("--watch", required=False,
                    help="Perform dynamic analysis against Windows/Android files. (Linux will coming soon!!)", action="store_true")
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
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}winAnalyzer.py \"{analyzeFile}\" True"
        else:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}winAnalyzer.py \"{analyzeFile}\" False"
        os.system(command)

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: [bold green]Linux[white]\n")
        if args.report:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}linAnalyzer.py \"{analyzeFile}\" True"
        else:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}linAnalyzer.py \"{analyzeFile}\" False"
        os.system(command)

    # MacOSX Analysis
    elif "Mach-O" in fileType:
        print(f"{infoS} Target OS: [bold green]OSX[white]\n")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}osXAnalyzer.py \"{analyzeFile}\""
        os.system(command)

    # Android Analysis
    elif "PK" in fileType and "Java archive" in fileType:

        # If given file is an valid APK file then run APK analysis
        try:
            look = pyaxmlparser.APK(analyzeFile)
        except:
            print(f"{errorS} An error occured while parsing the file. Maybe [bold green]AndroidManifest.xml[white] is corrupted?")
            sys.exit(1)

        if look.is_valid_APK() == True:
            print(f"{infoS} Target OS: [bold green]Android[white]")
            if args.report:
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}apkAnalyzer.py \"{analyzeFile}\" True APK"
            else:
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}apkAnalyzer.py \"{analyzeFile}\" False APK"
            os.system(command)
            # APP Security
            choice = str(input(f"\n{infoC} Do you want to check target app\'s security? This process will take a while.[Y/n]: "))
            if choice == "Y" or choice == "y":
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}apkSecCheck.py"
                os.system(command)
            else:
                pass
        else:
            # If given file is a JAR file then run JAR file analysis
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}apkAnalyzer.py \"{analyzeFile}\" False JAR"
            os.system(command)

    # Pcap analysis
    elif "pcap" in fileType or "capture file" in fileType:
        print(f"{infoS} Performing [bold green]PCAP[while] analysis...\n")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}pcap_analyzer.py \"{analyzeFile}\""
        os.system(command)

    # Powershell analysis
    elif ".ps1" in analyzeFile:
        print(f"{infoS} Performing [bold green]Powershell Script[white] analysis...\n")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}powershell_analyzer.py \"{analyzeFile}\""
        os.system(command)

    # Email file analysis
    elif "email message" in fileType or "message/rfc822" in fileType:
        print(f"{infoS} Performing [bold green]Email File[white] analysis...\n")
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}email_analyzer.py \"{analyzeFile}\""
        os.system(command)
    else:
        print("\n[bold white on red]File type not supported. Make sure you are analyze executable files or document files.")
        print("[bold]>>> If you want to scan document files try [bold green][i]--docs[/i] [white]argument.")
        sys.exit(1)

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            # Before doing something we need to check file size
            file_size = os.path.getsize(args.file)
            if file_size < 52428800: # If given file smaller than 100MB
                if distutils.spawn.find_executable("strings"):
                    str_proc = subprocess.run(f"strings {allA} \"{args.file}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
                    if sys.platform != "win32":
                        str_proc = subprocess.run(f"strings {allA} -e l {args.file} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
                else:
                    print("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
                    sys.exit(1)
            else:
                print(f"{infoS} Whoa!! Looks like we have a large file here.")
                if args.archive:
                    # Because why not!
                    print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
                    command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}archiveAnalyzer.py \"{args.file}\""
                    os.system(command)
                    sys.exit(0)

                # Check for embedded executables by default!
                if not args.sigcheck:
                    print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] module...")
                    command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{args.file}\""
                    os.system(command)
                    sys.exit(0)
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

    # Analyze archive files
    if args.archive:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}archiveAnalyzer.py \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}document_analyzer.py \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}hashScanner.py \"{args.file}\" --normal"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}hashScanner.py {args.folder} --multiscan"
            os.system(command)

    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}resourceChecker.py \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--resource[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # MITRE ATT&CK
    if args.mitre:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}mitre.py \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--mitre[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}languageDetect.py \"{args.file}\""
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
                directory = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                print("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
                sys.exit(1)
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                print("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
                sys.exit(1)
            else:
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}VTwrapper.py {apik[0]} \"{args.file}\""
                os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")
            sys.exit(1)

    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}packerAnalyzer.py --single \"{args.file}\""
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}packerAnalyzer.py --multiscan {args.folder}"
            os.system(command)

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}domainCatcher.py"
            os.system(command)
        # Handling --folder argument
        if args.folder is not None:
            print("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")
            sys.exit(1)

    # Dynamic analysis
    if args.watch:
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}emulator.py"
        os.system(command)

    # Interactive shell
    if args.console:
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}console.py"
        os.system(command)

    # Virtual environment setup
    if args.setup_venv:
        sc0pehelper.setup_virtual_environment()

    # Database update
    if args.db_update:
        command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}hashScanner.py --db_update"
        os.system(command)

    # entering VT API key
    if args.key_init:
        try:
            if os.path.exists(f"{homeD}{path_seperator}sc0pe_Base"):
                pass
            else:
                os.system(f"mkdir {homeD}{path_seperator}sc0pe_Base")

            apikey = str(input(f"{infoC} Enter your VirusTotal API key: "))
            apifile = open(f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated by user.\n")

    # Install Qu1cksc0pe on your system!!
    if args.install:
        if sys.platform == "win32":
            print(f"{errorS} This feature is not suitable for Windows systems for now!")
            sys.exit(1)

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

                # Copying sc0pe_helper module to /usr/lib/python3/dist-packages/
                print(f"{infoS} Copying [bold green]sc0pe_helper.py[white] to [bold green]/usr/lib/python3/dist-packages/[white] directory.")
                os.system("cp Modules/lib/sc0pe_helper.py /usr/lib/python3/dist-packages/")
                print(f"{infoS} Installation completed.")
            elif choose == 2:
                print(f"\n{infoS} Looks like we have permission to uninstall. Let\'s begin...")
                print(f"{infoS} Removing [bold green]/usr/bin/qu1cksc0pe[white] file.")
                os.system("rm -rf /usr/bin/qu1cksc0pe")
                print(f"{infoS} Removing [bold green]/etc/qu1cksc0pe.conf[white] file.")
                os.system("rm -rf /etc/qu1cksc0pe.conf")
                print(f"{infoS} Removing [bold green]/opt/Qu1cksc0pe[white] directory.")
                os.system("rm -rf /opt/Qu1cksc0pe")
                print(f"{infoS} Removing [bold green]sc0pe_helper[white] library.")
                os.system("rm -rf /usr/lib/python3/dist-packages/sc0pe_helper.py")
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
    sc0pehelper.cleanup_junks()
except:
    sc0pehelper.cleanup_junks()