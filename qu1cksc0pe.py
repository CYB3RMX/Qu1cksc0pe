#!/usr/bin/python3

# module checking
try:
    import os
    import sys
    import argparse
    import getpass
    import configparser
    import distutils.spawn
    import shutil
    import warnings
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
except ModuleNotFoundError as e:
    print("Error: >rich< module not found.")
    raise e

# Testing puremagic existence
try:
    import puremagic as pr
except ModuleNotFoundError as e:
    print("Error: >puremagic< module not found.")
    raise e

try:
    from colorama import Fore, Style
except ModuleNotFoundError as e:
    print("Error: >colorama< module not found.")
    raise e

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
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Is Qu1cksc0pe installed??
if os.name != "nt":
    if os.path.exists("/usr/bin/qu1cksc0pe") == True and os.path.exists(f"/etc/qu1cksc0pe.conf") == True:
        # Parsing new path and write into handler
        sc0peConf = configparser.ConfigParser()
        sc0peConf.read(f"/etc/qu1cksc0pe.conf")
        sc0pe_path = str(sc0peConf["Qu1cksc0pe_PATH"]["sc0pe"])
        sys.path.append(sc0pe_path)
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

# Utility functions
from Modules.utils import err_exit

MODULE_PREFIX = f"{sc0pe_path}{path_seperator}Modules{path_seperator}"
def execute_module(target, path=MODULE_PREFIX, invoker=py_binary):
    if "python" in invoker or ".py" in target:
        # TODO in the future, raise a ValueError/OSError (and remove the additional code below)
        # instead of warning with a PendingDeprecationWarning
        DEV_NOTE = "[DEV NOTE]: when switching to import statements, remember to adjust any downstream imports! (e.g. `from .utils import err_exit` vs `from utils import err_exit`)"
        warnings.warn("Direct execution of Python files won't be supported much longer." + f" {DEV_NOTE}", PendingDeprecationWarning)

    os.system(f"{invoker} {path}{target}")

import Modules.banners # show a banner

# Argument crating, parsing and handling
ARG_NAMES_TO_KWARG_OPTS = {
    "file": {"help": "Specify a file to scan or analyze."},
    "folder": {"help": "Specify a folder to scan or analyze."},
    "analyze": {"help": "Analyze target file.", "action": "store_true"},
    "archive": {"help": "Analyze archive files.", "action": "store_true"},
    "console": {"help": "Use Qu1cksc0pe on interactive shell.", "action": "store_true"},
    "db_update": {"help": "Update malware hash database.", "action": "store_true"},
    "docs": {"help": "Analyze document files.", "action": "store_true"},
    "domain": {"help": "Extract URLs and IP addresses from file.", "action": "store_true"},
    "hashscan": {"help": "Scan target file's hash in local database.", "action": "store_true"},
    "install": {"help": "Install or Uninstall Qu1cksc0pe.", "action": "store_true"},
    "key_init": {"help": "Enter your VirusTotal API key.", "action": "store_true"},
    "lang": {"help": "Detect programming language.", "action": "store_true"},
    "mitre": {"help": "Generate MITRE ATT&CK table for target sample (Windows samples for now.).", "action": "store_true"},
    "packer": {"help": "Check if your file is packed with common packers.", "action": "store_true"},
    "resource": {"help": "Analyze resources in target file", "action": "store_true"},
    "report": {"help": "Export analysis reports into a file (JSON Format for now).", "action": "store_true"},
    "watch": {"help": "Perform dynamic analysis against Windows/Android files. (Linux will coming soon!!)", "action": "store_true"},
    "sigcheck": {"help": "Scan file signatures in target file.", "action": "store_true"},
    "vtFile": {"help": "Scan your file with VirusTotal API.", "action": "store_true"}
}

parser = argparse.ArgumentParser()
for arg_name, cfg in ARG_NAMES_TO_KWARG_OPTS.items():
    cfg["required"] = cfg.get("required", False)
    parser.add_argument("--" + arg_name, **cfg)
args = parser.parse_args()

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{infoS} Analyzing: [bold green]{analyzeFile}[white]")
    fileType = str(pr.magic_file(analyzeFile))
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{infoS} Target OS: [bold green]Windows[white]\n")
        if args.report:
            execute_module(f"winAnalyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"winAnalyzer.py \"{analyzeFile}\" False")

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: [bold green]Linux[white]\n")
        import Modules.linAnalyzer as lina
        lina.run(sc0pe_path, analyzeFile, emit_report=args.report)

    # MacOSX Analysis
    elif "Mach-O" in fileType or '\\xca\\xfe\\xba\\xbe' in fileType:
        print(f"{infoS} Target OS: [bold green]OSX[white]\n")
        execute_module(f"apple_analyzer.py \"{analyzeFile}\"")

    # Android Analysis
    elif ("PK" in fileType and "Java archive" in fileType) or "Dalvik (Android) executable" in fileType:
        print(f"{infoS} Target OS: [bold green]Android[white]")

        # Extension parsing
        file_name_trim = os.path.splitext(analyzeFile)

        # If given file is a JAR file then run JAR file analysis
        if file_name_trim[-1] == ".jar": # Extension based detection
            execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False JAR")
        elif "Dalvik (Android) executable" in fileType:
            execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False DEX")
        else:
            if args.report:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" True APK")
            else:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False APK")
            # APP Security
            choice = str(input(f"\n{infoC} Do you want to check target app\'s security? This process will take a while.[Y/n]: "))
            if choice == "Y" or choice == "y":
                execute_module(f"apkSecCheck.py")
            else:
                pass

    # Pcap analysis
    elif "pcap" in fileType or "capture file" in fileType:
        print(f"{infoS} Performing [bold green]PCAP[while] analysis...\n")
        execute_module(f"pcap_analyzer.py \"{analyzeFile}\"")

    # Powershell analysis
    elif ".ps1" in analyzeFile:
        print(f"{infoS} Performing [bold green]Powershell Script[white] analysis...\n")
        execute_module(f"powershell_analyzer.py \"{analyzeFile}\"")

    # Email file analysis
    elif "email message" in fileType or "message/rfc822" in fileType:
        print(f"{infoS} Performing [bold green]Email File[white] analysis...\n")
        execute_module(f"email_analyzer.py \"{analyzeFile}\"")
    else:
        err_exit("\n[bold white on red]File type not supported. Make sure you are analyze executable files or document files.\n[bold]>>> If you want to scan document files try [bold green][i]--docs[/i] [white]argument.")

# Main function
def Qu1cksc0pe():
    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            # Before doing something we need to check file size
            file_size = os.path.getsize(args.file)
            if file_size < 52428800: # If given file smaller than 100MB
                if not distutils.spawn.find_executable("strings"):
                    err_exit("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
            else:
                print(f"{infoS} Whoa!! Looks like we have a large file here.")
                if args.analyze:
                    choice = str(input(f"\n{infoC} Do you want to analyze this file anyway [y/N]?: "))
                    if choice == "Y" or choice == "y":
                        BasicAnalyzer(analyzeFile=args.file)
                        sys.exit(0)

                if args.archive:
                    # Because why not!
                    print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
                    execute_module(f"archiveAnalyzer.py \"{args.file}\"")
                    sys.exit(0)

                # Check for embedded executables by default!
                if not args.sigcheck:
                    print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] module...")
                    execute_module(f"sigChecker.py \"{args.file}\"")
                    sys.exit(0)
        else:
            err_exit("[bold white on red]Target file not found!\n")

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--analyze[/blink] argument is not supported for folder analyzing!\n")

    # Analyze archive files
    if args.archive:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            execute_module(f"archiveAnalyzer.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            execute_module(f"document_analyzer.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"hashScanner.py \"{args.file}\" --normal")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"hashScanner.py {args.folder} --multiscan")

    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"sigChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"resourceChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--resource[/blink] argument is not supported for folder analyzing!\n")

    # MITRE ATT&CK
    if args.mitre:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"mitre.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--mitre[/blink] argument is not supported for folder analyzing!\n")

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"languageDetect.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--lang[/blink] argument is not supported for folder analyzing!\n")

    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                err_exit("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                err_exit("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
            else:
                execute_module(f"VTwrapper.py {apik[0]} \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")

    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"packerAnalyzer.py --single \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"packerAnalyzer.py --multiscan {args.folder}")

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"domainCatcher.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")

    # Dynamic analysis
    if args.watch:
        execute_module(f"emulator.py")

    # Interactive shell
    if args.console:
        execute_module(f"console.py")

    # Database update
    if args.db_update:
        execute_module(f"hashScanner.py --db_update")

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
            err_exit(f"{errorS} This feature is not suitable for Windows systems for now!")

        execute_module(f"installer.sh {sc0pe_path} {username}", invoker="sudo bash")

def cleanup_junks():
    junkFiles = ["temp.txt", ".path_handler", ".target-file.txt", ".target-folder.txt", "TargetAPK/", "TargetSource/"]
    for junk in junkFiles:
        if os.path.exists(junk):
            try: # assume simple file
                os.unlink(junk)
            except OSError: # try this for directories
                shutil.rmtree(junk)

def main():
    try:
        Qu1cksc0pe()
    finally: # ensure cleanup irrespective of errors
        cleanup_junks()


# This is the entrypoint when directly running
# this module as a standalone program
# (as opposed to it being imported/ran like a lib)
if __name__ == "__main__":
    main()