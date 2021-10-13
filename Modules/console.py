#!/usr/bin/python3

import os
import sys

# Testing prompt_toolkit existence
try:
    from prompt_toolkit.shortcuts import prompt
    from prompt_toolkit.completion import NestedCompleter
    from prompt_toolkit.styles import Style
except:
    print("Error: >prompt_toolkit< module not found.")
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

# Colorama
try:
    import colorama
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Colors
red = colorama.Fore.LIGHTRED_EX
cyan = colorama.Fore.LIGHTCYAN_EX
green = colorama.Fore.LIGHTGREEN_EX
white = colorama.Style.RESET_ALL
yellow = colorama.Fore.LIGHTYELLOW_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

# Path variable
sc0pe_path = open(".path_handler", "r").read()

console_style = Style.from_dict({
    # User input (default text).
    'input':          '#ff0066',

    # Prompt.
    'wall1': 'ansicyan',
    'program': 'ansired underline',
    'wall2':    'ansicyan',
    'shell':    '#00aa00',
})

console_output = [
    ('class:wall1', '['),
    ('class:program', 'Qu1cksc0pe'),
    ('class:wall2', ']'),
    ('class:shell', '>> '),
    ('class:input', ''),
]


# Message
print(f"{infoS} Entering interactive shell mode...")

# Parsing commands
console_commands = NestedCompleter.from_nested_dict({
    "analyze": {
        "windows",
        "linux",
        "android",
        "osx"
    },
    "set": {
        "target-file",
        "target-folder"
    },
    "document": None,
    "domain": None,
    "language": None,
    "packer": None,
    "hash-scan": None,
    "exit": None,
    "clear": None
})

try:
    while True:
        # Print target file or folder if it is specified
        if os.path.exists(".target-file.txt"):
            targ_file = open(".target-file.txt", "r").read()
            con_targ1 = os.path.split(targ_file)[1]
        else:
            con_targ1 = f"{red}Not specified{white}."

        if os.path.exists(".target-folder.txt"):
            targ_fold = open(".target-folder.txt", "r").read()
        else:
            targ_fold = f"{red}Not specified{white}."

        # Console output
        print(f"\n{cyan}[{white}Target File: {green}{con_targ1}{white} {yellow}|{white} Target Folder: {green}{targ_fold}{cyan}]")
        con_command = prompt(console_output, style=console_style, completer=console_commands)

        # Exit and clear everything
        if con_command == "exit":
            junkFiles = ["temp.txt", ".path_handler", "elves.txt", ".target-file.txt", ".target-folder.txt"]
            for junk in junkFiles:
                if os.path.exists(junk):
                    os.remove(junk)
            print(f"\n{infoS} Goodbye :3")
            sys.exit(0)

        # Simple clear command
        elif con_command == "clear":
            os.system("clear")

        # Specifying target file
        elif con_command == "set target-file":
            filename = str(input(f"{foundS} Enter full path of target file: "))
            if os.path.isfile(filename):
                with open(".target-file.txt", "w") as tfile:
                    tfile.write(filename)
            else:
                print(f"{errorS} Please enter a correct file.")

        # Specifying target folder
        elif con_command == "set target-folder":
            foldername = str(input(f"{foundS} Enter full path of target folder: "))
            if os.path.isdir(foldername):
                with open(".target-folder.txt", "w") as tfolder:
                    tfolder.write(foldername)
            else:
                print(f"{errorS} Please enter a correct folder.")

        # Windows analysis
        elif con_command == "analyze windows":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                print(f"\n{infoS} Analyzing: {green}{filename}{white}")
                fileType = str(pr.magic_file(filename))
                if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
                    print(f"{infoS} Target OS: {green}Windows{white}\n")
                    command = f"python3 {sc0pe_path}/Modules/winAnalyzer.py {filename}"
                    os.system(command)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Linux Analysis
        elif con_command == "analyze linux":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                print(f"\n{infoS} Analyzing: {green}{filename}{white}")
                fileType = str(pr.magic_file(filename))
                if "ELF" in fileType:
                    if os.path.exists("/usr/bin/strings"):
                        command = f"strings --all {filename} > temp.txt"
                        os.system(command)
                        print(f"{infoS} Target OS: {green}Linux{white}\n")
                        command = f"readelf -a {filename} > elves.txt"
                        os.system(command)
                        command = f"python3 {sc0pe_path}/Modules/linAnalyzer.py {filename}"
                        os.system(command)
                        os.remove(f"{sc0pe_path}/temp.txt")
                    else:
                        print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                        sys.exit(1)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # MacOSX Analysis
        elif con_command == "analyze osx":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                print(f"\n{infoS} Analyzing: {green}{filename}{white}")
                fileType = str(pr.magic_file(filename))
                if "Mach-O" in fileType:
                    if os.path.exists("/usr/bin/strings"):
                        command = f"strings --all {filename} > temp.txt"
                        os.system(command)
                        print(f"{infoS} Target OS: {green}OSX{white}\n")
                        command = f"python3 {sc0pe_path}/Modules/osXAnalyzer.py {filename}"
                        os.system(command)
                        os.remove(f"{sc0pe_path}/temp.txt")
                    else:
                        print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                        sys.exit(1)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Android Analysis
        elif con_command == "analyze android":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                print(f"\n{infoS} Analyzing: {green}{filename}{white}")
                fileType = str(pr.magic_file(filename))
                if "PK" in fileType and "Java archive" in fileType:
                    look = pyaxmlparser.APK(filename)
                    if look.is_valid_APK() == True:
                        if os.path.exists("/usr/bin/strings"):
                            command = f"strings --all {filename} > temp.txt"
                            os.system(command)
                            print(f"{infoS} Target OS: {green}Android{white}")
                            command = f"apkid -j {filename} > apkid.json"
                            os.system(command)
                            command = f"python3 {sc0pe_path}/Modules/apkAnalyzer.py {filename}"
                            os.system(command)
                            if os.path.exists("apkid.json"):
                                os.remove("apkid.json")
                            os.remove(f"{sc0pe_path}/temp.txt")
                        else:
                            print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                            sys.exit(1)
                else:
                    print(f"{errorS} Qu1cksc0pe doesn\'t support archive analysis for now ;)")
                    sys.exit(1)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Document Analysis
        elif con_command == "document":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                print(f"{infoS} Analyzing: {green}{filename}{white}")
                command = f"python3 {sc0pe_path}/Modules/nonExecAnalyzer.py {filename}"
                os.system(command)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Domain extractor
        elif con_command == "domain":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                if os.path.exists("/usr/bin/strings"):
                    command = f"strings --all {filename} > temp.txt"
                    os.system(command)
                    command = f"python3 {sc0pe_path}/Modules/domainCatcher.py {filename}"
                    os.system(command)
                    os.remove(f"{sc0pe_path}/temp.txt")
                else:
                    print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                    sys.exit(1)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Language Detection
        elif con_command == "language":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                if os.path.exists("/usr/bin/strings"):
                    command = f"strings --all {filename} > temp.txt"
                    os.system(command)
                    command = f"python3 {sc0pe_path}/Modules/languageDetect.py {filename}"
                    os.system(command)
                    os.remove(f"{sc0pe_path}/temp.txt")
                else:
                    print(f"{errorS} {green}strings{white} command not found. You need to install it.")
                    sys.exit(1)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Packer Detection
        elif con_command == "packer":
            if os.path.exists(".target-file.txt"):
                filename = open(".target-file.txt", "r").read()
                command = f"python3 {sc0pe_path}/Modules/packerAnalyzer.py {filename} --single"
                os.system(command)
            else:
                print(f"{errorS} You must specify target file with {green}set target-file{white} command.")

        # Hash Scanner
        elif con_command == "hash-scan":
            if os.path.exists(".target-folder.txt"):
                foldername = open(".target-folder.txt", "r").read()
                command = f"python3 {sc0pe_path}/Modules/hashScanner.py {foldername} --multiscan"
                os.system(command)
            else:
                print(f"{errorS} You must specify target folder with {green}set target-folder{white} command.")

        # Wrong command
        else:
            print(f"{errorS} Wrong command :(")

except Exception as err:
    print(err)
    sys.exit(1)