#!/usr/bin/python3

import os
import sys
import distutils.spawn

from .utils import err_exit

try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
except:
    err_exit("Error: >prompt_toolkit< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
infoC = f"{cyan}[{red}*{cyan}]{white}"

# Get python binary
if distutils.spawn.find_executable("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Path completer object
path_completer = PathCompleter()

class DynamicAnalyzer:
    def __init__(self):
        pass

    def dynamic_analysis_main(self):
        # This area is for linux environment
        if sys.platform != "win32":
            print(f"\n{infoS} Dynamic Analysis Options")
            print(f"[bold cyan][[bold red]1[bold cyan]][white] Android")
            tos = int(input("\n>>> Select: "))
            if tos == 1:
                print(f"\n{infoS} Target OS: [bold green]Android")
                target_file = prompt("[>>>] Enter Full Path of The Target File [Press TAB to auto-complete]: ", completer=path_completer)
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}android_dynamic_analyzer.py \"{target_file}\""
                os.system(command)
            else:
                err_exit(f"{errorS} Wrong option :(")

        # This area is for windows environment
        elif sys.platform == "win32":
            print(f"\n{infoS} Dynamic Analysis Options")
            print(f"[bold cyan][[bold red]1[bold cyan]][white] Android")
            print(f"[bold cyan][[bold red]2[bold cyan]][white] Windows")
            tos = int(input("\n>>> Select: "))
            if tos == 1:
                print(f"\n{infoS} Target OS: [bold green]Android")
                target_file = prompt("[>>>] Enter Full Path of The Target File [Press TAB to auto-complete]: ", completer=path_completer)
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}android_dynamic_analyzer.py \"{target_file}\""
                os.system(command)
            elif tos == 2:
                print(f"\n{infoS} Target OS: [bold green]Windows")
                target_pid = input(f"{infoC} Enter target PID: ")
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}windows_dynamic_analyzer.py {target_pid}"
                os.system(command)
            else:
                err_exit(f"{errorS} Wrong option :(")
        else:
            err_exit(f"{errorS} This platform is not suitable for dynamic analysis feature!!")

# Execute
emulator = DynamicAnalyzer()
try:
    print(f"{infoS} Performing Dynamic Analysis...")
    emulator.dynamic_analysis_main()
except KeyboardInterrupt:
    err_exit(f"{errorS} Keyboard interrupt detected...")