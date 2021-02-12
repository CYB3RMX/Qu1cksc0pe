#!/usr/bin/python3

import sys

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
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"

# All strings
allStrings = open("temp.txt", "r").read().split("\n")

# Strings for identifying programming language
detector = {"Golang": ["GODEBUG", "runtime.goexit", "runtime.gopanic"],
            "Nim": ["echoBinSafe", "nimFrame", "stdlib_system.nim.c", "nimToCStringConv"],
            "C#": ["#GUID", "</requestedPrivileges>", "<security>", "mscoree.dll", "System.Runtime", "</assembly>", ".NET4.0E", "_CorExeMain"],
            "C++": ["std::", "libstdc++.so.6"],
            "C": ["__libc_start_main", "GLIBC_2.2.5", "libc.so.6"]
}

def LanguageDetect():
    print(f"{infoS} Performing language detection. Please wait!!")

    # Basic string scan :)
    indicator = 0
    for key in detector:
        for val in detector[key]:
            if val in allStrings:
                print(f"{foundS} Possible programming language: {green}{key}{white}\n")
                indicator += 1
                sys.exit(0)
    if indicator == 0:
        print(f"{errorS} Programming language couldn\'t detected :(\n")

# Execution
LanguageDetect()