#!/usr/bin/python3

import sys

try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

try:
    from rich import print
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Getting name of the file for executable checker function
fileName = str(sys.argv[1])

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# All strings
allStrings = open("temp.txt", "r").read().split("\n")

# Strings for identifying programming language
detector = {"Golang": ["GODEBUG", "runtime.goexit", "runtime.gopanic"],
            "Nim": ["echoBinSafe", "nimFrame", "stdlib_system.nim.c", "nimToCStringConv"],
            "Python": ["_PYI_PROCNAME", "Py_BuildValue", "Py_Initialize", "__main__", "pydata", "libpython3.9.so.1.0", "py_compile"],
            "Zig": ["ZIG_DEBUG_COLOR", "__zig_probe_stack", "__zig_return_error", "ZIG"],
            "C#": ["#GUID", "</requestedPrivileges>", "<security>", "mscoree.dll", "System.Runtime", "</assembly>", ".NET4.0E", "_CorExeMain"],
            "C++": ["std::", "libstdc++.so.6", "GLIBCXX_3.4.9", "CXXABI_1.3.9"],
            "C": ["__libc_start_main", "GLIBC_2.2.5", "libc.so.6", "__cxa_finalize", ".text"]
} # TODO: Look for better solutions instead of strings!!

# This function scans special strings in binary files
def LanguageDetect():
    print(f"{infoS} Performing language detection. Please wait!!")

    # Basic string scan :)
    indicator = 0
    for key in detector:
        for val in detector[key]:
            if val in allStrings:
                print(f"{foundS} Possible programming language: [bold green]{key}[white]\n")
                indicator += 1
                sys.exit(0)
    if indicator == 0:
        print(f"{errorS} Programming language couldn\'t detected :(\n")
        sys.exit(1)

# This function analyses if given file is an executable file
def ExecutableCheck(fileName):
    exe_indicator = 0
    try:
        magicNums = list(pr.magic_file(fileName))
        for mag in range(0, len(magicNums)):
            if magicNums[mag].confidence >= 0.4:
                if "executable" in str(magicNums[mag].name) or "Executable" in str(magicNums[mag].name):
                    exe_indicator += 1
        if exe_indicator != 0:
            return True
        else:
            return False
    except:
        pass

# Execution
if ExecutableCheck(fileName) == True:
    LanguageDetect()
else:
    print(f"{errorS} Please scan executable files.\n")
    sys.exit(1)