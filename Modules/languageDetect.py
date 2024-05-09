#!/usr/bin/python3

import re
import sys
import subprocess

from utils import err_exit

try:
    import puremagic as pr
except:
    err_exit("Error: >puremagic< module not found.")

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Getting name of the file for executable checker function
fileName = str(sys.argv[1])

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
strings_param = "--all"
if sys.platform == "win32":
   strings_param = "-a"
elif sys.platform == "darwin":
   strings_param = "-a"
else:
   pass

# Perform strings
_ = subprocess.run(f"strings {strings_param} \"{fileName}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
if sys.platform != "win32":
    _ = subprocess.run(f"strings {strings_param} -e l {fileName} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

# All strings
allStrings = open("temp.txt", "r").read().split("\n")

# Strings for identifying programming language
language_dict = {
    "Golang": {
        "patterns": ["GODEBUG", "runtime.goexit", "runtime.gopanic", ".gosymtab", ".gopclntab", ".go.buildinfo", ".note.go.buildid", "go:build", "CGO_ENABLED", "CGO_CFLAGS", "GOARCH", "_cgo_gotypes.go"],
        "occurence": 0
    },
    "Nim": {
        "patterns": ["echoBinSafe", "nimFrame", "stdlib_system.nim.c", "nimToCStringConv", "nim_compiler", "nim.cfg", "main.nim", "nimBetterRun", "nimble", "nim command"],
        "occurence": 0
    },
    "Python": {
        "patterns": ["_PYI_PROCNAME", "Py_BuildValue", "Py_Initialize", "__main__", "pydata", "libpython3.9.so.1.0", "py_compile"],
        "occurence": 0
    },
    "Zig": {
        "patterns": ["ZIG_DEBUG_COLOR", "__zig_probe_stack", "__zig_return_error"],
        "occurence": 0
    },
    "C#": {
        "patterns": ["#GUID", "</requestedPrivileges>", "<security>", "mscoree.dll", "System.Runtime", "</assembly>", ".NET4.0E", "_CorExeMain"],
        "occurence": 0
    },
    "C++": {
        "patterns": ["std::", "libstdc++.so.6", "GLIBCXX_3.4.9", "CXXABI_1.3.9"],
        "occurence": 0
    },
    "C": {
        "patterns": ["__libc_start_main", "GLIBC_2.2.5", "libc.so.6", "__cxa_finalize", ".text"],
        "occurence": 0
    },
    "Rust": {
        "patterns": ["rustc", "cargo"],
        "occurence": 0
    }
}

# This function scans special strings in binary files
def LanguageDetect():
    print(f"{infoS} Performing language detection. Please wait!!")
    langTable = Table()
    langTable.add_column("Programming Language", justify="center")
    langTable.add_column("Probability", justify="center")
    langTable.add_column("Pattern Occurences", justify="center")

    # Basic string scan :)
    indicator = 0
    for key in language_dict:
        for pat in language_dict[key]["patterns"]:
            try:
                matches = re.findall(pat, str(allStrings))
                if matches != []:
                    language_dict[key]["occurence"] += len(matches)
                    indicator += 1
            except:
                continue

    # Scoring system: Calculating total occurence
    total_occurences = 0
    for key in language_dict:
        total_occurences += language_dict[key]["occurence"]

    # Calculating probability
    for key in language_dict:
        if language_dict[key]["occurence"] == 0:
            pass
        else:
            calc = (language_dict[key]["occurence"] * 100) / total_occurences
            langTable.add_row(f"[bold green]{key}[white]", f"[bold green]{str(calc)}[white]", f"[bold green]{str(language_dict[key]['occurence'])}[white]")
    print(langTable)

    if indicator == 0:
        err_exit(f"{errorS} Programming language couldn\'t detected. This file is might be obfuscated!\n")

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
    err_exit(f"{errorS} Please scan executable files.\n")