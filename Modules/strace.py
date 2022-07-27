#!/usr/bin/python3

import os
from shutil import ExecError
import sys
from subprocess import Popen, PIPE

try:
    from rich import print
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Target file
targetFile = str(sys.argv[1])

def Executor():
    if os.path.exists("/usr/bin/strace"):
        print(f"{infoS} Executing file via strace...")
        strace = Popen(["strace", f"{targetFile}"], stdout=PIPE, stderr=PIPE)
        debug = strace.communicate()
        deb_arr = debug[1].decode("utf-8").split("\n")
        for line in deb_arr:
            if "=" in line:
                print(line[::-1].split("=",1)[1][::-1] + " [bold green]>>RETURN VALUE>>[white]" + line[::-1].split("=",1)[0][::-1])
            else:
                print(line)
    else:
        print(f"{errorS} strace not found.")
        sys.exit(1)

# Exectuing
Executor()