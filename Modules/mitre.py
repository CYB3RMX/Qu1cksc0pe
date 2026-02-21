#!/usr/bin/python3

import os
import sys
import subprocess

from utils.helpers import err_exit

try:
    from rich import print
except Exception:
    err_exit("Error: >rich< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"


def _scope_path():
    try:
        with open(".path_handler", "r") as path_file:
            return path_file.read().strip()
    except Exception:
        return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _bool_text(value):
    return "True" if str(value).strip().lower() in ("true", "1", "yes", "y") else "False"


def main():
    if len(sys.argv) < 2:
        err_exit("Usage: mitre.py <file> [save_report=True|False]")

    target_file = sys.argv[1]
    save_report = _bool_text(sys.argv[2] if len(sys.argv) > 2 else "False")

    sc0pe_path = _scope_path()
    analyzer_path = f"{sc0pe_path}{path_seperator}Modules{path_seperator}windows_static_analyzer.py"
    if not os.path.exists(analyzer_path):
        err_exit(f"{errorS} windows_static_analyzer.py not found: {analyzer_path}")

    print(f"{infoS} MITRE analysis is integrated into Windows static analyzer.")
    cmd = [sys.executable or "python3", analyzer_path, target_file, save_report, "True"]
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        err_exit(f"{errorS} Integrated MITRE analysis failed.", arg_override=proc.returncode)


if __name__ == "__main__":
    main()
