#!/usr/bin/python3

import sys

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    import zepu1chr3
except:
    print("Error: >zepu1chr3< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Specify target binary
fileName = str(sys.argv[1])

#--------------------------------------------- Gathering all function imports from binary
print(f"{infoS} Extracting imports from target binary...")
zep = zepu1chr3.Binary()
tfl = zep.File(fileName)
allStrings = []
try:
    binaryfile = pf.PE(fileName)
    for imps in binaryfile.DIRECTORY_ENTRY_IMPORT:
        try:
            for im in imps.imports:
                allStrings.append(im.name.decode("ascii"))
        except:
            continue
except:
    for imps in zep.GetImports(tfl):
        try:
            allStrings.append(imps["realname"])
        except:
            continue

# Table matrix
mitre_table = {
    "Discovery": {
        "Account Discovery": {
            "api_list": [
                "IsNTAdmin",
                "IsUserAnAdmin",
                "GetUserNameA",
                "GetUserNameEx"
            ], 
            "score": 0
        },
        "Application Window Discovery": {
            "api_list": [
                "GetWindowThreadProcessId",
                "GetWindowLongA",
                "GetForegroundWindow",
                "FindWindow",
                "FindWindowA",
                "FindWindowEx",
                "GetActiveWindow",
                "GetWindowPlacement",
                "GetProcessWindowStation"
            ],
            "score": 0
        },
        "File and Directory Discovery": {
            "api_list": [
                "GetCurrentDirectoryA",
                "FileSystemInfo",
                "GetPathRoot",
                "SHGetFileInfoW",
                "SHGetFileInfoA",
                "FindFirstFileA",
                "FindNextFileA",
                "GetWindowsDirectoryA",
                "GetWindowsDirectoryW",
                "GetWindowsDirectory",
                "GetSystemDirectoryA"
            ],
            "score": 0
        },
        "Process Discovery": {
            "api_list": [
                "EnumProcesses",
                "CreateToolhelp32Snapshot"
            ],
            "score": 0
        },
        "Query Registry": {
            "api_list": [
                "RegQueryValueEx",
                "RegQueryInfoKeyW",
                "RegQueryInfoKeyA",
                "RegQueryValueExA",
                "RegQueryValueExW",
                "RegGetValue"
            ],
            "score": 0
        }
    },
    "Privilege Escalation": {
        "Access Token Manipulation": {
            "api_list": [
                "ImpersonateLoggedOnUser",
                "DuplicateToken",
                "DuplicateTokenEx",
                "SetThreadToken",
                "CreateProcessWithTokenW",
                "LogonUser",
                "CreateProcess",
                "OpenProcessToken",
                "AdjustTokenPrivileges"
            ],
            "score": 0
        }
    },
    "Persistence": {
        "Event Triggered Execution": {
            "api_list": [
                "CreateProcess",
                "CreateProcessAsUser",
                "CreateProcessWithLoginW",
                "CreateProcessWithTokenW",
                "WinExec"
            ],
            "score": 0
        },
        "Boot or Logon Autostart Execution": {
            "api_list": [
                "AddMonitor"
            ],
            "score": 0
        }
    },
    "Collection": {
        "Screen Capture": {
            "api_list": [
                "CopyFromScreen"
            ],
            "score": 0
        },
        "Input Capture": {
            "api_list": [
                "GetClipboardData",
                "EnumClipboardFormats",
                "OpenClipboard",
                "CountClipboardFormats",
                "SetWindowsHook",
                "SetWindowsHookEx",
                "SetWindowsHookExA",
                "SetWindowsHookExW",
                "GetKeyState",
                "GetAsyncKeyState"
            ],
            "score": 0
        }
    },
    "Credential Access": {
        "Input Capture": {
            "api_list": [
                "GetClipboardData",
                "EnumClipboardFormats",
                "OpenClipboard",
                "CountClipboardFormats",
                "SetWindowsHook",
                "SetWindowsHookEx",
                "SetWindowsHookExA",
                "SetWindowsHookExW",
                "GetKeyState",
                "GetAsyncKeyState",
                "AttachThreadInput"
            ],
            "score": 0
        },
        "Network Sniffing": {
            "api_list": [
                "WSAIoctl"
            ],
            "score": 0
        }
    },
    "Defense Evasion": {
        "Modify Registry": {
            "api_list": [
                "RegCreateKeyTransactedA",
                "RegCreateKeyExW",
                "RegCreateKeyExA",
                "RegSetValueExW",
                "RegSetValueExA",
                "RegDeleteKeyExA",
                "RegDeleteKeyA",
                "RegDeleteKeyW",
                "RegDeleteKeyExW",
                "RegDeleteValueA",
                "RegDeleteValueW",
                "RegCreateKeyA",
                "RegCreateKeyW"
            ],
            "score": 0
        },
        "Time Based Evasion": {
            "api_list": [
                "NtDelayExecution",
                "Sleep"
            ],
            "score": 0
        }
    }
}

# Defining function that parses windows api to make table
def MakeMitreTable():
    print(f"{infoS} Rendering tables...\n")
    for key in mitre_table:
        for api in mitre_table[key]:
            for funcs in mitre_table[key][api]:
                for af in mitre_table[key][api]["api_list"]:
                    if af in allStrings:
                        mitre_table[key][api]["score"] += 1

    # Parsing table
    table_contents = {
        "Discovery": [],
        "Privilege Escalation": [],
        "Persistence": [],
        "Collection": [],
        "Credential Access": [],
        "Defense Evasion": []
    }
    for key in mitre_table:
        for api in mitre_table[key]:
            for funcs in mitre_table[key][api]:
                if mitre_table[key][api]["score"] > 0:
                    if api not in table_contents[key]:
                        table_contents[key].append(api)

    # Rendering...
    tech_count = 0
    for tech in table_contents:
        if table_contents[tech] != []:
            mtable = Table()
            mtable.add_column(f"[bold green]{tech}", justify="center")
            for content in table_contents[tech]:
                mtable.add_row(content)
            print(mtable)
            tech_count += 1
    if tech_count == 0:
        print("[bold wihte on red]Not any techniques detected!")

# Execution
MakeMitreTable()