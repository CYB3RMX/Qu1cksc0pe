#!/usr/bin/env python

import os,sys

banner='''
  ____  _    _ __  _____ _  __ _____  _____ ___  _____  ______ 
 / __ \| |  | /_ |/ ____| |/ // ____|/ ____/ _ \|  __ \|  ____|
| |  | | |  | || | |    |   /| (___ | |   | | | | |__) | |__   
| |  | | |  | || | |    |  <  \___ \| |   | | | |  ___/|  __|  
| |__| | |__| || | |____| . \ ____) | |___| |_| | |    | |____ 
 \___\_\_____/ |_|\_____|_|\_\_____/ \_____\___/|_|    |______|

  >>> Quick suspicious file analysis tool.
  ----------------------------------------
  >>> By CYB3RMX_   | Version: 1.0
  ----------------------------------------
  >>> Remainder: Check "information.txt" to learn what are these keywords meanings.
'''

def scope():
   target_file = sys.argv[1]
   regdict={
      "Registry": ["RegKeyOpen","RegSetValue","RegGetValue"],
      "File": ["CreateFile","ReadFile","WriteFile","FindResource","LoadResource","FindFirstFile","FindNextFile","NtQueryDirectoryFile","CreateFileMapping","MapViewOfFile"],
      "Network": ["WSAStartup","WSAGetLastError","socket","recv","connect","getaddrinfo","accept","send","listen"],
      "Web": ["InternetOpen","InternetOpenURL","InternetConnect","InternetReadFile","InternetWriteFile","HTTPOpenRequest","HTTPSendRequest","HTTPQueryInfo","URLDownloadToFile"],
      "Keyboard/Keylogger": ["SetWindowsHook","CallNextHook","MapVirtualKey","GetKeyState","GetAsyncKeyState","GetForegroundWindow","AttachThreadInput"],
      "Process": ["VirtualAlloc","VirtualProtect","OpenProcess","EnumProcesses","EnumProcessModules","CreateRemoteThread","WriteProcessMemory","AdjustTokenPrivileges","IsWow64Process","QueueUserAPC"],
      "Dll": ["LoadLibrary","GetProcAddress","LdrLoadDll"],
      "Debugger Identifying": ["IsDebuggerPresent","CheckRemoteDebuggerPresent","FindWindow","GetTickCount","NtQueryInformationProcess","OutputDebugString"],
      "System Persistence": ["CreateService","ControlService"],
      "COM Object": ["OleInitialize","CoInitialize"],
      "Data Leakage": ["LsaEnumerateLogonSessions","SamIConnect","SamIGetPrivateData","SamQueryInformationUse","NetShareEnum","ReadProcessMemory","Toolhelp32ReadProcessMemory"],
      "Other": ["CreateMutex","CreateProcess","ShellExecute","WinExec","System","CryptAcquireContext","EnableExecuteProtectionSupport","NtSetInformationProcess","GetSystemDefaultLangId","GetTempPath","SetFileTime","StartServiceCtrlDispatcher","IsNTAdmin","IsUserAnAdmin"]
   }
   for category in regdict:
       print("\n\u001b[96m[\u001b[91m+\u001b[96m]\u001b[0m Checking\u001b[92m {}\u001b[0m activites...\n".format(category))
       for word in regdict[category]:
           command = "./grepper.sh {} {}".format(target_file,word)
           os.system(command)
if __name__ == '__main__':
    print(banner)
    try:
        scope()
    except:
        print("Usage: python3 qu1cksc0pe.py [target file]")
