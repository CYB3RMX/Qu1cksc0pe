# Qu1cksc0pe
<img src="https://img.shields.io/badge/-Linux-black?style=for-the-badge&logo=Linux&logoColor=white"> <img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/-Terminal-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-GPL%203.0-black?style=for-the-badge&Color=white">
<br>All-in-One malware analysis tool for analyze Windows, Linux, OSX binaries, Document files and APK files.<br>

*You can get*: 
- What DLL files are used.
- Functions and APIs.
- Sections and segments.
- URLs, IP addresses and emails.
- Android permissions.
- File extensions and their names.
<br><b>And so on...</b><br>

Qu1cksc0pe aims to get even more information about suspicious files and helps user realize what that file is capable of.

# Usage
```bash
python3 qu1cksc0pe.py --file suspicious_file --analyze
```

# Screenshot
![Screenshot](https://user-images.githubusercontent.com/42123683/189416059-339b4a6c-57e0-4c8c-a2a3-380161f89d55.png)

# Updates
<b>14/09/2022</b>
- [X] Bug fixes on ```DocumentAnalyzer``` module. PDF analyzer now have better embedded URL detection capabilities.

<b>12/09/2022</b>
- [X] ```DocumentAnalyzer``` module is upgraded. Now Qu1cksc0pe can extract embedded files/exploits from PDF files!!<br>
![exploit](https://user-images.githubusercontent.com/42123683/189676266-d2b6f502-b254-4de1-ad6e-bbc03740febc.gif)

# Available On
![blackarch](https://user-images.githubusercontent.com/42123683/189416163-4ffd12ce-dd62-4510-b496-924396ce77c2.png)
![tsurugi](https://user-images.githubusercontent.com/42123683/189416193-a709291f-be8f-469c-b649-c6201fa86677.jpeg)

# Note
- [X] You can also use Qu1cksc0pe from ```Windows Subsystem Linux``` in Windows 10.

# Setup
<b>Necessary python modules</b>: 
- ```puremagic``` => <i>Analyzing target OS and magic numbers.</i>
- ```androguard``` => <i>Analyzing APK files.</i>
- ```apkid``` => <i>Check for Obfuscators, Anti-Disassembly, Anti-VM and Anti-Debug.</i>
- ```rich``` => <i>Pretty outputs and TUI.</i>
- ```tqdm``` => <i>Progressbar animation.</i>
- ```colorama``` => <i>Colored outputs.</i>
- ```oletools``` => <i>Analyzing VBA Macros.</i>
- ```pefile``` => <i>Gathering all information from PE files.</i>
- ```quark-engine``` => <i>Extracting IP addresses and URLs from APK files.</i>
- ```pyaxmlparser``` => <i>Gathering informations from target APK files.</i>
- ```yara-python``` => <i>Android library scanning with Yara rules.</i>
- ```prompt_toolkit``` => <i>Interactive shell.</i>
- ```frida``` => <i>Performing dynamic analysis against android applications.</i>
- ```lief``` => <i>ELF binary parsing and analysis.</i>
- ```zepu1chr3``` => <i>Analyzing binaries via radare2.</i>
- ```pygore``` => <i>Analyzing golang binaries```</i>
- ```qiling``` => <i>Dynamic analysis of binaries.</i>
- ```pdfminer.six``` => <i>PDF analysis.</i>

<br><b>Installation of python modules</b>: ```pip3 install -r requirements.txt```<br>
<b>Gathering other dependencies</b>:
- <i>VirusTotal API Key</i>: ```https://virustotal.com```
- <i>Strings</i>: ```sudo apt-get install strings```
- <i>PyExifTool</i>: ```git clone git://github.com/smarnach/pyexiftool.git``` then ```cd pyexiftool && sudo python3 setup.py install```

**Alert**
> **You must specify jadx binary path in Systems/Android/libScanner.conf**
```ini
[Rule_PATH]
rulepath = /Systems/Android/YaraRules/

[Decompiler]
decompiler = JADX_BINARY_PATH <-- You must specify this.
```

# Installation
- [X] You can install Qu1cksc0pe easily on your system. Just execute the following commands.<br>
<b>Command 0</b>: ```sudo pip3 install -r requirements.txt```<br>
<b>Command 1</b>: ```sudo python3 qu1cksc0pe.py --install```

# Static Analysis
## Normal analysis
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```<br>
![analyze](https://user-images.githubusercontent.com/42123683/189416371-5815062d-09d9-49aa-82c9-e9961203a642.gif)

## Resource analysis
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --resource```<br>
![resource](https://user-images.githubusercontent.com/42123683/189416431-de08337f-8d46-4c9c-a635-59a5faca28ff.gif)

## Hash scan
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --hashscan```<br>
![hash](https://user-images.githubusercontent.com/42123683/189416516-8268817c-f186-4ee9-971e-adcccfcb45eb.gif)

## Folder scan
<b>Supported Arguments</b>:
- ```--hashscan```
- ```--packer```

<b>Usage</b>: ```python3 qu1cksc0pe.py --folder FOLDER --hashscan```<br>
![hashscan_tui](https://user-images.githubusercontent.com/42123683/189416636-494f8d0b-4692-4b81-b133-8bd5eb0f5683.gif)

## VirusTotal
<b>Report Contents</b>:
- ```Threat Categories```
- ```Detections```
- ```CrowdSourced IDS Reports```

<b>Usage for --vtFile</b>: ```python3 qu1cksc0pe.py --file suspicious_file --vtFile```<br>
![total](https://user-images.githubusercontent.com/42123683/189416676-06216d52-4882-492d-9ee4-4ff7c04b6358.gif)

## Document scan
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_document --docs```<br>
![docs](https://user-images.githubusercontent.com/42123683/189416778-f7f93d49-7ff0-4eb5-9898-53e63e5833a1.gif)

### Embedded File/Exploit Extraction
![exploit](https://user-images.githubusercontent.com/42123683/189676461-86565ff2-3a0c-426a-a66b-80a9462489b7.gif)

## File signature analyzer
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --sigcheck```<br>
![sigcheck](https://user-images.githubusercontent.com/42123683/189416864-0e3e3be0-a7bf-4d35-bd9d-403afc38bb96.gif)

### File Carving
![carving](https://user-images.githubusercontent.com/42123683/189416908-31a06ac7-778a-48bd-a5f7-26708a255340.gif)

## MITRE ATT&CK Technique Extraction
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --mitre```<br>
![mitre](https://user-images.githubusercontent.com/42123683/189416941-46e8be6b-2eec-4145-b0b8-b0da78d6611e.gif)

## Programming language detection
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_executable --lang```<br>
![langDet](https://user-images.githubusercontent.com/42123683/189416982-75ea308d-2590-4bc7-baf0-10c034878ed7.gif)

## Interactive shell
<b>Usage</b>: ```python3 qu1cksc0pe.py --console```<br>
![console](https://user-images.githubusercontent.com/42123683/189417009-dec6a91b-228c-4c7e-9579-66c4aa9f4036.gif)

# Dynamic Analysis
## Dynamic instrumentation with FRIDA scripts (for android applications)
**Alert**
> **You must connect a virtual device or physical device to your computer.**

<br><b>Usage</b>: ```python3 qu1cksc0pe.py --runtime```<br>
![dynamic](https://user-images.githubusercontent.com/42123683/189417071-7c23e5c7-77c1-419a-b563-7820751e4ae6.gif)

## Binary Emulation
**Alert**
> **Binary emulator is not recommended for .NET analysis.**

<br><b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --watch```<br>
![animation](.animations/emulate.gif)

# Informations about categories
## Registry
<b>This category contains functions and strings about:</b>
- Creating or destroying registry keys.
- Changing registry keys and logs.

## File
<b>This category contains functions and strings about:</b>
- Creating/modifying/infecting/deleting files.
- Getting information about file contents and filesystems.

## Networking/Web
<b>This category contains functions and strings about:</b>
- Communicating with malicious hosts.
- Downloading malicious files.
- Sending informations about infected machine and its user.

## Process
<b>This category contains functions and strings about:</b>
- Creating/infecting/terminating processes.
- Manipulating processes.

## Dll/Resource Handling
<b>This category contains functions and strings about:</b>
- Handling DLL files and another malware's resource files.
- Infecting and manipulating DLL files.

## Evasion/Bypassing
<b>This category contains functions and strings about:</b>
- Manipulating Windows security policies and bypassing restrictions.
- Detecting debuggers and doing evasive tricks.

## System/Persistence
<b>This category contains functions and strings about:</b>
- Executing system commands.
- Manipulating system files and system options to get persistence in target systems.

## COMObject
<b>This category contains functions and strings about:</b>
- Microsoft's Component Object Model system.

## Cryptography
<b>This category contains functions and strings about:</b>
- Encrypting and decrypting files.
- Creating and destroying hashes.

## Information Gathering
<b>This category contains functions and strings about:</b>
- Gathering informations from target hosts like process states, network devices etc.

## Keyboard/Keylogging
<b>This category contains functions and strings about:</b>
- Tracking infected machine's keyboard.
- Gathering information about targets keyboard.
- Managing input methods etc.

## Memory Management
<b>This category contains functions and strings about:</b>
- Manipulating and using target machines memory.

# Thanks to
For most of FRIDA scripts: <i>https://github.com/Ch0pin/</i><br>
Another scripts: <i>https://codeshare.frida.re/browse</i>
