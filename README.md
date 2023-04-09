# Qu1cksc0pe
<img src="https://img.shields.io/badge/-Linux-black?style=for-the-badge&logo=Linux&logoColor=white"> <img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/-Terminal-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-GPL%203.0-black?style=for-the-badge&Color=white">
<p align="center">
    <img width="400" src="https://user-images.githubusercontent.com/42123683/216772963-0b035e5a-c9db-4a6e-ac32-ebca22921405.png" alt="logo">
</p>
<br>All-in-One malware analysis tool for analyze Windows, Linux, OSX binaries, Document files, APK files and Archive files.<br>

*You can get*: 
- What DLL files are used.
- Functions and APIs.
- Sections and segments.
- URLs, IP addresses and emails.
- Android permissions.
- File extensions and their names.
<br><b>And so on...</b><br>

Qu1cksc0pe aims to get even more information about suspicious files and helps user realize what that file is capable of.

# Qu1cksc0pe Can Analyze Currently
| Files | Analysis Type |
| :--- | :--- |
| Windows Executables (.exe, .dll, .msi, .bin) | Static, Dynamic |
| Linux Executables (.elf, .bin) | Static, Dynamic |
| MacOS Executables (mach-o) | Static |
| Android Files (.apk, .jar) | Static, Dynamic(for now .apk only) |
| Golang Binaries (Linux) | Static |
| Document Files | Static |
| Archive Files (.zip, .rar, .ace) | Static |

# Usage
```bash
python3 qu1cksc0pe.py --file suspicious_file --analyze
```

# Screenshot
![2023-04-06_03-47](https://user-images.githubusercontent.com/42123683/230245219-2ed5fc0c-5da2-4ac0-ae77-bf4d2e83704d.png)

# Updates
<b>09/04/2023</b>
- [X] ```sc0pe_helper``` module is changed. You need to execute following command in project directory to update it: ```sudo cp Modules/lib/sc0pe_helper.py /usr/lib/python3/dist-packages/```
- [X] Bug fixes.

<b>06/04/2023</b>
- [X] <b>New feature</b>: ```Archive Analysis``` <b><i>Now Qu1cksc0pe can analyze archive files too!!</i></b>
- <b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_archive_file --archive```
![archiveanalysis](https://user-images.githubusercontent.com/42123683/230241452-0d93d2ca-69a2-42d9-aa99-c9c7cfe637bf.gif)

<b>02/04/2023</b>
- [X] ```Document Analyzer``` module is improved. Now Qu1cksc0pe can analyze ```OneNote``` documents.
- [X] Added new YARA rules.
![onenote](https://user-images.githubusercontent.com/42123683/229323261-bbbe4353-1cc1-4d90-8064-f5d6764235b3.gif)

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
- ```pygore``` => <i>Analyzing golang binaries.</i>
- ```qiling``` => <i>Dynamic analysis of binaries.</i>
- ```pdfminer.six``` => <i>PDF analysis.</i>
- ```rarfile``` => <i>Rar analysis.</i>
- ```acefile``` => <i>Ace analysis.</i>

<br><b>Other dependencies</b>:
- ```VirusTotal API Key``` => <i>Performing VirusTotal based analysis.</i>
- ```Strings``` => <i>Necessary for static analysis.</i>
- ```PyExifTool``` => <i>Metadata extraction.</i>
- ```Jadx``` => <i>Performing source code and resource analysis.</i>
- ```PyOneNote``` => <i>OneNote document analysis.</i>

```bash
# You can simply execute the following command!
bash setup.sh
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

## Archive File Scan
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_archive_file --archive```
![archiveanalysis](https://user-images.githubusercontent.com/42123683/230241452-0d93d2ca-69a2-42d9-aa99-c9c7cfe637bf.gif)

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
![langdetect](https://user-images.githubusercontent.com/42123683/228696312-1362cc48-f978-40c9-a0f0-22a216b83f6f.gif)

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

# References
- <a href="https://www.linkedin.com/posts/mehmetalikerimoglu_qu1cksc0pe-all-in-one-static-malware-analysis-activity-6853239604439523328-B9dN/?trk=public_profile_like_view&originalSubdomain=tr">The Cyber Security Hub</a>
- <a href="https://www.kitploit.com/2021/12/top-20-most-popular-hacking-tools-in.html">Kitploit - Top 20 Most Popular Hacking Tools in 2021</a>
- <a href="https://www.csirt.rnsi.mai.gov.pt/content/infosec-news-20211011">CSIRT.MAI</a>
- <a href="https://vulners.com/kitploit/KITPLOIT:8846405132281597137">Vulners</a>
- <a href="https://www.redpacketsecurity.com/qu1cksc0pe-all-in-one-static-malware-analysis-tool/">RedPacket Security</a>
- <a href="https://cert.bournemouth.ac.uk/qu1cksc0pe-all-in-one-static-malware-analysis-tool/">Bournemouth University - CERT</a>

# Thanks to
For most of FRIDA scripts: <i>https://github.com/Ch0pin/</i><br>
Another scripts: <i>https://codeshare.frida.re/browse</i>
