# Qu1cksc0pe
<a href="https://www.buymeacoffee.com/cyb3rmx"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" height="40px"></a><br><br>
<img src="https://img.shields.io/badge/-Linux-black?style=for-the-badge&logo=Linux&logoColor=white"> <img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/-Terminal-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-GPL%203.0-black?style=for-the-badge&Color=white">
<p align="center">
    <img width="400" src="https://user-images.githubusercontent.com/42123683/216772963-0b035e5a-c9db-4a6e-ac32-ebca22921405.png" alt="logo">
</p>
<br>All-in-One malware analysis tool for analyze many file types, from Windows binaries to E-Mail files.<br>

*You can get*: 
- What DLL files are used.
- Functions and APIs.
- Sections and segments.
- URLs, IP addresses and emails.
- Android permissions.
- File extensions and their names.
- Embedded executables/exploits.
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
| PCAP Files (.pcap) | Static |
| Powershell Scripts | Static |
| E-Mail Files (.eml) | Static |

# Usage
```bash
python3 qu1cksc0pe.py --file suspicious_file --analyze
```

# Screenshot
![Screenshot](https://github.com/CYB3RMX/Qu1cksc0pe/assets/42123683/22e652db-c25f-49b1-b122-ac9f89d14ae3)

# Updates
<b>07/08/2023</b>
- [X] Bug fixes and improvements.

<b>03/08/2023</b>
- [X] ```WindowsAnalyzer``` module is improved. Now you can get XREF information about functions!
![windows_analyze](https://github.com/CYB3RMX/Qu1cksc0pe/assets/42123683/bd6945b6-5198-42fb-adff-2118a596bf58)

<b>30/07/2023</b>
- [X] ```DocumentAnalyzer``` module is improved. Now you can perform better PDF analysis!

<b>29/07/2023</b>
- [X] ```AndroidAnalyzer``` module is improved. Now you can perform detection against Anti-VM/Anti-Debug patterns!
- [X] Added new payload detection/carving techniques to ```ResourceAnalyzer``` module.

# Available On
![blackarch](https://user-images.githubusercontent.com/42123683/189416163-4ffd12ce-dd62-4510-b496-924396ce77c2.png)
![tsurugi](https://user-images.githubusercontent.com/42123683/189416193-a709291f-be8f-469c-b649-c6201fa86677.jpeg)

# Recommended Systems
- [X] Parrot OS
- [X] Kali Linux

<br><b><i>And similar Linux distributions...</i></b>

# Setup and Installation
<br><b>Necessary Dependencies</b>:
- ```VirusTotal API Key``` => <i>Performing VirusTotal based analysis.</i>
- ```Strings``` => <i>Necessary for static analysis.</i>
- ```PyExifTool``` => <i>Metadata extraction.</i>
- ```Jadx``` => <i>Performing source code and resource analysis.</i>
- ```PyOneNote``` => <i>OneNote document analysis.</i>
- ```Mono``` => <i>Performing .Net binary analysis.</i>

```bash
# You can simply execute the following command it will do everything for you!
bash setup.sh

# If you want to install Qu1cksc0pe on your system just execute the following commands.
bash setup.sh
sudo python3 qu1cksc0pe.py --install

# Or you can use Qu1cksc0pe from Docker!
docker build qu1cksc0pe .
docker run -it --rm -v $(pwd):/data qu1cksc0pe:latest --file /data/suspicious_file --analyze
```

# Static Analysis
## Normal analysis
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```<br>
![windows_analyze](https://github.com/CYB3RMX/Qu1cksc0pe/assets/42123683/bd6945b6-5198-42fb-adff-2118a596bf58)

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
- <a href="https://github.com/Ignitetechnologies/Mindmap/blob/main/Forensics/Digital%20Forensics%20Tools%20HD.png">Hacking Articles - Digital Forensics Tools Mindmap</a>
- <a href="https://twitter.com/hack_git/status/1666867995036057602">HackGit - Twitter Post</a>
- <a href="https://twitter.com/DailyDarkWeb/status/1668966526358286336">Daily Dark Web - Twitter Post</a>
- <a href="https://isc.sans.edu/diary/The+Importance+of+Malware+Triage/29984">SANS ISC - Blog Post</a>

# Thanks to
For most of FRIDA scripts: <i>https://github.com/Ch0pin/</i><br>
Another scripts: <i>https://codeshare.frida.re/browse</i>
