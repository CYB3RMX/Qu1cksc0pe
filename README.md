# Qu1cksc0pe
<img src="https://img.shields.io/badge/-Linux-black?style=for-the-badge&logo=Linux&logoColor=white"> <img src="https://img.shields.io/badge/-Python-black?style=for-the-badge&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/-Terminal-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-Bash-black?style=for-the-badge&logo=GNU%20Bash&logoColor=white"> <img src="https://img.shields.io/badge/-Apache%202.0-black?style=for-the-badge&Color=white">
<br>This tool allows to statically analyze windows, linux executables and also APK files.<br>
<i>You can get</i>: 
- What DLL files are used.
- Functions and API's.
- Sections and segments.
- URL's, IP addresses and emails.
- Android permissions.

Qu1cksc0pe aims to get even more information about suspicious files and helps to user realizing what that file capable of.

- [x] Usage: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```
- [x] Alternative usage: ```python3 qu1cksc0pe.py --file [PATH TO FILE] --analyze```

# Screenshot
![Screen](.animations/Screenshot.jpg)

# Updates
<b>23/08/2020</b>
- [X] Added new category ```Memory Management``` to linux analyzer module.

# Setup
<b>Necessary python modules</b>: ```puremagic``` and ```androguard```<br>
<b>Installation of python modules</b>: ```pip3 install -r requirements.txt```<br>
<b>Other dependencies</b>: ```VirusTotal API key```, ```binutils```, ```exiftool``` and ```aapt```.<br>
<b>Gathering other dependencies<b>
- <i>VirusTotal</i>: ```https://virustotal.com```
- <i>Binutils</i>: ```sudo apt-get install binutils```
- <i>ExifTool</i>: ```sudo apt-get install exiftool```
- <i>AAPT</i>: ```sudo apt-get install aapt```

# Scan arguments
## Normal analysis
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```<br>
![animation](.animations/analyze.gif)

## VirusTotal
<b>Usage for --vtFile</b>: ```python3 qu1cksc0pe.py --file suspicious_file --vtFile```<br>
<b>Usage for --vtUrl</b>: ```python3 qu1cksc0pe.py --vtUrl```<br>
![animation](.animations/total.gif)

## Domain
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --domain```<br><br>
![animation](.animations/domain.gif)
