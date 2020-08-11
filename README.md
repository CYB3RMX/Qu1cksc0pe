# Qu1cksc0pe
![os](https://img.shields.io/badge/Os-Linux-yellow?logo=linux)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
![Bash](https://img.shields.io/badge/Bash-v4.4%5E-green?logo=GNU%20bash)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
<br>This tool allows to analyze windows, linux executables and also APK files.<br>
You can get used dll files, functions, sections, segments, urls, domains and permissions from your suspicious files.<br>
Qu1cksc0pe aims to get even more information about suspicious files and helps to user realizing what that file capable of.

- [x] Usage: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```
- [x] Alternative usage: ```python3 qu1cksc0pe.py --file [PATH TO FILE] --analyze```

# Screenshot
![Screen](.animations/.Screenshot.png)

# Updates
<b>11/08/2020</b>
- [X] Added some improvements for OS identifying.

# Setup
<b>Necessary python modules</b>: ```puremagic``` and ```androguard```<br>
<b>Installation of python modules</b>: ```pip install -r requirements.txt```<br>
<b>Other dependencies</b>: ```VirusTotal API key``` and ```binutils```<br>
<b>Gathering other dependencies<b>
- <i>VirusTotal</i>: ```https://virustotal.com```
- <i>Binutils</i>: ```sudo apt-get install binutils```
- <i>ExifTool</i>: ```sudo apt-get install exiftool```

# Scan arguments
## Normal analysis
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --analyze```<br>
![animation](.animations/analyze.gif)

## VirusTotal
<b>Usage for --vtFile</b>: ```python3 qu1cksc0pe.py --file suspicious_file --vtFile```<br>
<b>Usage for --vtUrl</b>: ```python3 qu1cksc0pe.py --vtUrl```<br>
![animation](.animations/total.gif)

## URL
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --url```<br><br>
![animation](.animations/url.gif)
