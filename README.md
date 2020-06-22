# Qu1cksc0pe
![os](https://img.shields.io/badge/Os-Linux-yellow?logo=linux)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
![Bash](https://img.shields.io/badge/Bash-v4.4%5E-green?logo=GNU%20bash)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
<br>This tool allows to analyze windows and linux executables.<br>
You can get used dll files, functions, sections, segments, urls and domains from your suspicious files.<br>
Qu1cksc0pe aims to get even more information about suspicious files and helps to user realizing what that file capable of.

- [x] Usage: ```python3 qu1cksc0pe.py --file suspicious_file --windows/--linux```
- [x] Alternative usage: ```python3 qu1cksc0pe.py --file [PATH TO FILE] --windows/--linux```

# Screenshot
![Screen](.animations/.Screenshot.png)

# Updates
- [x] <b>23/06/2020</b>: Bug fixes.

# Scan arguments
## Windows Scan
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --windows```<br><br>
![animation](.animations/windows.gif)

## Linux Scan
<b>Attention!</b><i> this argument needs binutils/readelf.</i><br>
<i>To get binutils/readelf do this</i>: ```sudo apt-get install binutils``` </i><br>

<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --linux```<br>
![animation](.animations/linux.gif)

## VirusTotal
<b>Attention!</b><i> this argument needs VirusTotal api key.</i><br>
<i>To get your api key go to the VT website</i>: <b>https://www.virustotal.com/</b>

<b>Usage for --vtFile</b>: ```python3 qu1cksc0pe.py --file suspicious_file --vtFile```<br>
<b>Usage for --vtUrl</b>: ```python3 qu1cksc0pe.py --vtUrl```<br>
![animation](.animations/total.gif)

## URL
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --url```<br><br>
![animation](.animations/url.gif)

# Can you buy me a coffee m8 :) ?
<b>My BTC address</b>: <i>3CURiEGSTUyQPrQuVG2v4Uo6vVjaQBp24v</i>
