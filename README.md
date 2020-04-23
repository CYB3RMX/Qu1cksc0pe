# Qu1cksc0pe
Quick suspicious file static-analysis tool. This tool allows to analyze windows and linux executables.<br>
You can get used dll files, functions, sections, segments, urls and domains from your suspicious files.<br>
Qu1cksc0pe aims to get even more information about suspicious files and helps to user realizing what that file capable of.

- Usage: ```python3 qu1cksc0pe.py --file suspicious_file --scan```
- Alternative usage: ```python3 qu1cksc0pe.py --file [PATH TO FILE] --scan```

# Screenshot
![Screen](.Screenshot.png)

# Updates
- <b>23/04/2020</b>: Some improvements and bug fixes.

# Scan arguments
<b>----Normal Scan----</b><br>
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --scan```<br><br>

<b>----Metadata----</b><br>
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --metadata```<br><br>

<b>----DLL----</b><br>
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --dll```<br><br>

<b>----URL----</b><br>
<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_file --url```<br><br>

<b>----VirusTotal----</b><br>
<b>Attention!</b><i> this argument needs VirusTotal api key.</i><br>
<i>To get your api key go to the VT website</i>: <b>https://www.virustotal.com/</b>

<b>Usage for --vtFile</b>: ```python3 qu1cksc0pe.py --file suspicious_file --vtFile```<br>
<b>Usage for --vtUrl</b>: ```python3 qu1cksc0pe.py --vtUrl```<br>

<b>----ELF----</b><br>
<b>Attention!</b><i> this argument needs binutils/readelf.</i><br>
<i>To get binutils/readelf do this</i>: ```sudo apt-get install binutils``` </i><br>

<b>Usage</b>: ```python3 qu1cksc0pe.py --file suspicious_elf_file --elf```<br>
