# Qu1cksc0pe
Quick suspicious file analysis tool.

- Usage before install: ```python3 qu1cksc0pe.py --file suspicious_file --category anything```
- Usage after install: ```qu1cksc0pe --file suspicious_file --category anything```

<b>----Arguments----</b>
- -f or --file: Select suspicious file.
- -c or --category: Scan specified category.
- --install: Install Qu1cksc0pe on your system.
- --dll: Look for used DLL files.
- --metadata: Get exif information.
- --vtscan: Scan with VirusTotal api.

<b>----Categories----</b>
- <i>Registry</i>
- ```qu1cksc0pe --file suspicious_file --category registry```

- <i>File</i>
- ```qu1cksc0pe --file suspicious_file --category file```

- <i>Network</i>
- ```qu1cksc0pe --file suspicious_file --category network```

- <i>Web</i>
- ```qu1cksc0pe --file suspicious_file --category web```

- <i>Keyboard/Keylogger</i>
- ```qu1cksc0pe --file suspicious_file --category keylogger```

- <i>Process</i>
- ```qu1cksc0pe --file suspicious_file --category process```

- <i>Dll</i>
- ```qu1cksc0pe --file suspicious_file --category dll```

- <i>Debugger Indentifying</i>
- ```qu1cksc0pe --file suspicious_file --category debugger```

- <i>System Persistence</i>
- ```qu1cksc0pe --file suspicious_file --category persistence```

- <i>COM Object</i>
- ```qu1cksc0pe --file suspicious_file --category comobject```

- <i>Data Leakage</i>
- ```qu1cksc0pe --file suspicious_file --category dataleak```

- <i>Other</i>
- ```qu1cksc0pe --file suspicious_file --category other```

- <i>All Categories</i>
- ```qu1cksc0pe --file suspicious_file --category all```

<b>----Metadata----</b>
- ```qu1cksc0pe --file suspicious_file --metadata```

<b>----DLL----</b>
- ```qu1cksc0pe --file suspicious_file --dll```

<b>----VirusTotal----</b>
- ````qu1cksc0pe --file suspicious_file --vtscan```
