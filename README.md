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
| Android Files (.apk, .jar, .dex) | Static, Dynamic(for now .apk only) |
| Golang Binaries (Linux) | Static |
| Document Files | Static |
| VBScript/VBA Family (.vbs, .vbe, .vba, .vb, .bas, .cls, .frm) | Static (`--docs`) |
| Windows Batch Scripts (.bat, .cmd) | Static (`--analyze`) |
| Archive Files (.zip, .rar, .ace) | Static |
| PCAP Files (.pcap) | Static |
| Powershell Scripts | Static |
| E-Mail Files (.eml) | Static |

# Usage
```bash
python qu1cksc0pe.py --file suspicious_file --analyze
```

```bash
# Launch Web UI
python3 qu1cksc0pe.py --ui
```

# Screenshot
![Screenshot](https://github.com/user-attachments/assets/84b72c33-8ca6-48f5-a613-52fca7c596e2)

# Updates
<b>20/02/2026</b>
- [X] Windows setup script (`setup.ps1`) was hardened: automatic `winget` fallback installation, Python/7-Zip bootstrap, Sysinternals `strings` EULA auto-accept, and resilient Ollama install flow.
- [X] Ollama cloud-model handling in setup was improved: clear `ollama signin` guidance is shown once, and setup continues gracefully if cloud model pull fails.
- [X] Config parsing was hardened for Windows/analysis modules with `utf-8-sig` support to avoid BOM-related `configparser` errors.
- [X] Windows static analyzer report flow was fixed to avoid early exit on low-import samples, so `--report/--ai` can still produce JSON output.
- [X] Web UI worker subprocess decoding was made robust on Windows (`utf-8` with replacement) to prevent `UnicodeDecodeError` crashes.
- [X] Added/updated Windows Batch Script (`.bat`, `.cmd`) analysis support in `--analyze` flow with JSON report output.

<b>15/02/2026</b>
- [X] Linux setup script (`setup.sh`) was improved with automatic Ollama installation and model pull support from `Systems/Multiple/multiple.conf`.

<b>14/02/2026</b>
- [X] Windows setup script (`setup.ps1`) was improved with persistent user PATH updates, automatic `winget`/Ollama setup, and graceful `kimi-k2.5:cloud` auth-error handling.

<b>13/02/2026</b>
- [X] NEW FEATURE: Added Web UI.

<b>12/02/2026</b>
- [X] Linux dynamic analyzer: added a dedicated Linux menu with separate actions for Binary Emulation and PID Monitoring.
- [X] PID monitoring improvements: target can now be selected by PID or process name, with better Frida attach retries and child-process attach handling.
- [X] Linux emulation fallback chain improved: Docker SDK -> Docker CLI -> host `qemu` fallback (when available).
- [X] Linux dynamic prompts now support TAB autocomplete (menu selection, binary path, PID/process name).
- [X] Linux PID monitoring exits gracefully on `Ctrl+C` without traceback.

<b>11/02/2026</b>
- [X] Document analyzer: added VBScript/VBA family static analysis for `.vbs`, `.vbe`, `.vba`, `.vb`, `.bas`, `.cls`, `.frm` (pattern summary, `CreateObject` values, shell command hits, decoded payload hints).
- [X] AI analyzer model selection is now explicit: only the model in `Systems/Multiple/multiple.conf` (`[Ollama] model`) is used.
- [X] AI analyzer performance/stability: `temp.txt` is parsed/sampled before prompt building; large reports are compacted with size guards; incomplete/truncated LLM output is retried.
- [X] AI output cleanup: hidden/internal thinking blocks are stripped; partial `<<SC0PE_IOCS_JSON_*>>` blocks are removed from UI/report when response is cut.
- [X] LLM IoC quality improvements: local analysis paths are filtered from `file_paths`; stricter domain/IP validation added; file-like pseudo-domains (e.g. `sheet1.xml`) are dropped.
- [X] Email analyzer hardening: Python 3.14 event loop compatibility for DNSBL checks, noisy DNSBL false-positive filtering, and reliable extracted-attachment cleanup.

<b>10/02/2026</b>
- [X] Removed FLOSS/Vivisect from the project (no string decode/emulation stage in Windows analysis).
- [X] Linux static analyzer: Golang special analysis findings are now saved into the Linux JSON report under `golang`.
- [X] AI analyzer (`--ai`): full report JSON is included in the LLM prompt (`report_full`); model thinking blocks are stripped from console output and the saved AI report; extracted IoCs are displayed in a separate table.

<b>09/02/2026</b>
- [X] Windows static analyzer improvements: faster import/export extraction (`pefile` fast load + parsing only required directories).
- [X] .NET analysis no longer requires `pythonnet`/Mono (pure-Python metadata parsing via `dnfile`).
- [X] Windows static analyzer cleanup: removed FLOSS integration (string decode/emulation) due to stability/performance issues.
- [X] Setup/Docker cleanup: removed `mono-complete` / `pythonnet` dependency.
- [X] Archive analyzer: removed `acefile` dependency. ACE archives are extracted via `7z`/`7zz` when available.
- [X] Android analyzer: APK resource/content scan is now part of `--analyze` and is saved into the JSON report under `resource_scan`.

<b>08/02/2026</b>
- [X] **NEW FEATURE**: AI report analysis via `--ai` (auto-enables `--report`)
- [X] Android analyzer improvements: faster source pattern scanning and cleaner report outputs.
- [X] Setup improvements: JADX updated to `v1.5.3` and setup scripts made more robust (`setup.sh`, `setup.ps1`).
- [X] Better handling for problematic APKs: detect encrypted ZIP entries and report the reason when decompilation is skipped/failed.
- [X] Document analyzer improvements: automatic decryption attempt for `FILEPASS`-protected Office documents.

# Available On
<img width="400" src="https://user-images.githubusercontent.com/42123683/189416163-4ffd12ce-dd62-4510-b496-924396ce77c2.png" alt="logo"><img width="400" src="https://user-images.githubusercontent.com/42123683/189416193-a709291f-be8f-469c-b649-c6201fa86677.jpeg" alt="logo">
<img width="400" src="https://github.com/user-attachments/assets/a555750e-d979-4f0f-9d2c-730662b00915" alt="logo">
<img width="400" src="https://github.com/user-attachments/assets/56054b07-0512-42bb-ab97-cecbf845116e" alt="logo">

# Recommended Systems
- [X] Parrot OS
- [X] Kali Linux
- [X] Windows 10 or 11

<br><b><i>And also another Linux distributions like as Kali/Parrot</i></b>

# Setup and Installation
> [!NOTE]
> If you encounter issues with the Python modules, creating a Python virtual environment (python_venv) should resolve them.
> For detailed setup and troubleshooting (dependencies, Docker usage, Windows notes), see the <a href="https://zread.ai/CYB3RMX/Qu1cksc0pe/1-overview">project overview documentation</a>.
> AI model selection is manual: set `[Ollama] model` in `Systems/Multiple/multiple.conf` to the exact model you want to use.

```bash
# First you need to clone Qu1cksc0pe with this command
git clone --depth 1 https://github.com/CYB3RMX/Qu1cksc0pe

# After cloning the repository YOU MUST create a python virtual environment (for handling python modules)
virtualenv -p python3 sc0pe_venv
source sc0pe_venv/bin/activate

# You can simply execute the following command it will do everything for you!
bash setup.sh
#
# setup.sh also installs required system tools (e.g. adb, strings, unzip, 7z) and sets up JADX.

# If you want to install Qu1cksc0pe on your system just execute the following commands.
python qu1cksc0pe.py --install # Optional

# To prevent interpreter errors after installation, use dos2unix.
dos2unix /usr/bin/qu1cksc0pe

# Or you can use Qu1cksc0pe from Docker!
docker build -t qu1cksc0pe .
docker run -it --rm -v $(pwd):/data qu1cksc0pe:latest --file /data/suspicious_file --analyze

# For Windows systems you need to execute the following command (Powershell)
# PS C:\Users\user\Desktop\Qu1cksc0pe> .\setup.ps1
#
# setup.ps1 handles winget dependency fallback, Python + 7-Zip setup,
# Sysinternals strings EULA acceptance, and resilient Ollama installation.
# If cloud model auth is needed, run:
# ollama signin
# ollama pull kimi-k2.5:cloud
```

# Environment Variables
You can change some analyzer behaviors via environment variables (useful for CI, reproducibility, or controlling report size/timeouts).

**Linux/macOS (bash/zsh) example**
```bash
SC0PE_ANDROID_REPORT_DETAILED=1 python qu1cksc0pe.py --file app.apk --analyze --report
```

**Windows (PowerShell) example**
```powershell
$env:SC0PE_ANDROID_REPORT_DETAILED="1"
python .\\qu1cksc0pe.py --file app.apk --analyze --report
```

| Variable | Default | What It Does |
| :--- | :--- | :--- |
| `SC0PE_ANDROID_REPORT_DETAILED` | `0` | Android analyzer JSON becomes more verbose (keeps larger fields and higher limits). Includes more details under `resource_scan`, and keeps large duplicate fields like `code_patterns` more often. |
| `SC0PE_WINDOWS_REPORT_DETAILED` | `0` | Windows analyzer stores per-category API lists in more detail (instead of unique API names only). |
| `SC0PE_AUTO_DECRYPT_CHAIN` | `0` | Document analyzer: when an Office document decryption succeeds, automatically re-runs analysis on the decrypted output (best-effort). |
| `SC0PE_AI_INTERESTING_PATTERNS_MAX_KEYS` | `25` | AI analyzer: limit how many keys from `interesting_string_patterns` are included in the LLM prompt. |
| `SC0PE_AI_INTERESTING_PATTERNS_MAX_VALUES` | `30` | AI analyzer: limit list size per `interesting_string_patterns` key in the LLM prompt. |
| `SC0PE_AI_INCLUDE_TEMP_EXCERPT` | `0` | AI analyzer: include raw `temp.txt` excerpt in prompt when set to `1` (default is parsed/summarized mode without raw excerpt). |
| `SC0PE_AI_TEMP_TXT_EXCERPT_CHARS` | `800` | AI analyzer: character limit for raw `temp.txt` excerpt (used when `SC0PE_AI_INCLUDE_TEMP_EXCERPT=1`). |
| `SC0PE_AI_TEMP_TXT_MAX_STRINGS` | `50` | AI analyzer: limit number of meaningful strings selected from parsed `temp.txt`. |
| `SC0PE_AI_TEMP_TXT_MIN_LEN` | `6` | AI analyzer: minimum length for a meaningful string extracted from `temp.txt`. |
| `SC0PE_AI_TEMP_TXT_MAX_LEN` | `180` | AI analyzer: maximum length for a meaningful string extracted from `temp.txt`. |
| `SC0PE_AI_TEMP_PARSE_MAX_BYTES` | `2097152` | AI analyzer: max bytes to parse from `temp.txt` while building compact evidence. |
| `SC0PE_AI_TEMP_PARSE_MAX_LINES` | `12000` | AI analyzer: max lines to parse from `temp.txt`. |
| `SC0PE_AI_TEMP_SAMPLE_LINES` | `2500` | AI analyzer: sample size used for meaningful-string scoring. |
| `SC0PE_AI_TEMP_IOC_CAP` | `40` | AI analyzer: cap for IoC candidates parsed from `temp.txt`. |
| `SC0PE_AI_TEMP_IOC_PROMPT_MAX` | `20` | AI analyzer: max parsed IoC values per kind sent to LLM prompt. |
| `SC0PE_AI_MAX_REPORT_CHARS` | `180000` | AI analyzer: threshold for full-report prompt mode; larger reports are compacted automatically. |
| `SC0PE_AI_COMPACT_MAX_LIST_ITEMS` | `40` | AI analyzer: list sampling limit in compact report mode. |
| `SC0PE_AI_COMPACT_MAX_STR` | `220` | AI analyzer: max string length per field in compact report mode. |
| `SC0PE_AI_COMPACT_MAX_DEPTH` | `4` | AI analyzer: nested depth limit in compact report mode. |
| `SC0PE_AI_OLLAMA_HTTP_TIMEOUT` | `60` | AI analyzer: Ollama HTTP call timeout (seconds). |
| `SC0PE_AI_HTTP_PROBE_TIMEOUT` | `20` | AI analyzer: short probe timeout before full HTTP generation call (seconds). |
| `SC0PE_AI_OLLAMA_CLI_TIMEOUT` | `90` | AI analyzer: Ollama CLI call timeout (seconds). |
| `SC0PE_AI_TOTAL_BUDGET` | `120` | AI analyzer: total generation budget across retries/fallback attempts (seconds). |
| `SC0PE_AI_OLLAMA_NUM_PREDICT` | `700` | AI analyzer: default generation token budget per Ollama call. |
| `SC0PE_AI_OLLAMA_RETRY_NUM_PREDICT` | `1400` | AI analyzer: generation token budget for retry when output looks truncated. |
| `SC0PE_AI_OLLAMA_NUM_CTX` | `8192` | AI analyzer: Ollama context window setting. |
| `SC0PE_AI_DISABLE_THINK` | `1` | AI analyzer: sends `think=false` (if supported) and removes thinking artifacts from displayed/saved output. |
| `SC0PE_AI_ALLOW_SHORT_DOMAINS` | `0` | IoC sanitizer: allow very short SLD domains (disabled by default to reduce false positives). |
| `SC0PE_AI_MIN_SLD_LEN` | `4` | IoC sanitizer: minimum registrable-label length for domain validation. |
| `SC0PE_AI_ALLOW_FILELIKE_TLDS` | `0` | IoC sanitizer: when `0`, filters file-like pseudo-domains such as `sheet1.xml`. |
| `SC0PE_AI_KEEP_LOCAL_PATHS` | `0` | IoC sanitizer: when `0`, removes local analysis machine paths from `file_paths`. |
| `SC0PE_EMAIL_DNSBL_FILTER_NOISY` | `1` | Email analyzer: filter noisy DNSBL providers to reduce false positives. |
| `SC0PE_EMAIL_DNSBL_ALLOW_UNKNOWN` | `0` | Email analyzer: include/exclude DNSBL hits with unknown category. |
| `SC0PE_EMAIL_DNSBL_NOISY_PROVIDERS` | unset | Email analyzer: comma-separated extra DNSBL providers to treat as noisy. |
| `SC0PE_AUTO_CLEANUP_ATTACHMENTS` | unset | Email analyzer: set `1` for auto-delete, `0` for never-delete, unset for interactive prompt. |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | AI report analysis backend (Ollama). Set this if Ollama is remote or on a different host/port. |
| `JAVA_HOME` | unset | Android analyzer: helps locate Java runtime for JADX. Set this if Java is installed but not detected. |

# Static Analysis
## Normal analysis
<i><b>Description</b>: You can perform basic analysis and triage against your samples.</i>

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_file --analyze```<br>
![windows_analyze](https://github.com/CYB3RMX/Qu1cksc0pe/assets/42123683/bd6945b6-5198-42fb-adff-2118a596bf58)

## Resource analysis
<i><b>Description</b>: With this feature you can analyze assets of given file. Also you can detect and extract embedded payloads from malware samples such as AgentTesla, Formbook etc.</i>

<b>Effective Against</b>:
- .NET Executables

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_file --resource```<br>

> [!NOTE]
> Android APK resource scanning was moved into the Android analyzer. Use:
> `python qu1cksc0pe.py --file app.apk --analyze --report`
> The JSON report includes `resource_scan`. Set `SC0PE_ANDROID_REPORT_DETAILED=1` to keep more details in the report.
![resource](https://user-images.githubusercontent.com/42123683/189416431-de08337f-8d46-4c9c-a635-59a5faca28ff.gif)

## Hash scan
<i><b>Description</b>: You can check if hash value of the given file is in built-in malware hash database. Also you can scan your directories with this feature.</i>

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_file --hashscan```<br>
![hash](https://user-images.githubusercontent.com/42123683/189416516-8268817c-f186-4ee9-971e-adcccfcb45eb.gif)

## Folder scan
<b>Supported Arguments</b>:
- ```--hashscan```
- ```--packer```

<b>Usage</b>: ```python qu1cksc0pe.py --folder FOLDER --hashscan```<br>
![hashscan_tui](https://user-images.githubusercontent.com/42123683/189416636-494f8d0b-4692-4b81-b133-8bd5eb0f5683.gif)

## VirusTotal
<b>Report Contents</b>:
- ```Threat Categories```
- ```Detections```
- ```CrowdSourced IDS Reports```

<b>Usage for --vtFile</b>: ```python qu1cksc0pe.py --file suspicious_file --vtFile```<br>
> [!NOTE]
> In Web UI flow, `Standart Analysis` and `Document` presets also execute VirusTotal file lookup in background and show the result in the report page.

![total](https://user-images.githubusercontent.com/42123683/189416676-06216d52-4882-492d-9ee4-4ff7c04b6358.gif)

## Document scan
<i><b>Description</b>: This feature can perform deep file inspection against given document files. For example: You can detect and extract possible malicious links or embedded exploits/payloads from your suspicious document file easily!</i>

<b>Effective Against</b>:
- Word Documents (.doc, .docm, .docx)
- Excel Documents (.xls, .xlsm, .xlsx)
- Portable Document Format (.pdf)
- OneNote Documents (.one)
- HTML Documents (.htm, .html)
- Rich Text Format Documents (.rtf)
- VBScript/VBA Family (.vbs, .vbe, .vba, .vb, .bas, .cls, .frm)

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_document --docs```<br>
![docs](https://user-images.githubusercontent.com/42123683/189416778-f7f93d49-7ff0-4eb5-9898-53e63e5833a1.gif)

## Batch Script scan (.bat/.cmd)
<i><b>Description</b>: Analyze Windows Batch scripts for suspicious commands, encoded payload patterns, URLs/domains/IPs, and rule matches.</i>

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_script.bat --analyze --report```<br>

### Embedded File/Exploit Extraction
![exploit](https://user-images.githubusercontent.com/42123683/189676461-86565ff2-3a0c-426a-a66b-80a9462489b7.gif)

## Archive File Scan
<i><b>Description</b>: With this feature you can perform checks for suspicious files against archive files.</i>

<b>Effective Against</b>:
- ZIP
- RAR 
- ACE
 
<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_archive_file --archive```

> [!NOTE]
> ACE archive support requires `7z`/`7zz` to be installed (setup scripts install it on supported systems).
![archiveanalysis](https://user-images.githubusercontent.com/42123683/230241452-0d93d2ca-69a2-42d9-aa99-c9c7cfe637bf.gif)

## File signature analyzer
<i><b>Description</b>: With this feature you can detect and extract embedded executable files(.exe, .elf) from given file. Also you can analyze large files (even 1gb or higher) and extract actual malware samples from them (pumped-file analysis).</i>

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_file --sigcheck```<br>
![sigcheck](https://user-images.githubusercontent.com/42123683/189416864-0e3e3be0-a7bf-4d35-bd9d-403afc38bb96.gif)

### File Carving
![carving](https://user-images.githubusercontent.com/42123683/189416908-31a06ac7-778a-48bd-a5f7-26708a255340.gif)

## MITRE ATT&CK Technique Extraction
<i><b>Description</b>: This feature allows you to generate potential MITRE ATT&CK tables based on the import/export table or functions contained within the given file.</i>

<b>Effective Against</b>:
- Windows Executables

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_file --mitre```<br>
![mitre](https://user-images.githubusercontent.com/42123683/189416941-46e8be6b-2eec-4145-b0b8-b0da78d6611e.gif)

## Programming language detection
<i><b>Description</b>: You can get programming language information from given file.</i>

<b>Usage</b>: ```python qu1cksc0pe.py --file suspicious_executable --lang```<br>
![langdetect](https://user-images.githubusercontent.com/42123683/228696312-1362cc48-f978-40c9-a0f0-22a216b83f6f.gif)

## Interactive shell
<i><b>Description</b>: You can use Qu1cksc0pe in command line mode.</i>

<b>Usage</b>: ```python qu1cksc0pe.py --console```<br>
![console](https://user-images.githubusercontent.com/42123683/189417009-dec6a91b-228c-4c7e-9579-66c4aa9f4036.gif)

# Dynamic Analysis
## Android Application Analysis
> [!NOTE]
> You must connect a virtual device or physical device to your computer.

<br><b>Usage</b>: ```python qu1cksc0pe.py --watch```<br>

https://github.com/user-attachments/assets/7b27abb9-f18e-4611-8bdd-cd65106b5cf0

## Linux Dynamic Analysis
<i><b>Description</b>: Linux dynamic flow is menu-driven and lets you choose emulation or live process monitoring.</i>

<br><b>Usage</b>: ```python qu1cksc0pe.py --watch```<br>

After selecting Linux:
- Option `1`: Binary Emulation (isolated environment).
- Option `2`: PID Monitoring (`Frida` + `psutil`).

Notes:
- PID monitoring accepts both numeric PID and process name.
- Interactive Linux prompts support TAB autocomplete (selection, path, PID/name).
- Emulation fallback order: Docker SDK -> Docker CLI -> host `qemu` (if Docker is unavailable).

## Windows Process Analysis
<br><b>Usage</b>: ```python qu1cksc0pe.py --watch```<br>

https://github.com/CYB3RMX/Qu1cksc0pe/assets/42123683/a2c84b8f-c12c-47ac-96e9-c345aeda1f54

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
- <a href="https://korben.info/qu1cksc0pe-analyse-logiciels-malveillants.html">Korben - Blog Post</a>
- <a href="https://www.heise.de/ratgeber/Malware-Analysetool-Schadpotenzial-von-Daten-mit-Qu1cksc0pe-ermitteln-10001929.html">heise online - Blog Post</a>
