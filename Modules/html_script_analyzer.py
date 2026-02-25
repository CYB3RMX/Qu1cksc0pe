#!/usr/bin/python3

import re
import os
import sys
import json
import base64
import subprocess
import configparser
import urllib.parse
from bs4 import BeautifulSoup
from analysis.multiple.multi import chk_wlist, perform_strings, yara_rule_scanner, calc_hashes
from utils.helpers import err_exit, get_argv, save_report

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
URL_REGEX = r"https?://[^\s'\"<>()]+"
URL_PATTERN = re.compile(URL_REGEX)

# Target file
targetFile = sys.argv[1]

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# All strings
allstr = "\n".join(perform_strings(targetFile))

# Parsing config file to get rule path
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf", encoding="utf-8-sig")

# Report — document schema (matches document_analyzer.py so save_report("document",...) works)
report = {
    "filename": "",
    "document_type": "",
    "file_magic": "",
    "hash_md5": "",
    "hash_sha1": "",
    "hash_sha256": "",
    "all_strings": 0,
    "categorized_findings": 0,
    "is_ole_file": False,
    "is_encrypted": False,
    "matched_rules": [],
    "extracted_urls": [],
    "macros": {
        "extracted": False,
        "vba": [],
        "xlm": [],
        "truncated": {
            "vba": 0,
            "xlm": 0
        }
    },
    "script_analysis": {
        "language": "",
        "vbe_encoded": False,
        "categories": {},
        "createobject_values": [],
        "shell_commands": [],
        "decoded_payload_hints": []
    },
    "embedded_files": [],
    "extracted_files": [],
    "sections": {},
    "decryption": {
        "attempted": False,
        "success": False,
        "output_file": "",
        "error": "",
        "auto_analysis": {
            "triggered": False,
            "target_file": "",
            "exit_code": None
        }
    }
}


class HTMLScriptAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self._findings_seen = set()
        report["filename"] = self.targetFile
        calc_hashes(self.targetFile, report)
        report["all_strings"] = len(allstr.split("\n"))
        self.base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_html_codes.json", "r") as fp:
            self.mal_code = json.load(fp)

    # ── Utility helpers ──────────────────────────────────────────────────────

    def _append_unique(self, key, value):
        if value and value not in report[key]:
            report[key].append(value)

    def _add_finding(self, category, value):
        finding_key = f"{category}:{value}"
        if value and finding_key not in self._findings_seen:
            self._findings_seen.add(finding_key)
            report["categorized_findings"] += 1

    def _register_section(self, key, value):
        report["sections"][key] = value

    def _sanitize_text(self, value):
        sanitized = ""
        for ch in str(value):
            sanitized += ch if ch.isprintable() else f"\\x{ord(ch):02x}"
        return sanitized

    def _sanitize_and_truncate(self, value, max_chars):
        sanitized = self._sanitize_text(value)
        if max_chars is None:
            return sanitized, False
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 0
        if max_chars > 0 and len(sanitized) > max_chars:
            return sanitized[:max_chars] + "\\n...<truncated>...", True
        return sanitized, False

    def _normalize_url(self, raw_url):
        candidate = raw_url.strip().rstrip(".,;:)]}>\"'")
        parsed = urllib.parse.urlparse(candidate)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.netloc:
            return None
        host = parsed.netloc.split("@")[-1].split(":")[0].strip("[]")
        if host == "":
            return None
        return candidate

    def _extract_normalized_urls(self, text_buffer):
        urls = []
        for raw_url in URL_PATTERN.findall(text_buffer):
            sanitized = self._normalize_url(raw_url)
            if sanitized and chk_wlist(sanitized) and sanitized not in urls:
                urls.append(sanitized)
        return urls

    @staticmethod
    def _is_short_symbolic_string(text):
        if len(text) > 6:
            return False
        symbol_chars = [")", "(", "[", "]", "+", "-", "<", ">", "*", "!"]
        return any(symbol in text for symbol in symbol_chars)

    def output_writer(self, out_file, mode, buffer):
        with open(out_file, mode) as ff:
            ff.write(buffer)
        print(f"{infoS} Data saved as: [bold yellow]{out_file}[white]")
        self._append_unique("extracted_files", out_file)

    # ── Shared analysis helpers ───────────────────────────────────────────────

    def html_fetch_urls(self, given_buffer):
        print(f"\n{infoS} Checking URL values...")
        url_vals = self._extract_normalized_urls(given_buffer)
        if not url_vals:
            print(f"{errorS} There is no URL value found!")
            return

        for sanitized in url_vals:
            self._append_unique("extracted_urls", sanitized)
        url_table = Table()
        url_table.add_column("[bold green]URL Values", justify="center")
        for url in url_vals:
            url_table.add_row(url)
        print(url_table)
        self._add_finding("Other", f"url_count={len(url_vals)}")

    def html_detect_malicious_code(self, given_buffer):
        # Check for malicious code patterns
        print(f"\n{infoS} Performing detection of the malicious code patterns...")
        mind = 0
        for mc in self.mal_code:
            mtc = re.findall(mc, given_buffer, re.IGNORECASE)
            if mtc != []:
                mind += 1
                self.mal_code[mc]["count"] = len(mtc)
        if mind != 0:
            att_types = []
            mal_table = Table()
            mal_table.add_column("[bold green]Pattern", justify="center")
            mal_table.add_column("[bold green]Description", justify="center")
            for mc in self.mal_code:
                if self.mal_code[mc]["count"] != 0:
                    mal_table.add_row(str(mc), self.mal_code[mc]["description"])
                    self._add_finding("HTML", f"{mc}:{self.mal_code[mc]['count']}")

                    # Parsing attack keywords
                    if self.mal_code[mc]["type"] not in att_types:
                        att_types.append(self.mal_code[mc]["type"])
            print(mal_table)
            print(f"{infoS} Keywords for this sample: [bold red]{att_types}[white]")
            self._register_section("html_attack_keywords", att_types)
        else:
            print(f"{errorS} There is no pattern found!")

    # ── HTML-specific helpers ─────────────────────────────────────────────────

    def chk_b64(self, given_buffer):
        keywords_to_check = [r"function", r"_0x", r"parseInt", r"script", r"var", r"document", r"src", r"atob", r"eval"]
        decc = []
        for cod in re.findall(self.base64_pattern, given_buffer):
            try:
                decoded_text = base64.b64decode(cod).decode()
            except:
                continue

            if self._is_short_symbolic_string(decoded_text):
                continue

            key_count = 0
            for key in keywords_to_check:
                km = re.findall(key, decoded_text)
                if km != []:
                    key_count += 1

            # If we have target patterns and the decoded payload is very large, save it as file.
            if key_count != 0 and len(decoded_text) >= 150:
                print(f"\n{infoS} Warning length of the decoded data is bigger than as we expected!")
                self.output_writer(
                    out_file=f"qu1cksc0pe_decoded_javascript-{len(decoded_text)}.js",
                    mode="w",
                    buffer=decoded_text
                )
                continue
            decc.append(decoded_text)

        return decc if decc != [] else None

    def html_dump_javascript(self, soup_obj):
        # Dump javascript
        print(f"\n{infoS} Checking for Javascript...")
        javscr = soup_obj.find_all("script")
        if javscr != []:
            print(f"{infoS} Found [bold red]{len(javscr)}[white]. If there is a potential malicious one we will extract it...")
            self._add_finding("HTML", f"javascript_tag_count={len(javscr)}")
            for jv in javscr:
                jav_buf = jv.getText().replace("<script>", "").replace("</script>", "")
                # We need only malicious codes!
                mal_ind = 0
                for mcode in self.mal_code:
                    mtc = re.findall(mcode, jav_buf)
                    if mtc != []:
                        mal_ind += 1

                if mal_ind != 0 and len(jav_buf) > 0:
                    self.output_writer(out_file=f"qu1cksc0pe_carved_javascript-{len(jav_buf)}.js", mode="w", buffer=jav_buf)
        else:
            print(f"{errorS} There is no Javascript found!")

    def html_check_input_points(self, soup_obj):
        # Check for input points
        print(f"\n{infoS} Checking for input points...")
        inputz = soup_obj.find_all("input")
        if inputz != []:
            inp_table = Table()
            inp_table.add_column("[bold green]ID", justify="center")
            inp_table.add_column("[bold green]Name", justify="center")
            inp_table.add_column("[bold green]Type", justify="center")
            inp_table.add_column("[bold green]Value", justify="center")
            for inp in inputz:
                input_template = {
                    "id": None,
                    "name": None,
                    "type": None,
                    "value": None
                }
                try:
                    # Check for values
                    for key in input_template:
                        input_template[key] = inp.get(key)

                    inp_table.add_row(str(input_template["id"]), str(input_template["name"]), str(input_template["type"]), str(input_template["value"]))
                except:
                    continue
            print(inp_table)
        else:
            print(f"{errorS} There is no input point found!")

    def html_check_iframe_tag(self, soup_obj):
        # Check for iframe tag
        print(f"\n{infoS} Checking for iframe presence...")
        ifr = soup_obj.find_all("iframe")
        if ifr != []:
            ifr_table = Table()
            ifr_table.add_column("[bold green]Source", justify="center")
            for ii in ifr:
                ifr_template = {
                    "src": None
                }
                try:
                    #Check values
                    for key in ifr_template:
                        ifr_template[key] = ii.get(key)

                    ifr_table.add_row(str(ifr_template["src"]))
                except:
                    continue
            print(ifr_table)
        else:
            print(f"{errorS} There is no iframe presence!")

    def html_check_suspicious_files(self, given_buffer):
        # Check suspicious files
        susp_file_pattern = [r'\b\w+\.exe\b', r'\b\w+\.ps1\b', r'\b\w+\.hta\b', r'\b\w+\.bat\b', r'\b\w+\.zip\b', r'\b\w+\.rar\b']
        print(f"\n{infoS} Checking for suspicious filename patterns...")
        indicator = 0
        for sus in susp_file_pattern:
            smt = re.findall(sus, given_buffer)
            if smt != []:
                indicator += 1
                for pat in smt:
                    print(f"[bold magenta]>>>[white] {pat}")
                    self._add_finding("HTML", f"suspicious_file:{pat}")

        if indicator == 0:
            print(f"{errorS} There is no suspicious pattern found!")

    def html_check_powershell_codes(self, given_buffer):
        pow_code = [r"AppData", r"Get-Random", r"New-Object", r"System.Random", r"Start-BitsTransfer", r"Remove-Item", r"New-ItemProperty"]
        powe_table = Table()
        powe_table.add_column("[bold green]Pattern", justify="center")
        powe_table.add_column("[bold green]Occurence", justify="center")
        pind = 0
        for co in pow_code:
            mtch = re.findall(co, given_buffer, re.IGNORECASE)
            if mtch != []:
                pind += 1
                powe_table.add_row(co, str(len(mtch)))
                self._add_finding("HTML", f"powershell_pattern:{co}")
        if pind != 0:
            print(f"\n{infoS} Looks like we found powershell code patterns!")
            print(powe_table)

    # ── File type detection ───────────────────────────────────────────────────

    def CheckExt(self):
        doc_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        decoded_doc_type = doc_type.stdout.decode()
        lower_file = self.targetFile.lower()
        report["file_magic"] = decoded_doc_type.strip()
        if lower_file.endswith(".js"):
            return "javascript"
        if lower_file.endswith(".hta"):
            return "hta"
        if "HTML document" in decoded_doc_type:
            return "html"
        return "unknown"

    # ── Main analyzers ────────────────────────────────────────────────────────

    def HTMLanalysis(self):
        print(f"{infoS} Performing HTML analysis...")
        soup_analysis = BeautifulSoup(allstr, "html.parser")

        # Check for malicious code patterns
        self.html_detect_malicious_code(given_buffer=allstr)

        # Fetch url values
        self.html_fetch_urls(given_buffer=allstr)

        # Dump javascript
        self.html_dump_javascript(soup_obj=soup_analysis)

        # Check for input points
        self.html_check_input_points(soup_obj=soup_analysis)

        # Check for iframe presence
        self.html_check_iframe_tag(soup_obj=soup_analysis)

        # Check for powershell patterns
        self.html_check_powershell_codes(given_buffer=allstr)

        # Print possible base64 decoded values
        print(f"\n{infoS} Extracting possible decoded [bold green]BASE64[white] values...")
        decodd = self.chk_b64(given_buffer=allstr)
        if decodd:
            for dd in decodd:
                print(f"[bold magenta]>>>[white] {dd}")
            self._add_finding("HTML", f"decoded_base64={len(decodd)}")
        else:
            print(f"{errorS} There is no potential encoded BASE64 value found!")

        # Check suspicious files
        self.html_check_suspicious_files(given_buffer=allstr)

        # Check for unescape pattern
        if self.mal_code["unescape"]["count"] != 0:
            print(f"\n{infoS} Looks like we have a obfuscated data (via [bold green]unescape[white])")
            print(f"{infoS} Performing extraction...")
            un_dat = re.findall(r"unescape\('([^']+)'", allstr)
            if un_dat != []:
                for escape in un_dat:
                    deobf = urllib.parse.unquote(escape)
                    self.output_writer(out_file=f"qu1cksc0pe_decoded_unescape-{len(deobf)}.bin", mode="w", buffer=deobf)

                    # After extracting the data also we need to scan it!
                    print(f"\n{infoS} Performing analysis against [bold yellow]qu1cksc0pe_decoded_unescape-{len(deobf)}.bin[white]")
                    if "html" in deobf:
                        new_soup = BeautifulSoup(deobf, "html.parser")
                        self.html_check_input_points(soup_obj=new_soup)
                        self.html_check_iframe_tag(soup_obj=new_soup)
                        self.html_detect_malicious_code(given_buffer=deobf)
                        self.html_check_suspicious_files(given_buffer=deobf)

    def JSAnalysis(self):
        print(f"{infoS} Performing JavaScript static analysis...")
        try:
            with open(self.targetFile, "rb") as fptr:
                script_bytes = fptr.read()
        except Exception as exc:
            err_exit(f"{errorS} Could not read target script. Details: {exc}")

        script_text = script_bytes.decode("utf-8", errors="ignore")
        if script_text.strip() == "":
            script_text = allstr

        report["script_analysis"]["language"] = "JavaScript"

        js_patterns = {
            "Execution": [
                r"\beval\s*\(",
                r"\bnew\s+Function\s*\(",
                r"\bsetTimeout\s*\(",
                r"\bsetInterval\s*\(",
            ],
            "Obfuscation": [
                r"\b_0x[0-9a-fA-F]+\b",
                r"\bString\.fromCharCode\s*\(",
                r"\bunescape\s*\(",
                r"\batob\s*\(",
                r"\bbtoa\s*\(",
                r"[A-Za-z0-9+/]{100,}={0,2}",
            ],
            "Network": [
                r"\bXMLHttpRequest\b",
                r"\bfetch\s*\(",
                r"\bWebSocket\s*\(",
                r"\bActiveXObject\s*\(",
                r"\bWScript\.Shell\b",
            ],
            "Shell/Execution": [
                r"\brequire\s*\(\s*['\"]child_process['\"]",
                r"\bexecSync\s*\(",
                r"\bspawnSync\s*\(",
                r"\bprocess\.env\b",
            ],
            "FileSystem": [
                r"\brequire\s*\(\s*['\"]fs['\"]",
                r"\bfs\.write(?:File)?(?:Sync)?\s*\(",
                r"\bfs\.read(?:File)?(?:Sync)?\s*\(",
                r"\bScripting\.FileSystemObject\b",
            ],
            "Persistence": [
                r"\bWScript\.Shell\b.{0,60}RegWrite\b",
                r"\bschtasks\b",
                r"CurrentVersion\\\\Run\b",
            ],
        }

        summary_table = Table(title="* JavaScript Pattern Summary *", title_style="bold italic cyan", title_justify="center")
        summary_table.add_column("[bold green]Category", justify="center")
        summary_table.add_column("[bold green]Count", justify="center")

        for category, p_list in js_patterns.items():
            hits = []
            seen = set()
            for pattern in p_list:
                for mt in re.finditer(pattern, script_text, re.IGNORECASE):
                    matched = mt.group(0).strip()
                    if matched and matched not in seen:
                        seen.add(matched)
                        hits.append(self._sanitize_text(matched))
            if hits:
                summary_table.add_row(f"[bold red]{category}", str(len(hits)))
                self._add_finding("JavaScript", f"{category.lower()}={len(hits)}")
            else:
                summary_table.add_row(category, "0")
            report["script_analysis"]["categories"][category] = hits
            self._register_section(f"js_{category.lower()}_hits", hits)

        print(summary_table)

        # Reuse malicious HTML/JS pattern database (eval, atob, XMLHttpRequest, WScript.Shell, etc.)
        self.html_detect_malicious_code(given_buffer=script_text)

        # Base64 decode hints
        decoded_hints = []
        b64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", script_text)
        for candidate in b64_candidates[:30]:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            except Exception:
                continue
            decoded = decoded.strip()
            if len(decoded) < 20:
                continue
            printable_ratio = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
            if printable_ratio < 0.80:
                continue
            hint, truncated = self._sanitize_and_truncate(decoded, 200)
            if hint and hint not in decoded_hints:
                decoded_hints.append(hint)
            if truncated:
                self._add_finding("JavaScript", "decoded_payload_truncated")
            if len(decoded_hints) >= 15:
                break
        report["script_analysis"]["decoded_payload_hints"] = decoded_hints
        self._register_section("js_decoded_payload_hint_count", len(decoded_hints))
        if decoded_hints:
            dec_table = Table(title="* Decoded Payload Hints *", title_style="bold italic cyan", title_justify="center")
            dec_table.add_column("[bold green]Snippet", justify="center")
            for hint in decoded_hints:
                dec_table.add_row(hint)
            print(dec_table)

        # URL extraction
        print(f"\n{infoS} Looking for embedded URL values...")
        url_hits = self._extract_normalized_urls(script_text)
        if url_hits:
            url_table = Table(title="* Extracted URLs *", title_style="bold italic cyan", title_justify="center")
            url_table.add_column("[bold green]URL", justify="center")
            for url in url_hits:
                url_table.add_row(url)
                self._append_unique("extracted_urls", url)
            print(url_table)
            self._add_finding("JavaScript", f"url_count={len(url_hits)}")
        else:
            print(f"{errorS} There is no URL value found!")

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

    def HTAAnalysis(self):
        print(f"{infoS} Performing HTA (HTML Application) analysis...")
        try:
            with open(self.targetFile, "rb") as fptr:
                hta_bytes = fptr.read()
        except Exception as exc:
            err_exit(f"{errorS} Could not read target file. Details: {exc}")

        hta_text = hta_bytes.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(hta_text, "html.parser")

        # HTA application metadata
        hta_tag = soup.find("hta:application")
        if hta_tag:
            print(f"\n{infoS} HTA application metadata found:")
            hta_meta = {}
            for attr in ["applicationname", "singleinstance", "windowstate", "navigable", "icon", "border", "borderstyle"]:
                val = hta_tag.get(attr)
                if val:
                    print(f"[bold magenta]>>>[white] {attr}: [bold green]{val}")
                    hta_meta[attr] = val
            self._register_section("hta_application_meta", hta_meta)
        else:
            print(f"\n{infoS} No [bold yellow]<HTA:APPLICATION>[white] tag found.")

        # Determine scripting language from script tags
        script_lang = "JScript"
        for tag in soup.find_all("script"):
            lang_attr = (tag.get("language") or "").lower()
            if "vbscript" in lang_attr:
                script_lang = "VBScript"
                break
        print(f"{infoS} Detected script language: [bold green]{script_lang}")
        self._register_section("hta_script_language", script_lang)
        report["script_analysis"]["language"] = f"HTA/{script_lang}"

        # HTML analysis components
        self.html_detect_malicious_code(given_buffer=hta_text)
        self.html_fetch_urls(given_buffer=hta_text)
        self.html_dump_javascript(soup_obj=soup)
        self.html_check_iframe_tag(soup_obj=soup)
        self.html_check_powershell_codes(given_buffer=hta_text)
        self.html_check_suspicious_files(given_buffer=hta_text)

        # Extract and scan inline script block content
        script_blocks = []
        for tag in soup.find_all("script"):
            block = tag.get_text()
            if block.strip():
                script_blocks.append(block)
        combined_scripts = "\n".join(script_blocks)

        if combined_scripts.strip():
            print(f"\n{infoS} Scanning [bold green]{len(script_blocks)}[white] inline script block(s)...")
            if script_lang == "VBScript":
                vb_patterns = {
                    "Execution": [
                        r"\bCreateObject\s*\(", r"\bWScript\.Shell\b", r"\bShell\s*\(", r"\bExec\s*\(", r"\bRun\s*\("
                    ],
                    "Network": [
                        r"\bMSXML2\.(?:XMLHTTP|ServerXMLHTTP)\b", r"\bWinHttp\.WinHttpRequest\b",
                        r"\bURLDownloadToFile(?:A|W)?\b", r"\bADODB\.Stream\b"
                    ],
                    "Obfuscation": [
                        r"\bChrW?\s*\(", r"\bStrReverse\s*\(", r"\bFromBase64String\b",
                        r"[A-Za-z0-9+/]{100,}={0,2}"
                    ],
                    "Persistence": [
                        r"\bRegWrite\b", r"\bCurrentVersion\\Run(?:Once)?\b", r"\bschtasks\b"
                    ],
                }
            else:
                vb_patterns = {
                    "Execution": [
                        r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"\bActiveXObject\s*\(", r"\bWScript\.Shell\b"
                    ],
                    "Network": [
                        r"\bXMLHttpRequest\b", r"\bfetch\s*\(", r"\bWebSocket\s*\("
                    ],
                    "Obfuscation": [
                        r"\b_0x[0-9a-fA-F]+\b", r"\bString\.fromCharCode\s*\(", r"\batob\s*\(",
                        r"[A-Za-z0-9+/]{100,}={0,2}"
                    ],
                    "Persistence": [
                        r"\bschtasks\b", r"CurrentVersion\\\\Run\b"
                    ],
                }

            script_table = Table(title="* Script Block Pattern Summary *", title_style="bold italic cyan", title_justify="center")
            script_table.add_column("[bold green]Category", justify="center")
            script_table.add_column("[bold green]Count", justify="center")
            for category, p_list in vb_patterns.items():
                hits = []
                seen = set()
                for pattern in p_list:
                    for mt in re.finditer(pattern, combined_scripts, re.IGNORECASE):
                        matched = mt.group(0).strip()
                        if matched and matched not in seen:
                            seen.add(matched)
                            hits.append(self._sanitize_text(matched))
                if hits:
                    script_table.add_row(f"[bold red]{category}", str(len(hits)))
                    self._add_finding("HTA", f"{category.lower()}={len(hits)}")
                else:
                    script_table.add_row(category, "0")
                report["script_analysis"]["categories"][category] = hits
            print(script_table)

        # Base64 decode hints from full HTA text
        decoded_hints = []
        b64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", hta_text)
        for candidate in b64_candidates[:30]:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            except Exception:
                continue
            decoded = decoded.strip()
            if len(decoded) < 20:
                continue
            printable_ratio = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
            if printable_ratio < 0.80:
                continue
            hint, truncated = self._sanitize_and_truncate(decoded, 200)
            if hint and hint not in decoded_hints:
                decoded_hints.append(hint)
            if len(decoded_hints) >= 15:
                break
        report["script_analysis"]["decoded_payload_hints"] = decoded_hints
        if decoded_hints:
            dec_table = Table(title="* Decoded Payload Hints *", title_style="bold italic cyan", title_justify="center")
            dec_table.add_column("[bold green]Snippet", justify="center")
            for hint in decoded_hints:
                dec_table.add_row(hint)
            print(dec_table)

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)


# Execution area
try:
    scriptObj = HTMLScriptAnalyzer(targetFile)
    ext = scriptObj.CheckExt()
    report["document_type"] = ext
    if ext == "html":
        scriptObj.HTMLanalysis()
    elif ext == "javascript":
        scriptObj.JSAnalysis()
    elif ext == "hta":
        scriptObj.HTAAnalysis()
    elif ext == "unknown":
        print(f"{errorS} File type not recognized as HTML, JavaScript, or HTA.")
    if get_argv(2) == "True":
        save_report("document", report)
except Exception as exc:
    err_exit(f"{errorS} An error occured while analyzing that file. Details: {exc}")
