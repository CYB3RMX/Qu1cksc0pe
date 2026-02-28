#!/usr/bin/python3

import re
import io
import os
import sys
import json
import math
import struct
import socket
import hashlib
import datetime
import binascii
import shutil
import ipaddress
import subprocess

from analysis.multiple.multi import chk_wlist
from utils.helpers import err_exit, user_confirm, save_report

try:
    from rich import print
    from rich.progress import track
    from rich.table import Table
except ImportError:
    err_exit("Error: >rich< module not found.")

try:
    import dpkt
except ImportError:
    err_exit("Error: >dpkt< module not found.")

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

if not shutil.which("ja3"):
    print(f"{errorS} Error: [bold green]ja3[white] command not found!")
    print(f"[bold red]>>>[white] Execute: [bold green]pip3 install pyja3[white]")
    sys.exit(1)

# Get python binary
if shutil.which("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
with open(".path_handler", "r") as _ph:
    sc0pe_path = _ph.read()

# Report generation is enabled when qu1cksc0pe.py passes "True" as the second argument,
# matching the convention used by powershell_analyzer.py, document_analyzer.py, etc.
report_mode = len(sys.argv) > 2 and sys.argv[2].strip().lower() == "true"

#--------------------------------------------- Detection constants

# Destination ports commonly used by C2 frameworks, RATs, and backdoors
_SUSPICIOUS_PORTS = {
    1337:  "Generic C2/RAT",
    4444:  "Metasploit default listener",
    4899:  "Radmin remote admin",
    5554:  "Sasser worm",
    5900:  "VNC remote access",
    6666:  "IRC C2",
    6667:  "IRC C2",
    6668:  "IRC C2",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
    9150:  "Tor Browser SOCKS",
    31337: "Back Orifice / classic backdoor",
}

# HTTP ports to inspect for request parsing (client→server direction)
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3128}

# TLS ports where ClientHello messages are expected
_TLS_PORTS = {443, 8443, 993, 995, 465}

# User-Agent substrings associated with automated/malicious tools
_SUSPICIOUS_USER_AGENTS = [
    "python-requests",
    "Go-http-client",
    "curl/",
    "Wget/",
    "libwww-perl",
    "masscan",
    "zgrab",
    "nmap",
    "sqlmap",
    "nikto",
    "dirbuster",
    "hydra",
]

#--------------------------------------------- Module-level helpers

def _is_private_ip(ip_str):
    """Return True if ip_str is an RFC-1918 / loopback / link-local address."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def _shannon_entropy(text):
    """Compute the Shannon entropy (bits) of the characters in text."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def _parse_tls_sni(data):
    """
    Extract the SNI hostname from a TLS ClientHello TCP payload.
    Returns the hostname string, or None if not found / parse error.
    """
    try:
        # TLS record header: content_type(1) + version(2) + length(2)
        if len(data) < 6 or data[0] != 0x16:   # 0x16 = Handshake
            return None
        if data[5] != 0x01:                      # 0x01 = ClientHello
            return None

        # Skip: record header(5) + handshake type(1) + length(3) +
        #        client_version(2) + random(32) = 43 bytes
        pos = 43

        # Session ID
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Cipher suites
        if pos + 2 > len(data):
            return None
        cipher_len = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2 + cipher_len

        # Compression methods
        if pos >= len(data):
            return None
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions length
        if pos + 2 > len(data):
            return None
        ext_total = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total

        while pos + 4 <= end:
            ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
            ext_len  = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            pos += 4
            if ext_type == 0x0000 and ext_len >= 5:  # SNI extension
                # name_list_len(2) + name_type(1) + name_len(2) + name
                name_len = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                sni = data[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
                return sni if sni else None
            pos += ext_len
    except Exception:
        return None
    return None

# Suspicious Win32 API imports worth flagging in a triage report
_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateThread",
    "ShellExecuteA", "ShellExecuteW", "WinExec",
    "CreateProcessA", "CreateProcessW",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyA", "RegCreateKeyW",
    "InternetOpenUrlA", "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect", "send", "recv",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}

_PE_SUBSYSTEMS = {
    1: "Native", 2: "GUI", 3: "Console",
    9: "WinCE GUI", 10: "EFI Application",
    14: "Xbox", 16: "Boot Application",
}

def _triage_pe(filepath):
    """
    Basic PE triage on a carved executable.
    Returns a dict with hashes, PE metadata, section entropy, suspicious
    imports, and IoC strings (URLs, IPs, email addresses) extracted from
    the raw binary data.
    """
    result = {}

    with open(filepath, "rb") as _f:
        data = _f.read()

    result["md5"]    = hashlib.md5(data).hexdigest()
    result["sha256"] = hashlib.sha256(data).hexdigest()

    # --- File type / MIME type (requires puremagic) ---
    try:
        import puremagic as _pm
        # Prefer matches that carry an actual MIME type; among those take
        # the one with the highest confidence score.
        mime_matches = [m for m in _pm.magic_file(filepath) if m.mime_type]
        if mime_matches:
            best = max(mime_matches, key=lambda m: m.confidence)
            result["mime_type"]  = best.mime_type
            result["file_type"]  = best.name
    except Exception:
        pass

    # --- PE metadata (requires pefile) ---
    try:
        import pefile as _pf
        pe = _pf.PE(data=data)

        result["architecture"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
        result["subsystem"] = _PE_SUBSYSTEMS.get(
            pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)
        )
        result["compile_timestamp"] = datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            ih = pe.get_imphash()
            if ih:
                result["imphash"] = ih
        except Exception:
            pass

        # Sections — flag any with entropy >= 6.8 (packed/encrypted content)
        sections = []
        for sec in pe.sections:
            name    = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            entropy = sec.get_entropy()
            sections.append({
                "name":         name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size":     sec.SizeOfRawData,
                "entropy":      round(entropy, 2),
                "packed":       entropy >= 6.8,
            })
        result["sections"] = sections

        # Suspicious imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            hits = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    name = (imp.name or b"").decode("ascii", errors="ignore")
                    if name in _SUSPICIOUS_IMPORTS:
                        hits.append(name)
            if hits:
                result["suspicious_imports"] = sorted(set(hits))

        pe.close()
    except Exception:
        pass

    # --- IoC strings from raw bytes ---
    urls = list({u.decode("ascii", errors="ignore")
                 for u in re.findall(rb"https?://[a-zA-Z0-9./@?=_%:&\-]+", data)})
    if urls:
        result["embedded_urls"] = urls[:30]

    ips = []
    for ip_b in set(re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", data)):
        try:
            ip_obj = ipaddress.ip_address(ip_b.decode())
            # Skip private/loopback addresses and IPs with any zero octet
            # (zero-octet addresses are almost always PE header artefacts)
            if not ip_obj.is_private and all(int(p) > 0 for p in ip_b.decode().split(".")):
                ips.append(ip_b.decode())
        except ValueError:
            pass
    if ips:
        result["embedded_ips"] = ips[:30]

    emails = list({e.decode("ascii", errors="ignore")
                   for e in re.findall(
                       rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}", data
                   )})
    if emails:
        result["embedded_emails"] = emails[:20]

    return result


class PcapAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        # Open the file once; derive the dpkt reader from a BytesIO view of the
        # same bytes so the raw buffer is also available for regex-based scans.
        with open(self.pcap_file, "rb") as f:
            self.all_content = f.read()
        self.pcap_content = dpkt.pcap.Reader(io.BytesIO(self.all_content))
        print(f"{infoS} Loading PCAP content. It will take a while please wait...")
        self.packet_content_array = []
        for _, buf in self.pcap_content:
            self.packet_content_array.append(buf)
        # Populated by search_dns_queries(); consumed by detect_dga_domains()
        self.dns_queries = []
        # Accumulated by every analysis method; flushed to JSON by save_report()
        self.reportz = {}

    def search_urls(self):
        url_table = Table()
        url_table.add_column("[bold green]Extracted URL\'s (Without whitelist domains)", justify="center")
        extracted_data = []
        print(f"{infoS} Performing URL extraction. It will take a while please wait...")
        for packet in track(self.packet_content_array, description="Processing packets..."):
            try:
                match = re.findall(rb"http[s]?://[a-zA-Z0-9./@?=_%:-]*", packet)
                if match:
                    for url in match:
                        if url not in extracted_data:
                            extracted_data.append(url)
            except Exception:
                continue
        final_urls = []
        if extracted_data:
            for i in extracted_data:
                if (i.decode() != "http://" and i.decode() != "https://") and ("." in i.decode()):
                    if chk_wlist(i.decode()):
                        url_table.add_row(i.decode())
                        final_urls.append(i.decode())
        self.reportz["extracted_urls"] = final_urls
        self.make_choice_and_print(url_table, "URL address", final_urls)

    def search_ip_addresses(self):
        print(f"\n{infoS} Performing IP Address extraction. It will take a while please wait...")
        ip_table = Table()
        ip_table.add_column("[bold green]Extracted IP Addresses", justify="center")
        uniq_ips = set()
        for buf in self.packet_content_array:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                uniq_ips.update([src_ip, dst_ip])
        for ips in uniq_ips:
            ip_table.add_row(ips)
        print(ip_table)

    def search_dns_queries(self):
        dns_table = Table()
        dns_table.add_column("[bold green]DNS Queries", justify="center")
        extracted_data = []
        print(f"\n{infoS} Performing extraction of DNS queries. It will take a while please wait...")
        for packet in track(self.packet_content_array, description="Processing packets..."):
            try:
                eth = dpkt.ethernet.Ethernet(packet)
            except Exception:
                continue
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):
                udp = eth.data.data
                if udp.dport == 53 or udp.sport == 53:
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                        if dns.qr == dpkt.dns.DNS_Q and dns.opcode == dpkt.dns.DNS_QUERY:
                            for question in dns.qd:
                                if question.name not in extracted_data:
                                    extracted_data.append(question.name)
                                    dns_table.add_row(question.name)
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        continue
        # Persist for detect_dga_domains() and the report
        self.dns_queries = extracted_data
        self.reportz["dns_queries"] = extracted_data
        self.make_choice_and_print(dns_table, "DNS queries", extracted_data)

    def detect_dga_domains(self):
        """
        Flag DNS-queried domains that show DGA or DNS-tunneling characteristics
        using three heuristics per domain label:
          - Shannon entropy > 3.5 on labels of 7+ characters (random-looking name)
          - Label length > 25 characters (long encoded subdomain = tunneling)
          - Digit ratio > 45 % (numerically heavy = algorithmic generation)
        Whitelisted domains are skipped to suppress false positives on CDN subdomains.
        """
        print(f"\n{infoS} Performing DGA / DNS-tunneling domain analysis...")
        if not self.dns_queries:
            print(f"{errorS} No DNS queries available for DGA analysis.")
            return

        dga_table = Table()
        dga_table.add_column("[bold green]Domain",       justify="center")
        dga_table.add_column("[bold green]Entropy",      justify="center")
        dga_table.add_column("[bold green]Label Length", justify="center")
        dga_table.add_column("[bold green]Digit Ratio",  justify="center")
        dga_table.add_column("[bold red]Indicator",      justify="center")

        flagged = []
        for domain in self.dns_queries:
            # Skip trusted domains
            if not chk_wlist(domain):
                continue

            labels = domain.rstrip(".").split(".")
            # Examine every label except the TLD
            for label in labels[:-1]:
                if len(label) < 6:
                    continue

                entropy    = _shannon_entropy(label)
                digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
                indicators = []

                if entropy > 3.5 and len(label) >= 7:
                    indicators.append(f"high entropy ({entropy:.2f})")
                if len(label) > 25:
                    indicators.append(f"long label ({len(label)} chars)")
                if digit_ratio > 0.45:
                    indicators.append(f"high digit ratio ({digit_ratio:.0%})")

                if indicators and domain not in flagged:
                    flagged.append(domain)
                    dga_table.add_row(
                        domain,
                        f"{entropy:.2f}",
                        str(len(label)),
                        f"{digit_ratio:.0%}",
                        ", ".join(indicators),
                    )
                    break   # one suspicious label is enough to flag the domain

        self.reportz["dga_suspicious_domains"] = flagged
        if flagged:
            print(f"{infoS} Found [bold red]{len(flagged)}[white] suspicious domain(s):")
            print(dga_table)
        else:
            print(f"{errorS} No DGA or DNS-tunneling indicators found.")

    def make_choice_and_print(self, table_obj, data_type, given_data):
        if given_data and len(given_data) <= 50:
            print(f"\n{infoS} We found [bold green]{len(given_data)}[white] valid {data_type}.")
            print(table_obj)
        elif given_data and len(given_data) > 50:
            print(f"\n{infoS} We found [bold red]{len(given_data)}[white] valid {data_type}.")
            if user_confirm(f">>> Do you want to print {len(given_data)} lines [y/n]?: "):
                print(table_obj)
        else:
            print(f"{errorS} There is no {data_type} found!")

    def find_interesting_stuff(self):
        stuff_table = Table()
        stuff_table.add_column("[bold green]Interesting Strings", justify="center")
        extracted_data = []
        interesting_stuff = [
            r'\b[a-zA-Z0-9_\-\\/:]+\.pdb', r'\b[a-zA-Z0-9_\-\\/:]+\.vbs',
            r'\b[a-zA-Z0-9_\-\\/:]+\.vba', r'\b[a-zA-Z0-9_\-\\/:]+\.vbe',
            r'\b[a-zA-Z0-9_\-\\/:]+\.exe', r'\b[a-zA-Z0-9_\-\\/:]+\.ps1',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dll', r'\b[a-zA-Z0-9_\-\\/:]+\.bat',
            r'\b[a-zA-Z0-9_\-\\/:]+\.cmd', r'\b[a-zA-Z0-9_\-\\/:]+\.tmp',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dmp', r'\b[a-zA-Z0-9_\-\\/:]+\.cfg',
            r'\b[a-zA-Z0-9_\-\\/:]+\.lnk', r'\b[a-zA-Z0-9_\-\\/:]+\.config',
            r'\b[a-zA-Z0-9_\-\\/:]+\.7z',  r'\b[a-zA-Z0-9_\-\\/:]+\.docx'
        ]
        print(f"\n{infoS} Performing analysis of interesting strings. It will take a while please wait...")
        for pattern in track(interesting_stuff, description="Processing buffer..."):
            matches = re.findall(pattern.encode(), self.all_content)
            if matches:
                for mm in matches:
                    try:
                        decoded = mm.decode()
                        if decoded and decoded[0] != "." and "." in decoded:
                            if decoded not in extracted_data:
                                extracted_data.append(decoded)
                                stuff_table.add_row(decoded)
                    except Exception:
                        continue
        self.reportz["interesting_strings"] = extracted_data
        self.make_choice_and_print(stuff_table, "Interesting strings", extracted_data)

    def detect_executables(self):
        print(f"\n{infoS} Performing embedded executable file detection. Please wait...")
        executable_sigs = {
            "Windows Executable": "4D5A9000"
        }
        valid_offsets = []
        for key in executable_sigs:
            regex = re.finditer(binascii.unhexlify(executable_sigs[key]), self.all_content)
            for pat in regex:
                if pat.start() not in valid_offsets:
                    valid_offsets.append(pat.start())
        self.reportz["embedded_executables_count"] = len(valid_offsets)
        if valid_offsets:
            print(f"{infoS} This PCAP file contains [bold red]{len(valid_offsets)}[white] possible executable files!!")
            print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] for embedded file extraction...")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{self.pcap_file}\" {report_mode}"
            os.system(command)
            # Collect metadata + triage for each file sigChecker.py actually carved
            carved = []
            for off in valid_offsets:
                carved_name = f"qu1cksc0pe_carved-{off}.bin"
                if os.path.exists(carved_name):
                    entry = {
                        "filename":   carved_name,
                        "offset_hex": hex(off),
                        "size_bytes": os.path.getsize(carved_name),
                    }
                    try:
                        entry["triage"] = _triage_pe(carved_name)
                    except Exception:
                        pass
                    carved.append(entry)
            if carved:
                self.reportz["carved_executables"] = carved
        else:
            print(f"{errorS} There is no executable file pattern found!")

    def analyze_connections(self):
        """
        Build a connection inventory from all TCP/UDP packets.
        Reports:
          1. Connections to known suspicious/C2 destination ports.
          2. Unique external (public) IP addresses contacted.
        """
        print(f"\n{infoS} Performing connection analysis...")

        seen        = set()
        suspicious  = []
        ext_ips     = set()

        for buf in self.packet_content_array:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip  = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto  = "TCP"
                sport  = ip.data.sport
                dport  = ip.data.dport
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto  = "UDP"
                sport  = ip.data.sport
                dport  = ip.data.dport
            else:
                continue

            key = (src, sport, dst, dport, proto)
            if key in seen:
                continue
            seen.add(key)

            if dport in _SUSPICIOUS_PORTS:
                suspicious.append((src, dst, dport, proto, _SUSPICIOUS_PORTS[dport]))

            if not _is_private_ip(dst):
                ext_ips.add(dst)

        self.reportz["suspicious_connections"] = [
            {"src": s, "dst": d, "port": p, "proto": proto, "reason": reason}
            for s, d, p, proto, reason in suspicious
        ]
        self.reportz["external_ips"] = sorted(ext_ips)

        # --- Suspicious port connections ---
        if suspicious:
            susp_table = Table()
            susp_table.add_column("[bold green]Source IP",      justify="center")
            susp_table.add_column("[bold green]Destination IP", justify="center")
            susp_table.add_column("[bold green]Port",           justify="center")
            susp_table.add_column("[bold green]Protocol",       justify="center")
            susp_table.add_column("[bold red]Reason",           justify="center")
            for s, d, p, proto, reason in suspicious:
                susp_table.add_row(s, d, str(p), proto, reason)
            print(f"{infoS} Found [bold red]{len(suspicious)}[white] suspicious connection(s):")
            print(susp_table)
        else:
            print(f"{errorS} No connections to known suspicious ports found.")

        # --- External IP summary ---
        if ext_ips:
            ext_table = Table()
            ext_table.add_column("[bold green]External (Public) IP Addresses", justify="center")
            for ip_addr in sorted(ext_ips):
                ext_table.add_row(ip_addr)
            print(f"\n{infoS} Found [bold green]{len(ext_ips)}[white] unique external IP(s):")
            print(ext_table)

    def analyze_http_requests(self):
        """
        Parse TCP packets destined for common HTTP ports using dpkt.http.Request.
        Extracts method, Host, URI, and User-Agent for each unique request.
        Flags User-Agents that match known automated/malicious tool signatures.
        """
        print(f"\n{infoS} Performing HTTP traffic analysis...")

        req_table  = Table()
        req_table.add_column("[bold green]Method",     justify="center")
        req_table.add_column("[bold green]Host",       justify="center")
        req_table.add_column("[bold green]URI",        justify="center")
        req_table.add_column("[bold green]User-Agent", justify="center")

        ua_table = Table()
        ua_table.add_column("[bold green]User-Agent",       justify="center")
        ua_table.add_column("[bold red]Suspicious Pattern", justify="center")

        seen_requests  = set()
        seen_uas       = set()
        flagged_uas    = []   # parallel list to ua_table rows for report collection

        for buf in self.packet_content_array:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            tcp = eth.data.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport not in _HTTP_PORTS or not tcp.data:
                continue
            try:
                req = dpkt.http.Request(tcp.data)
            except Exception:
                continue

            host   = req.headers.get("host", "")
            ua     = req.headers.get("user-agent", "")
            method = req.method
            uri    = req.uri[:100]

            key = (method, host, uri)
            if key not in seen_requests:
                seen_requests.add(key)
                req_table.add_row(method, host, uri, ua[:70] if ua else "")

            if ua and ua not in seen_uas:
                seen_uas.add(ua)
                for sus in _SUSPICIOUS_USER_AGENTS:
                    if sus.lower() in ua.lower():
                        ua_table.add_row(ua, sus)
                        flagged_uas.append(ua)
                        break

        self.reportz["http_requests"] = [
            {"method": m, "host": h, "uri": u} for m, h, u in seen_requests
            if chk_wlist(h)
        ]
        self.reportz["suspicious_user_agents"] = flagged_uas

        self.make_choice_and_print(req_table, "HTTP request", list(seen_requests))

        if flagged_uas:
            print(f"\n{infoS} Found [bold red]{len(flagged_uas)}[white] suspicious User-Agent(s):")
            print(ua_table)

    def extract_tls_sni(self):
        """
        Extract TLS SNI hostnames from ClientHello messages on known TLS ports.
        The SNI reveals the intended server hostname even when traffic is encrypted.
        Whitelisted hostnames are suppressed.
        """
        print(f"\n{infoS} Performing TLS SNI hostname extraction...")

        seen      = set()
        sni_table = Table()
        sni_table.add_column("[bold green]TLS SNI Hostname", justify="center")

        for buf in self.packet_content_array:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            tcp = eth.data.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport not in _TLS_PORTS or not tcp.data:
                continue

            sni = _parse_tls_sni(tcp.data)
            if sni and sni not in seen and chk_wlist(sni):
                seen.add(sni)
                sni_table.add_row(sni)

        self.reportz["tls_sni_hostnames"] = list(seen)
        if seen:
            print(f"{infoS} Extracted [bold green]{len(seen)}[white] TLS SNI hostname(s):")
            print(sni_table)
        else:
            print(f"{errorS} No TLS SNI hostnames found.")

    def lookup_ja3_digest(self):
        print(f"\n{infoS} Performing malicious [bold green]JA3 Digest[white] lookup. Please wait...")

        result = subprocess.run(["ja3", self.pcap_file], capture_output=True)
        if result.returncode != 0 or not result.stdout.strip():
            print(f"{errorS} There is no malicious digest value found!")
            return

        try:
            ja3_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"{errorS} There is no malicious digest value found!")
            return

        if not ja3_data:
            print(f"{errorS} There is no malicious digest value found!")
            return

        ja3_array = []
        jtable = Table()
        jtable.add_column("[bold green]Extracted Digest Values", justify="center")
        for ja in ja3_data:
            if ja["ja3_digest"] not in ja3_array:
                ja3_array.append(ja["ja3_digest"])
                jtable.add_row(ja["ja3_digest"])

        if not ja3_array:
            print(f"{errorS} There is no malicious digest value found!")
            return

        print(jtable)

        fp_path = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}ja3_fingerprints.lst"
        with open(fp_path) as fp_fh:
            raw_lines = fp_fh.read().split("\n")

        digest_map = {}
        for line in raw_lines:
            parts = line.split(",")
            if len(parts) >= 2 and parts[0]:
                digest_map[parts[0]] = parts[1]

        self.reportz["ja3_digests"] = ja3_array
        self.reportz["ja3_matches"] = {jd: digest_map[jd] for jd in ja3_array if jd in digest_map}

        j_count = 0
        for jd in ja3_array:
            if jd in digest_map:
                j_count += 1
                print(f"[bold magenta]>>>[white] JA3: [bold green]{jd}[white] ---> [bold red]{digest_map[jd]}")

        if j_count == 0:
            print(f"\n{errorS} There is no malicious digest value found!")

# Execution
target_pcap = sys.argv[1]
pcap_analyzer = PcapAnalyzer(target_pcap)
pcap_analyzer.search_urls()
pcap_analyzer.search_ip_addresses()
pcap_analyzer.search_dns_queries()
pcap_analyzer.detect_dga_domains()
pcap_analyzer.find_interesting_stuff()
pcap_analyzer.detect_executables()
pcap_analyzer.analyze_connections()
pcap_analyzer.analyze_http_requests()
pcap_analyzer.extract_tls_sni()
pcap_analyzer.lookup_ja3_digest()
if report_mode:
    clean_report = {k: v for k, v in pcap_analyzer.reportz.items() if v}
    save_report("pcap", clean_report)
