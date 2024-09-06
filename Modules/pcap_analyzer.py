#!/usr/bin/python3

import re
import os
import sys
import json
import binascii
import distutils.spawn

from utils import err_exit, user_confirm

try:
    from rich import print
    from rich.progress import track
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import dpkt
except:
    err_exit("Error: >dpkt< module not found.")

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

if not distutils.spawn.find_executable("ja3"):
    print(f"{errorS} Error: [bold green]ja3[white] command not found!")
    print(f"[bold red]>>>[white] Execute: [bold green]pip3 install pyja3[white]")
    sys.exit(1)

# Get python binary
if distutils.spawn.find_executable("python"):
    py_binary = "python"
else:
    py_binary = "python3"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

class PcapAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.all_content = open(self.pcap_file, "rb").read()
        self.file_buffer = open(self.pcap_file, "rb")
        self.pcap_content = dpkt.pcap.Reader(self.file_buffer)
        print(f"{infoS} Loading PCAP content. It will take a while please wait...")
        self.packet_content_array = []
        for _, buf in self.pcap_content:
            self.packet_content_array.append(buf)

    def search_urls(self):
        url_table = Table()
        url_table.add_column("[bold green]Extracted URL\'s", justify="center")
        extracted_data = []
        print(f"{infoS} Performing URL extraction. It will take a while please wait...")
        for packet in track(range(len(self.packet_content_array)), description="Processing packets..."):
            eth = dpkt.ethernet.Ethernet(self.packet_content_array[packet])
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                http = eth.data.data.data
                try:
                    if http.startswith(b'GET') or http.startswith(b'POST'):
                        match = re.search(rb'(?i)\bHost: (.*?)\r\n', http)
                        if match:
                            host = match.group(1).decode('utf-8')
                            url_match = re.search(rb'(?i)\b(GET|POST) (.*?) HTTP', http)
                            if url_match:
                                path = url_match.group(2).decode('utf-8')
                                url = f"http://{host}{path}"
                                if url not in extracted_data:
                                    extracted_data.append(url)
                                    url_table.add_row(url)
                except:
                    continue
        self.make_choice_and_print(url_table, "URL address", extracted_data)

    def search_dns_queries(self):
        dns_table = Table()
        dns_table.add_column("[bold green]DNS Queries", justify="center")
        extracted_data = []
        print(f"\n{infoS} Performing extraction of DNS queries. It will take a while please wait...")
        for packet in track(range(len(self.packet_content_array)), description="Processing packets..."):
            eth = dpkt.ethernet.Ethernet(self.packet_content_array[packet])
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
        self.make_choice_and_print(dns_table, "DNS queries", extracted_data)

    def make_choice_and_print(self, table_obj, data_type, given_data):
        self.table_obj = table_obj
        self.data_type = data_type
        self.given_data = given_data

        if self.given_data != [] and len(self.given_data) <= 50:
            print(f"\n{infoS} We found [bold green]{len(self.given_data)}[white] valid {self.data_type}.")
            print(self.table_obj)
        elif self.given_data != [] and len(self.given_data) > 50:
            print(f"\n{infoS} We found [bold red]{len(self.given_data)}[white] valid {self.data_type}.")
            if user_confirm(f">>> Do you want to print {len(self.given_data)} lines [y/n]?: "):
                print(self.table_obj)
        else:
            print(f"{errorS} There is no {self.data_type} found!")

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
            r'\b[a-zA-Z0-9_\-\\/:]+\.7z', r'\b[a-zA-Z0-9_\-\\/:]+\.docx'
        ]
        print(f"\n{infoS} Performing analysis of interesting strings. It will take a while please wait...")
        for stuff in track(range(len(interesting_stuff)), description="Processing buffer..."):
            matches = re.findall(interesting_stuff[stuff].encode(), self.all_content)
            if matches != []:
                for mm in matches:
                    try:
                        if mm not in extracted_data:
                            if mm.decode()[0] != "." and "." in mm.decode():
                                extracted_data.append(mm.decode())
                                stuff_table.add_row(mm.decode())
                    except:
                        continue
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
        if valid_offsets != []:
            print(f"{infoS} This PCAP file contains [bold red]{len(valid_offsets)}[white] possible executable files!!")
            print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] for embedded file extraction...")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{self.pcap_file}\""
            os.system(command)
        else:
            print(f"{errorS} There is no executable file pattern found!")

    def lookup_ja3_digest(self):
        print(f"\n{infoS} Performing malicious [bold green]JA3 Digest[white] lookup. Please wait...")
        os.system(f"ja3 {self.pcap_file} > out.json")
        ja3_data = json.load(open("out.json"))
        ja3_array = []

        # Table for extracted data
        jtable = Table()
        jtable.add_column("[bold green]Extracted Digest Values", justify="center")

        # Try to get ja3 digests
        for ja in ja3_data:
            if ja["ja3_digest"] not in ja3_array:
                ja3_array.append(ja["ja3_digest"])
                jtable.add_row(ja["ja3_digest"])

        if ja3_array:
            print(jtable)

            # Parsing database
            l_data = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}ja3_fingerprints.lst").read().split("\n")
            digest_arr = []
            for d in l_data:
                if d.split(",")[0] not in digest_arr:
                    digest_arr.append(d.split(",")[0])

            # Perform lookup
            j_count = 0
            for jd in ja3_array:
                if jd in digest_arr:
                    j_count += 1
                    j_type_index = digest_arr.index(jd)
                    print(f"[bold magenta]>>>[white] JA3: [bold green]{jd}[white] ---> [bold red]{l_data[j_type_index].split(',')[1]}")

            if j_count == 0:
                print(f"\n{errorS} There is no malicious digest value found!")
        os.system("rm -rf out.json")

# Execution
target_pcap = sys.argv[1]
pcap_analyzer = PcapAnalyzer(target_pcap)
pcap_analyzer.search_urls()
pcap_analyzer.search_dns_queries()
pcap_analyzer.find_interesting_stuff()
pcap_analyzer.detect_executables()
pcap_analyzer.lookup_ja3_digest()