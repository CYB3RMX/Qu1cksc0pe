#!/usr/bin/python3

import re
import os
import sys
import binascii

try:
    from rich import print
    from rich.progress import track
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import dpkt
except:
    print("Error: >dpkt< module not found.")
    sys.exit(1)

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

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
            choice = input(f">>> Do you want to print {len(self.given_data)} lines [y/n]?: ")
            if choice == "y" or choice == "Y":
                print(self.table_obj)
        else:
            print(f"{errorS} There is no {self.data_type} found!")

    def find_interesting_stuff(self):
        stuff_table = Table()
        stuff_table.add_column("[bold green]Interesting Strings", justify="center")
        extracted_data = []
        interesting_stuff = [
            r"[a-zA-Z0-9_.]*pdb", r"[a-zA-Z0-9_.]*vbs", 
            r"[a-zA-Z0-9_.]*vba", r"[a-zA-Z0-9_.]*vbe", 
            r"[a-zA-Z0-9_.]*exe", r"[a-zA-Z0-9_.]*ps1",
            r"[a-zA-Z0-9_.]*dll", r"[a-zA-Z0-9_.]*bat",
            r"[a-zA-Z0-9_.]*cmd", r"[a-zA-Z0-9_.]*tmp",
            r"[a-zA-Z0-9_.]*dmp", r"[a-zA-Z0-9_.]*cfg",
            r"[a-zA-Z0-9_.]*lnk", r"[a-zA-Z0-9_.]*config"
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
            command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{self.pcap_file}\""
            os.system(command)
        else:
            print(f"{errorS} There is no executable file pattern found!")

# Execution
target_pcap = sys.argv[1]
pcap_analyzer = PcapAnalyzer(target_pcap)
pcap_analyzer.search_urls()
pcap_analyzer.search_dns_queries()
pcap_analyzer.find_interesting_stuff()
pcap_analyzer.detect_executables()