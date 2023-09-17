#!/usr/bin/python3

import os
import re
import sys
import email
import subprocess

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from pydnsbl import DNSBLDomainChecker, providers
    from pydnsbl.providers import BASE_DOMAIN_PROVIDERS, Provider
except:
    print("Error: >pydnsbl< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

class EmailAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.blacklist_domain_list = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}blacklist_domains.txt", "r").read().split("\n")
        self.attachments = []

    def extract_and_analyze_attachment_file_type(self, message_obj):
        print(f"\n{infoS} Checking for attachments...")
        # Check for attachments
        for part in message_obj.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                self.attachments.append(filename)
                with open(filename, 'wb') as attachment_file:
                    attachment_file.write(part.get_payload(decode=True))
        # If we have attachment lets analyze it!
        if self.attachments != []:
            # Create a table
            attach_table = Table()
            attach_table.add_column("[bold green]Attachment Name[white]", justify="center")
            for an in self.attachments:
                attach_table.add_row(an)
            print(attach_table)

            # Check attachment type and perform analysis against it!
            for att in self.attachments:
                self.attachment_type_check(target_attach=att)
        else:
            print(f"{errorS} There is no attachment found!\n")

    def attachment_type_check(self, target_attach):
        # Check attachment type and perform analysis against it!
        attachment_type = subprocess.run(["file", target_attach], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        parsed_type = attachment_type.stdout.decode()
        # Analyze document files
        if "Microsoft Office Word" in parsed_type or "Microsoft Excel" in parsed_type or "PDF" in parsed_type:
            print(f"\n{infoS} Attachment Type: [bold green]Document[white]")
            print(f"{infoS} Executing: [bold green]DocumentAnalyzer[white] against [bold cyan]{target_attach}[white]")
            command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}document_analyzer.py \"{target_attach}\""
            os.system(command)
        # Analyze executable files and anothers
        elif "executable" in parsed_type:
            if "PE" in parsed_type or ".Net" in parsed_type:
                print(f"\n{infoS} Attachment Type: [bold green]Windows Executable[white]")
                print(f"{infoS} Executing: [bold green]WindowsAnalyzer[white] against [bold cyan]{target_attach}[white]")
                command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}winAnalyzer.py \"{target_attach}\""
                os.system(command)
            elif "ELF" in parsed_type:
                print(f"\n{infoS} Attachment Type: [bold green]Linux/Unix Executable[white]")
                print(f"{infoS} Executing: [bold green]LinuxAnalyzer[white] against [bold cyan]{target_attach}[white]")
                command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}linAnalyzer.py \"{target_attach}\""
                os.system(command)
            else:
                print(f"{errorS} Executable type not supported!\n")
        # Analyze archive files
        elif "archive data" in parsed_type:
            print(f"\n{infoS} Attachment Type: [bold green]Archive File[white]")
            print(f"{infoS} Executing: [bold green]ArchiveAnalyzer[white] against [bold cyan]{target_attach}[white]")
            command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}archiveAnalyzer.py \"{target_attach}\""
            os.system(command)
        else:
            print(f"\n{infoS} Executing: [bold green]SignatureAnalyzer[white] against [bold cyan]{target_attach}[white]")
            command = f"python {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{target_attach}\""
            os.system(command)

    def check_blacklist_domain(self, target_email):
        print(f"\n{infoS} Performing blacklist domain check against: [bold green]{target_email}[white]")
        domain = target_email.split('@')[1]  # Extract the domain from the email address
        # Adding new DNSBL providers!
        dnsbl_prov = []
        for pp in self.blacklist_domain_list:
            dnsbl_prov.append(Provider(pp))
        providers = BASE_DOMAIN_PROVIDERS + dnsbl_prov

        # Create dnsbl checker
        dsnbl_checker = DNSBLDomainChecker(providers=providers)
        print(f"{infoS} We currently have: [bold green]{len(dsnbl_checker.providers)}[white] blacklists. Please wait...")
        result = dsnbl_checker.check(domain)
        if result.blacklisted:
            bltable = Table()
            bltable.add_column("[bold cyan]Blacklist[white]", justify="center")
            bltable.add_column("[bold cyan]Category[white]", justify="center")
            for blst in result.detected_by:
                bltable.add_row(blst, result.detected_by[blst][0])
            print(bltable)
        else:
            print(f"{errorS} There is no record about this address!\n")

    def email_analyzer_main(self):
        with open(self.target_file, 'r', encoding='utf-8') as eml_file:
            eml_data = eml_file.read()
        message_obj = email.message_from_string(eml_data)
        print(f"{infoS} Extracting information about sender...")
        sender_mail = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?\b', message_obj["FROM"])
        print(f"[bold magenta]>>>[white] Sender: [bold green]{sender_mail[0]}[white]")
        self.check_blacklist_domain(target_email=sender_mail[0])
        self.extract_and_analyze_attachment_file_type(message_obj=message_obj)

    def cleanup_junks(self):
        choice = str(input(">>> Do you want to remove extracted files [y/n]?: "))
        if choice == "Y" or choice == "y":
            for att in self.attachments:
                if sys.platform != "win32":
                    os.system(f"rm -rf {sc0pe_path}{path_seperator}{att}")
                else:
                    os.system(f"powershell -c \"del {sc0pe_path}{path_seperator}{att} -Force -Recurse\"")
            print(f"{infoS} Cleaning up...")

# Execution
target_eml = sys.argv[1]
em_anl = EmailAnalyzer(target_file=target_eml)
em_anl.email_analyzer_main()
em_anl.cleanup_junks()