#!/usr/bin/python3

import os
import re
import sys
import email
import asyncio
import subprocess
import shutil
from utils.helpers import err_exit, save_report, get_argv

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    from pydnsbl import DNSBLDomainChecker
    from pydnsbl.providers import BASE_DOMAIN_PROVIDERS, Provider
except:
    err_exit("Error: >pydnsbl< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
NOISY_DNSBL_DEFAULT = {
    "cbl.anti-spam.org.cn",
    "cdl.anti-spam.org.cn",
    "cblless.anti-spam.org.cn",
    "cblplus.anti-spam.org.cn",
    "bad.psky.me",
    "dnsbl.solid.net",
    "dnsrbl.org",
    "hostkarma.junkemailfilter.com",
}

# Get python binary
if shutil.which("python"):
    py_binary = "python"
else:
    py_binary = "python3"

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
        # Keep absolute paths of carved attachments for reliable cleanup.
        self.attachments = []
        self.report = {
            "filename": self.target_file,
            "sender": "",
            "blacklist_checked": False,
            "blacklisted": False,
            "blacklist_confidence": "none",
            "blacklists": [],
            "blacklists_raw": [],
            "blacklists_filtered_out": [],
            "attachments": [],
        }

    def _filter_dnsbl_hits(self, detected_by):
        # Strict-by-default filtering to reduce false positives.
        allow_unknown = str(os.environ.get("SC0PE_EMAIL_DNSBL_ALLOW_UNKNOWN", "0")).strip().lower() in ("1", "true", "yes", "y")
        apply_noisy_filter = str(os.environ.get("SC0PE_EMAIL_DNSBL_FILTER_NOISY", "1")).strip().lower() in ("1", "true", "yes", "y")
        noisy_env = str(os.environ.get("SC0PE_EMAIL_DNSBL_NOISY_PROVIDERS", "")).strip()
        noisy_set = set(NOISY_DNSBL_DEFAULT)
        if noisy_env:
            for prov in noisy_env.split(","):
                p = prov.strip().lower()
                if p:
                    noisy_set.add(p)

        trusted = []
        filtered_out = []
        for provider_name in detected_by:
            cat = "unknown"
            try:
                cat = str(detected_by[provider_name][0]).strip().lower()
            except:
                cat = "unknown"

            entry = {"provider": provider_name, "category": cat}
            is_noisy = provider_name.strip().lower() in noisy_set if apply_noisy_filter else False
            is_unknown = (cat == "unknown")

            if is_noisy or (is_unknown and not allow_unknown):
                filtered_out.append(entry)
            else:
                trusted.append(entry)

        return trusted, filtered_out

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
                safe_name = os.path.basename(str(filename))
                out_path = os.path.abspath(safe_name)
                self.attachments.append(out_path)
                if safe_name not in self.report["attachments"]:
                    self.report["attachments"].append(safe_name)
                with open(out_path, 'wb') as attachment_file:
                    attachment_file.write(part.get_payload(decode=True))
        # If we have attachment lets analyze it!
        if self.attachments != []:
            # Create a table
            attach_table = Table()
            attach_table.add_column("[bold green]Attachment Name[white]", justify="center")
            for an in self.attachments:
                attach_table.add_row(os.path.basename(an))
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
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}document_analyzer.py \"{target_attach}\""
            os.system(command)
        # Analyze executable files and anothers
        elif "executable" in parsed_type:
            if "PE" in parsed_type or ".Net" in parsed_type:
                print(f"\n{infoS} Attachment Type: [bold green]Windows Executable[white]")
                print(f"{infoS} Executing: [bold green]WindowsAnalyzer[white] against [bold cyan]{target_attach}[white]")
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}windows_static_analyzer.py \"{target_attach}\""
                os.system(command)
            elif "ELF" in parsed_type:
                print(f"\n{infoS} Attachment Type: [bold green]Linux/Unix Executable[white]")
                print(f"{infoS} Executing: [bold green]LinuxAnalyzer[white] against [bold cyan]{target_attach}[white]")
                command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}linux_static_analyzer.py \"{target_attach}\""
                os.system(command)
            else:
                print(f"{errorS} Executable type not supported!\n")
        # Analyze archive files
        elif "archive data" in parsed_type:
            print(f"\n{infoS} Attachment Type: [bold green]Archive File[white]")
            print(f"{infoS} Executing: [bold green]ArchiveAnalyzer[white] against [bold cyan]{target_attach}[white]")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}archiveAnalyzer.py \"{target_attach}\""
            os.system(command)
        else:
            print(f"\n{infoS} Executing: [bold green]SignatureAnalyzer[white] against [bold cyan]{target_attach}[white]")
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}sigChecker.py \"{target_attach}\""
            os.system(command)

    def check_blacklist_domain(self, target_email):
        print(f"\n{infoS} Performing blacklist domain check against: [bold green]{target_email}[white]")
        if "@" not in str(target_email):
            print(f"{errorS} Sender email format is invalid. Skipping blacklist check.\n")
            return

        domain = target_email.split('@')[1]  # Extract the domain from the email address
        # Adding new DNSBL providers!
        dnsbl_prov = []
        for pp in self.blacklist_domain_list:
            if pp.strip() == "":
                continue
            try:
                dnsbl_prov.append(Provider(pp))
            except:
                continue
        providers = BASE_DOMAIN_PROVIDERS + dnsbl_prov

        self.report["blacklist_checked"] = True
        loop = None
        created_loop = False
        try:
            # Python 3.14 no longer creates a default loop automatically.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created_loop = True
            try:
                dsnbl_checker = DNSBLDomainChecker(providers=providers, loop=loop)
            except TypeError:
                dsnbl_checker = DNSBLDomainChecker(providers=providers)

            print(f"{infoS} We currently have: [bold green]{len(dsnbl_checker.providers)}[white] blacklists. Please wait...")
            result = dsnbl_checker.check(domain)
            if result.blacklisted:
                for blst in result.detected_by:
                    try:
                        category = str(result.detected_by[blst][0])
                    except:
                        category = "unknown"
                    self.report["blacklists_raw"].append({"provider": blst, "category": category})

                trusted_hits, filtered_out_hits = self._filter_dnsbl_hits(result.detected_by)
                self.report["blacklists_filtered_out"] = filtered_out_hits

                if trusted_hits:
                    self.report["blacklisted"] = True
                    self.report["blacklist_confidence"] = "high"
                    bltable = Table()
                    bltable.add_column("[bold cyan]Blacklist[white]", justify="center")
                    bltable.add_column("[bold cyan]Category[white]", justify="center")
                    for hit in trusted_hits:
                        self.report["blacklists"].append(hit)
                        bltable.add_row(hit["provider"], hit["category"])
                    print(bltable)
                else:
                    self.report["blacklisted"] = False
                    self.report["blacklist_confidence"] = "low"
                    print(f"{errorS} DNSBL hits exist but filtered as low-confidence/noisy. Treating as no reliable blacklist record.\n")
            else:
                print(f"{errorS} There is no record about this address!\n")
        except Exception as exc:
            print(f"{errorS} Blacklist check failed: {exc}")
            print(f"{infoS} Skipping blacklist check and continuing analysis...\n")
        finally:
            if created_loop and loop is not None:
                try:
                    loop.close()
                except:
                    pass
                try:
                    asyncio.set_event_loop(None)
                except:
                    pass

    def email_analyzer_main(self):
        with open(self.target_file, 'r', encoding='utf-8', errors='ignore') as eml_file:
            eml_data = eml_file.read()
        message_obj = email.message_from_string(eml_data)
        print(f"{infoS} Extracting information about sender...")
        sender_field = str(message_obj.get("FROM", ""))
        sender_mail = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?\b', sender_field)
        if sender_mail:
            self.report["sender"] = sender_mail[0]
            print(f"[bold magenta]>>>[white] Sender: [bold green]{sender_mail[0]}[white]")
            self.check_blacklist_domain(target_email=sender_mail[0])
        else:
            print(f"{errorS} Sender address could not be extracted.\n")
        self.extract_and_analyze_attachment_file_type(message_obj=message_obj)

    def cleanup_junks(self):
        if self.attachments == []:
            return

        auto_cleanup = str(os.environ.get("SC0PE_AUTO_CLEANUP_ATTACHMENTS", "")).strip().lower()
        if auto_cleanup in ("1", "true", "yes", "y"):
            choice = "y"
        elif auto_cleanup in ("0", "false", "no", "n"):
            choice = "n"
        else:
            # In non-interactive sessions, don't crash on input.
            if not sys.stdin or not sys.stdin.isatty():
                print(f"{infoS} Non-interactive session detected. Skipping extracted file cleanup prompt.")
                return
            try:
                choice = str(input(">>> Do you want to remove extracted files [y/n]?: "))
            except EOFError:
                print(f"{infoS} Input stream is closed. Skipping extracted file cleanup.")
                return

        if choice == "Y" or choice == "y":
            for att in self.attachments:
                try:
                    # Attachments are files carved into current working directory.
                    if os.path.isfile(att):
                        os.remove(att)
                    elif os.path.isdir(att):
                        shutil.rmtree(att, ignore_errors=True)
                except Exception as exc:
                    print(f"{errorS} Could not remove [bold yellow]{att}[white]: {exc}")
            print(f"{infoS} Cleaning up...")

# Execution
target_eml = sys.argv[1]
em_anl = EmailAnalyzer(target_file=target_eml)
em_anl.email_analyzer_main()
if get_argv(2) == "True":
    save_report("email", em_anl.report)
em_anl.cleanup_junks()
