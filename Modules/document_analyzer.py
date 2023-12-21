#!/usr/bin/python3

import re
import os
import sys
import json
import zlib
import base64
import binascii
import zipfile
import subprocess
import configparser
import urllib.parse
from bs4 import BeautifulSoup

# Checking for rich
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< not found.")
    sys.exit(1)

try:
    import yara
except:
    print("Error: >yara< module not found.")
    sys.exit(1)

# Checking for oletools
try:
    from oletools.olevba import VBA_Parser
    from oletools.crypto import is_encrypted
    from oletools.oleid import OleID
    from olefile import isOleFile
except:
    print("Error: >oletools< module not found.")
    print("Try 'sudo -H pip3 install -U oletools' command.")
    sys.exit(1)

# Checking for pdfminer
try:
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
except:
    print("Error: >pdfminer< module not found.")
    sys.exit(1)

# Checking for pyOneNote module
try:
    from pyOneNote.Main import OneDocment
except:
    print("Error: >pyOneNote< module not found. Don\'t worry I can handle it...")
    os.system("pip install -U https://github.com/DissectMalware/pyOneNote/archive/master.zip --force")
    print("[bold yellow]Now try to re-execute program again!")
    sys.exit(0)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Target file
targetFile = sys.argv[1]

# Compatibility
path_seperator = "/"
strings_param = "--all"
if sys.platform == "win32":
    path_seperator = "\\"
    strings_param = "-a"
elif sys.platform == "darwin":
    strings_param = "-a"
else:
    pass

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Perform strings
_ = subprocess.run(f"strings {strings_param} \"{targetFile}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
if sys.platform != "win32":
    _ = subprocess.run(f"strings {strings_param} -e l {targetFile} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

# All strings
allstr = open("temp.txt", "r").read()

class DocumentAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
        self.file_sigs = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}file_sigs.json"))
        self.base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
        self.mal_code = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_html_codes.json"))
        self.mal_rtf_code = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_rtf_codes.json"))
        self.pat_ct = 0

    # Checking for file extension
    def CheckExt(self):
        magic_buf = open(self.targetFile, "rb").read(8)
        doc_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "Microsoft Word" in doc_type.stdout.decode() or "Microsoft Excel" in doc_type.stdout.decode() or "Microsoft Office Word" in doc_type.stdout.decode():
            return "docscan"
        elif "PDF document" in doc_type.stdout.decode():
            return "pdfscan"
        elif self.targetFile.endswith(".one"): # TODO: Look for better solutions!
            return "onenote"
        elif "HTML document" in doc_type.stdout.decode():
            return "html"
        elif ("Rich Text Format" in doc_type.stdout.decode() and binascii.unhexlify(b"7B5C72746631") in magic_buf) or (binascii.unhexlify(b"7B5C7274") in magic_buf):
            return "rtf"
        else:
            return "unknown"

    # Yara Scanner
    def DocumentYara(self):
        yara_match_indicator = 0
        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf")
        rule_path = conf["Rule_PATH"]["rulepath"]
        finalpath = f"{sc0pe_path}{path_seperator}{rule_path}"
        allRules = os.listdir(finalpath)

        # This array for holding and parsing easily matched rules
        yara_matches = []
        for rul in allRules:
            try:
                rules = yara.compile(f"{finalpath}{rul}")
                tempmatch = rules.match(self.targetFile)
                if tempmatch != []:
                    for matched in tempmatch:
                        if matched.strings != []:
                            if matched not in yara_matches:
                                yara_matches.append(matched)
            except:
                continue

        # Printing area
        if yara_matches != []:
            yara_match_indicator += 1
            for rul in yara_matches:
                yaraTable = Table()
                print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
                yaraTable.add_column("Offset", style="bold green", justify="center")
                yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
                for mm in rul.strings:
                    yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
                print(yaraTable)
                print(" ")

        if yara_match_indicator == 0:
            print(f"[bold white on red]There is no rules matched for {self.targetFile}")

    # Perform analysis against embedded binaries
    def JARCheck(self):
        # Data for JAR analysis
        jar_chek = {}

        # Check if file is an JAR file (for embedded .jar based attacks)
        keywordz = ["JAR", ".class", "META-INF"]
        jTable = Table(title="* Matches *", title_style="bold italic cyan", title_justify="center")
        jTable.add_column("[bold green]Pattern", justify="center")
        jTable.add_column("[bold green]Count", justify="center")
        for key in keywordz:
            jstr = re.findall(key, str(self.binarydata))
            jTable.add_row(key, str(len(jstr)))
            jar_chek.update({key: len(jstr)})

        # Condition for JAR file
        if jar_chek["JAR"] >= 1 or jar_chek[".class"] >= 2 or jar_chek["META-INF"] >= 1:
            print(f"[bold magenta]>>>[white] Binary Type: [bold green]JAR[white]")
            print(jTable)

    def VBasicCheck(self):
        # Data for VBA analysis
        vba_chek = {}

        # Check if file is an VBA file
        keywordz = ["Function", "Sub", "Dim", "End", "Document"]
        vbaTable = Table(title="* Matches *", title_style="bold italic cyan", title_justify="center")
        vbaTable.add_column("[bold green]Pattern", justify="center")
        vbaTable.add_column("[bold green]Count", justify="center")
        for key in keywordz:
            vbastr = re.findall(key, str(self.binarydata))
            vbaTable.add_row(key, str(len(vbastr)))
            vba_chek.update({key: len(vbastr)})

        # Condition for VBA file
        if vba_chek["Function"] >= 1 or vba_chek["Sub"] >= 1 or vba_chek["Dim"] >= 1 or vba_chek["End"] >= 1 or vba_chek["Document"] >= 1:
            print(f"[bold magenta]>>>[white] Binary Type: [bold green]Composite Document File V2 Document (Contains possible VBA code!!)[white]")
            print(vbaTable)

    def BinaryAnalysis(self, component, binarydata):
        self.component = component
        self.binarydata = binarydata

        print(f"\n{infoS} Analyzing: [bold red]{self.component}")
        # Check if file is an JAR file (for embedded .jar based attacks)
        self.JARCheck()
        # Check if file is an VBA file
        self.VBasicCheck()
        
    # Function for perform file structure analysis
    def Structure(self):
        # We need to unzip the file and check for interesting files
        print(f"\n{infoS} Analyzing file structure...")
        try:
            document = zipfile.ZipFile(self.targetFile)
            bins = []

            # Parsing the files
            docTable = Table(title="* Document Structure *", title_style="bold italic cyan", title_justify="center")
            docTable.add_column("[bold green]File Name", justify="center")
            for df in document.namelist():
                if ".bin" in df:
                    docTable.add_row(f"[bold red]{df}")
                    bins.append(df)
                else:
                    docTable.add_row(df)
            print(docTable)

            # Perform analysis against binaries
            if bins != []:
                for b in bins:
                    bdata = document.read(b)
                    self.BinaryAnalysis(b, bdata)

            # Check for insteresting external links (effective against follina related samples and IoC extraction)
            print(f"\n{infoS} Searching for interesting links...")
            exlinks = Table(title="* Interesting Links *", title_style="bold italic cyan", title_justify="center")
            exlinks.add_column("[bold green]Link", justify="center")
            for fff in document.namelist():
                try:
                    ddd = document.read(fff).decode()
                    linkz = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", ddd)
                    for lnk in linkz:
                        if "schemas.openxmlformats.org" not in lnk and "schemas.microsoft.com" not in lnk and "purl.org" not in lnk and "www.w3.org" not in lnk and "go.microsoft.com" not in lnk:
                            exlinks.add_row(lnk)
                except:
                    continue
            
            if exlinks.rows != []:
                print(exlinks)
            else:
                print(f"[bold white on red]There is no interesting links found.")
        except:
            print(f"{errorS} Error: Unable to unzip file.")

    # Macro parser function
    def MacroParser(self, macroList):
        self.macroList = macroList

        answerTable = Table()
        answerTable.add_column("[bold green]Threat Levels", justify="center")
        answerTable.add_column("[bold green]Macros", justify="center")
        answerTable.add_column("[bold green]Descriptions", justify="center")

        for fi in range(0, len(self.macroList)):
            if self.macroList[fi][0] == 'Suspicious':
                if "(use option --deobf to deobfuscate)" in self.macroList[fi][2]:
                    sanitized = f"{self.macroList[fi][2]}".replace("(use option --deobf to deobfuscate)", "")
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{sanitized}")
                elif "(option --decode to see all)" in self.macroList[fi][2]:
                    sanitized = f"{self.macroList[fi][2]}".replace("(option --decode to see all)", "")
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{sanitized}")
                else:
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            elif self.macroList[fi][0] == 'IOC':
                answerTable.add_row(f"[bold magenta]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            elif self.macroList[fi][0] == 'AutoExec':
                answerTable.add_row(f"[bold red]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            else:
                answerTable.add_row(f"{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
        print(answerTable)

    # A function that finds VBA Macros
    def MacroHunter(self):
        print(f"\n{infoS} Looking for Macros...")
        try:
            fileData = open(self.targetFile, "rb").read()
            vbaparser = VBA_Parser(self.targetFile, fileData)
            try:
                macroList = list(vbaparser.analyze_macros())
            except:
                pass
            macro_state_vba = 0
            macro_state_xlm = 0
            # Checking vba macros
            if vbaparser.contains_vba_macros == True:
                print(f"[bold red]>>>[white] VBA MACRO: [bold green]Found.")
                if vbaparser.detect_vba_stomping() == True:
                    print(f"[bold red]>>>[white] VBA Stomping: [bold green]Found.")

                else:
                    print(f"[bold red]>>>[white] VBA Stomping: [bold red]Not found.")
                self.MacroParser(macroList)
                macro_state_vba += 1
            else:
                print(f"[bold red]>>>[white] VBA MACRO: [bold red]Not found.\n")

            # Checking for xlm macros
            if vbaparser.contains_xlm_macros == True:
                print(f"\n[bold red]>>>[white] XLM MACRO: [bold green]Found.")
                self.MacroParser(macroList)
                macro_state_xlm += 1
            else:
                print(f"\n[bold red]>>>[white] XLM MACRO: [bold red]Not found.")

            # If there is macro we can extract it!
            if macro_state_vba != 0 or macro_state_xlm != 0:
                choice = str(input("\n>>> Do you want to extract macros [Y/n]?: "))
                if choice == "Y" or choice == "y":
                    print(f"{infoS} Attempting to extraction...\n")
                    if macro_state_vba != 0:
                        for mac in vbaparser.extract_all_macros():
                            for xxx in mac:
                                print(xxx.strip("\r\n"))
                    else:
                        for mac in vbaparser.xlm_macros:
                            print(mac)
                    print(f"\n{infoS} Extraction completed.")

        except:
            print(f"{errorS} An error occured while parsing that file for macro scan.")

    # Gathering basic informations
    def BasicInfoGa(self):
        # Check for ole structures
        if isOleFile(self.targetFile) == True:
            print(f"{infoS} Ole File: [bold green]True[white]")
        else:
            print(f"{infoS} Ole File: [bold red]False[white]")

        # Check for encryption
        if is_encrypted(self.targetFile) == True:
            print(f"{infoS} Encrypted: [bold green]True[white]")
        else:
            print(f"{infoS} Encrypted: [bold red]False[white]")

        # Perform file structure analysis
        self.Structure()

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        self.DocumentYara()

        # VBA_MACRO scanner
        vbascan = OleID(self.targetFile)
        vbascan.check()
        # Sanitizing the array
        vba_params = []
        for vb in vbascan.indicators:
            vba_params.append(vb.id)

        if "vba_macros" in vba_params:
            for vb in vbascan.indicators:
                if vb.id == "vba_macros":
                    if vb.value == True:
                        print(f"{infoS} VBA Macros: [bold green]Found[white]")
                        self.MacroHunter()
                    else:
                        print(f"{infoS} VBA Macros: [bold red]Not Found[white]")
        else:
            self.MacroHunter()

    # Onenote analysis
    def OneNoteAnalysis(self):
        print(f"{infoS} Performing OneNote analysis...")

        # Looking for embedded urls
        urlswitch = 0
        print(f"\n{infoS} Searching for interesting links...")
        url_match = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", allstr)
        if url_match != []:
            for lnk in url_match:
                if "schemas.openxmlformats.org" not in lnk and "schemas.microsoft.com" not in lnk and "purl.org" not in lnk and "www.w3.org" not in lnk and "go.microsoft.com" not in lnk and "ns.adobe.com" not in lnk:
                    print(f"[bold magenta]>>>[white] {lnk}")
                    urlswitch += 1
        
        if urlswitch == 0:
            print(f"[bold white on red]There is no interesting links found.")

        # Read and parse
        print(f"\n{infoS} Searching for embedded data/files...")
        if "keyData" in allstr and "encryptedKey" in allstr:
            print(f"\n{infoS} [bold yellow]WARNING![white]: This document seems contain encrypted data. Trying to analyze it anyway...")

        try:
            doc_buffer = open(self.targetFile, "rb")
            onenote_obj = OneDocment(doc_buffer)
        except:
            print(f"{errorS} An exception occured while reading data.")
            sys.exit(1)

        # Analysis of embedded file
        embedTable = Table(title="* Embedded Files *", title_style="bold italic cyan", title_justify="center")
        embedTable.add_column("[bold green]File Identity", justify="center")
        embedTable.add_column("[bold green]File Extension", justify="center")

        # Add table
        efs = onenote_obj.get_files()
        for key in efs.keys():
            embedTable.add_row(efs[key]["identity"], efs[key]["extension"])
        print(embedTable)

        # Extract embedded files
        print(f"\n{infoS} Performing embedded file extraction...")
        for key in efs.keys():
            with open(f"sc0pe_carved-{key}{efs[key]['extension']}", "wb") as binfile:
                binfile.write(efs[key]["content"])
            binfile.close()
            print(f"[bold magenta]>>>[white] Embedded file saved as: [bold green]sc0pe_carved-{key}{efs[key]['extension']}[white]")

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        self.DocumentYara()

    # PDF analysis
    def PDFAnalysis(self):
        print(f"{infoS} Performing PDF analysis...")

        # Parsing the PDF
        try:
            pdata = open(self.targetFile, "rb")
            pdf = PDFParser(pdata)
            doc = PDFDocument(pdf)
        except Exception as er:
            print(f"{errorS} Error: {er}")
            sys.exit(1)

        # Gathering meta information
        print(f"\n{infoS} Gathering meta information...")
        metaTable = Table(title="* Meta Information *", title_style="bold italic cyan", title_justify="center")
        metaTable.add_column("[bold green]Key", justify="center")
        metaTable.add_column("[bold green]Value", justify="center")
        if doc.info != [] and doc.info[0] != {}:
            for vals in doc.info[0]:
                metaTable.add_row(f"[bold yellow]{vals}", f"{doc.info[0][vals]}")
            print(metaTable)
        else:
            print(f"{errorS} No meta information found.")

        # Gathering PDF catalog
        print(f"\n{infoS} Gathering PDF catalog...")
        suspicious_keys = []
        catalogTable = Table(title="* PDF Catalog *", title_style="bold italic cyan", title_justify="center")
        catalogTable.add_column("[bold green]Key", justify="center")
        for vals in doc.catalog:
            if "Type" in vals:
                pass
            elif "AcroForm" in vals or "JavaScript" in vals or "OpenAction" in vals or "JS" in vals or "EmbeddedFile" in vals:
                catalogTable.add_row(f"[bold red]{vals}") # Highlighting suspicious keys
                suspicious_keys.append(vals)
            else:
                catalogTable.add_row(vals)
        print(catalogTable)

        # Suspicous PDF strings
        print(f"\n{infoS} Searching for suspicious strings...")
        embedded_switch = 0
        sstr = 0
        suspicious = [
            "/JavaScript", "/JS", "/AcroForm", "/OpenAction", 
            "/Launch", "/LaunchUrl", "/EmbeddedFile", "/URI", 
            "/Action", "cmd.exe", "system32", "%HOMEDRIVE%",
            "<script>",
            r"[a-zA-Z0-9_.]*pdb", r"[a-zA-Z0-9_.]*vbs", 
            r"[a-zA-Z0-9_.]*vba", r"[a-zA-Z0-9_.]*vbe", 
            r"[a-zA-Z0-9_.]*exe", r"[a-zA-Z0-9_.]*ps1",
            r"[a-zA-Z0-9_.]*dll", r"[a-zA-Z0-9_.]*bat",
            r"[a-zA-Z0-9_.]*cmd", r"[a-zA-Z0-9_.]*tmp",
            r"[a-zA-Z0-9_.]*dmp", r"[a-zA-Z0-9_.]*cfg",
            r"[a-zA-Z0-9_.]*lnk", r"[a-zA-Z0-9_.]*config",
            r"[a-zA-Z0-9_.]*7z", r"[a-zA-Z0-9_.]*docx",
            r"[a-zA-Z0-9_.]*zip"
        ]
        sTable = Table(title="* Suspicious Strings *", title_style="bold italic cyan", title_justify="center")
        sTable.add_column("[bold green]String", justify="center")
        sTable.add_column("[bold green]Count", justify="center")
        for s in suspicious:
            occur = re.findall(s, allstr)
            if len(occur) != 0:
                if s == "/EmbeddedFile":
                    embedded_switch += 1
                sTable.add_row(f"[bold red]{s}", f"{len(occur)}")
                sstr += 1

        if sstr != 0:
            print(sTable)
        else:
            print(f"{errorS} There is no suspicious strings found!")

        # Looking for embedded links
        print(f"\n{infoS} Looking for embedded URL\'s via [bold green]Regex[white]...")
        urlTable = Table(title="* Embedded URL\'s *", title_style="bold italic cyan", title_justify="center")
        urlTable.add_column("[bold green]URL", justify="center")
        uustr = 0
        linkz = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", allstr)
        if len(linkz) != 0:
            lcontrol = []
            for l in linkz:
                if "schemas.openxmlformats.org" not in l and "schemas.microsoft.com" not in l and "purl.org" not in l and "www.w3.org" not in l and "go.microsoft.com" not in l and "ns.adobe.com" not in l and "www.adobe.com" not in l and "www.microsoft.com" not in l:
                    if l not in lcontrol:
                        if ")" in l:
                            if l.split(')')[0] not in lcontrol:
                                urlTable.add_row(f"[bold yellow]{l.split(')')[0]}")
                                lcontrol.append(l.split(')')[0])
                        elif "<" in l:
                            if l.split('<')[0] not in lcontrol:
                                urlTable.add_row(f"[bold yellow]{l.split('<')[0]}")
                                lcontrol.append(l.split('<')[0])
                        else:
                            urlTable.add_row(f"[bold yellow]{l}")
                            lcontrol.append(l)
                        uustr += 1
            if uustr != 0:
                print(urlTable)
            else:
                print(f"{infoS} There is no interesting URL\'s found!\n")
        else:
            print(f"{errorS} There is no URL pattern found via regex!\n")

        # PDF Stream analysis
        print(f"{infoS} Performing PDF stream analysis...")
        print(f"{infoS} Analyzing total objects...")
        # Iterate over objects and analyze them!
        number_of_objects = 0
        ext_urls = []
        for xref in doc.xrefs:
            if "ranges" in str(xref):
                temp_of_objects = xref.ranges[0][1]
            else:
                temp_of_objects = len(xref.get_objids())

            if number_of_objects != temp_of_objects:
                number_of_objects = temp_of_objects
                for obj in xref.get_objids():
                    try:
                        if "PDFStream" in str(doc.getobj(obj)):
                            object_data = doc.getobj(obj).get_rawdata() # Gather buffer from object
                            # Check if there is an zlib compression
                            try:
                                object_data = zlib.decompress(object_data)
                            except:
                                pass
                        else:
                            object_data = None

                        # Check for magic headers
                        if object_data:
                            for categ in self.file_sigs:
                                for pattern in self.file_sigs[categ]["patterns"]:
                                    regex = re.findall(pattern.encode(), binascii.hexlify(object_data))
                                    if regex != []:
                                        print(f"{infoS} Possible [bold green]{categ}[white] detected at [bold green]ObjectID[white]: [bold yellow]{obj}[white]")
                                        print(f"{infoS} Attempting to extraction...")
                                        self.output_writer(out_file=f"sc0pe_carved-{categ}-{obj}.bin", mode="wb", buffer=object_data)

                        # Check for /URI object
                        if "URI" in str(doc.getobj(obj)):
                            # Method 1
                            try:
                                if doc.getobj(obj)["URI"].decode() not in ext_urls and doc.getobj(obj)["URI"].decode() != "":
                                    ext_urls.append(doc.getobj(obj)["URI"].decode())
                            except:
                                pass

                            # Method 2
                            get_url = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", str(doc.getobj(obj)))
                            if get_url != []:
                                for ur in get_url:
                                    if "'" in ur:
                                        if ur.split("'")[0] not in ext_urls:
                                            ext_urls.append(ur.split("'")[0])
                                    else:
                                        if ur not in ext_urls:
                                            ext_urls.append(ur)

                            # Print all
                            if ext_urls != []:
                                for ext in ext_urls:
                                    print(f"{infoS} Extracted URI from stream: [bold green]{ext}[white]")

                        # Check for /EmbeddedFile stream
                        if "EmbeddedFile" in str(doc.getobj(obj)) and "PDFStream" in str(doc.getobj(obj)):
                            print(f"\n{infoS} Performing embedded file extraction...")
                            print(f"{infoS} Checking for compression...")
                            try:
                                decompressed = zlib.decompress(doc.getobj(obj).get_rawdata())
                                self.output_writer(out_file=f"sc0pe_embedded_decompressed_file-{obj}.bin", mode="wb", buffer=decompressed)
                            except:
                                self.output_writer(out_file=f"sc0pe_embedded_file-{obj}.bin", mode="wb", buffer=doc.getobj(obj).get_rawdata())
                    except:
                        continue
            else:
                pass

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        self.DocumentYara()

    # HTML analysis
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
                    self.output_writer(out_file=f"sc0pe_decoded_unescape-{len(deobf)}.bin", mode="w", buffer=deobf)

                    # After extracting the data also we need to scan it!
                    print(f"\n{infoS} Performing analysis against [bold yellow]sc0pe_decoded_unescape-{len(deobf)}.bin[white]")
                    if "html" in deobf:
                        new_soup = BeautifulSoup(deobf, "html.parser")
                        self.html_check_input_points(soup_obj=new_soup)
                        self.html_check_iframe_tag(soup_obj=new_soup)
                        self.html_detect_malicious_code(given_buffer=deobf)
                        self.html_check_suspicious_files(given_buffer=deobf)

    def html_fetch_urls(self, given_buffer):
        print(f"\n{infoS} Checking URL values...")
        url_vals = []
        regx = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", given_buffer)
        if regx != []:
            url_table = Table()
            url_table.add_column("[bold green]URL Values", justify="center")
            for url in regx:
                if url not in url_vals:
                    url_table.add_row(url)
                    url_vals.append(url)
            print(url_table)
        else:
            print(f"{errorS} There is no URL value found!")

    def chk_b64(self, given_buffer):
        keywords_to_check = [r"function", r"_0x", r"parseInt", r"script", r"var", r"document", r"src", r"atob", r"eval"]
        b64codes = re.findall(self.base64_pattern, given_buffer)
        if b64codes != []:
            decc = []
            for cod in b64codes:
                try:
                    key_count = 0
                    decoded = base64.b64decode(cod)
                    if "\\x" not in decoded.decode(): # Because we need strings not byte stuff
                        if len(decoded.decode()) <= 6 and (")" in decoded.decode() or "(" in decoded.decode() or "[" in decoded.decode() or "]" in decoded.decode() or "+" in decoded.decode() or "-" in decoded.decode() or "<" in decoded.decode() or ">" in decoded.decode() or "*" in decoded.decode() or "!" in decoded.decode()):
                            pass
                        else:
                            # -- Data sanitization and keyword check
                            for key in keywords_to_check:
                                km = re.findall(key, decoded.decode())
                                if km != []:
                                    key_count += 1

                            # If we have target patterns then extract this sample
                            if key_count != 0:
                                if len(decoded.decode()) >= 150:
                                    print(f"\n{infoS} Warning length of the decoded data is bigger than as we expected!")
                                    self.output_writer(out_file=f"sc0pe_decoded_javascript-{len(decoded.decode())}.js", mode="w", buffer=decoded.decode())
                                else:
                                    decc.append(decoded.decode())
                            else:
                                decc.append(decoded.decode())
                    else: # Otherwise if ve have byte stuff we also need to check everything in case of the suspicious stuff
                        if len(decoded.decode()) <= 6 and (")" in decoded.decode() or "(" in decoded.decode() or "[" in decoded.decode() or "]" in decoded.decode() or "+" in decoded.decode() or "-" in decoded.decode() or "<" in decoded.decode() or ">" in decoded.decode() or "*" in decoded.decode() or "!" in decoded.decode()):
                            pass
                        else:
                            # -- Data sanitization and keyword check
                            for key in keywords_to_check:
                                km = re.findall(key, decoded.decode())
                                if km != []:
                                    key_count += 1

                            # If we have target patterns then extract this sample
                            if key_count != 0:
                                if len(decoded.decode()) >= 150:
                                    print(f"\n{infoS} Warning length of the decoded data is bigger than as we expected!")
                                    self.output_writer(out_file=f"sc0pe_decoded_javascript-{len(decoded.decode())}.js", mode="w", buffer=decoded.decode())
                                else:
                                    decc.append(decoded.decode())
                            else:
                                decc.append(decoded.decode())
                except:
                    continue

        if decc != []:
            return decc
        else:
            return None

    def html_dump_javascript(self, soup_obj):
        # Dump javascript
        print(f"\n{infoS} Checking for Javascript...")
        javscr = soup_obj.find_all("script")
        if javscr != []:
            print(f"{infoS} Found [bold red]{len(javscr)}[white]. If there is a potential malicious one we will extract it...")
            for jv in javscr:
                jav_buf = jv.getText().replace("<script>", "").replace("</script>", "")
                # We need only malicious codes!
                mal_ind = 0
                for mcode in self.mal_code:
                    mtc = re.findall(mcode, jav_buf)
                    if mtc != []:
                        mal_ind += 1

                if mal_ind != 0 and len(jav_buf) > 0:
                    self.output_writer(out_file=f"sc0pe_carved_javascript-{len(jav_buf)}.js", mode="w", buffer=jav_buf)
        else:
            print(f"{errorS} There is no Javascript found!")
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

                    # Parsing attack keywords
                    if self.mal_code[mc]["type"] not in att_types:
                        att_types.append(self.mal_code[mc]["type"])
            print(mal_table)
            print(f"{infoS} Keywords for this sample: [bold red]{att_types}[white]")
        else:
            print(f"{errorS} There is no pattern found!")
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
        if pind != 0:
            print(f"\n{infoS} Looks like we found powershell code patterns!")
            print(powe_table)

    def output_writer(self, out_file, mode, buffer):
        with open(out_file, mode) as ff:
            ff.write(buffer)
        print(f"{infoS} Data saved as: [bold yellow]{out_file}[white]")

    def check_exploit_patterns(self, buffer):
        # Check equation.3 pattern
        chk_ex = re.findall(r'ion.3'.encode(), bytes.fromhex(buffer), re.IGNORECASE)
        if chk_ex != []:
            print(f"{infoS} This file contains possible [bold green]CVE-2017-11882[white] exploit. Performing extraction...")
            self.pat_ct += 1
            self.output_writer(out_file=f"sc0pe_extracted_exploit-{len(buffer)}.bin", mode="wb", buffer=binascii.unhexlify(buffer))

        # Check equation.2 pattern
        chk_ex = re.findall(r'ion.2'.encode(), bytes.fromhex(buffer), re.IGNORECASE)
        if chk_ex != []:
            print(f"{infoS} This file contains possible [bold green]CVE-2017-11882[white] exploit. Performing extraction...")
            self.pat_ct += 1
            self.output_writer(out_file=f"sc0pe_extracted_exploit-{len(buffer)}.bin", mode="wb", buffer=binascii.unhexlify(buffer))

        # Check OLE10naTiVE pattern
        chk_ex = re.findall(r"OLE10naTiVE".encode(), bytes.fromhex(buffer).replace(b"\x00", b""), re.IGNORECASE)
        if chk_ex != []:
            print(f"{infoS} This file contains possible [bold green]CVE-2017-11882[white] exploit. Performing extraction...")
            self.pat_ct += 1
            self.output_writer(out_file=f"sc0pe_extracted_exploit-{len(buffer)}.bin", mode="wb", buffer=binascii.unhexlify(buffer))

        # Check vbscript
        chk_ex = re.findall(r'(script|Create|vbscript|Function)'.encode(), bytes.fromhex(buffer), re.IGNORECASE)
        if chk_ex != []:
            print(f"{infoS} This file contains possible [bold green]VBScript[white] file. Performing extraction...")
            self.pat_ct += 1
            self.output_writer(out_file=f"sc0pe_extracted_script-{len(buffer)}.bin", mode="wb", buffer=binascii.unhexlify(buffer))

    def rtf_check_exploit_main(self, buffer):
        # This method is for detecting \binxxx based patterns
        chek = re.findall(r'\\bin'.encode(), buffer, re.IGNORECASE)
        if chek != []:
            bin_sec = re.findall(r'[a-f0-9]+\\bin[a-f0-9]+'.encode(), buffer, re.IGNORECASE)
            if bin_sec != []:
                if len(bin_sec[-1]) > 15:
                    remove = re.findall(r'\\bin[0]+'.encode(), bin_sec[-1], re.IGNORECASE)
                    finalbuffer = bin_sec[-1].replace(remove[0], b"")
                    print(f"{infoS} Looks like we found [bold green]\\binxxx[white] pattern. Attempting to identify and extraction...")
                    self.rtf_check_exploit_parse(exploit_buffer=finalbuffer)

        # This method is for detecting {\\?\\objudate} based patterns
        chek = re.findall(r'{\\[^}]+\\objupdate}'.encode(), buffer, re.IGNORECASE)
        if chek != []: # This is for preventing catastrophic backtrace issues
            bin_sec = re.findall(r'([0-9a-fA-F]+){\\[^}]+\\objupdate}([0-9a-fA-F]+)'.encode(), buffer, re.IGNORECASE)
            if bin_sec != []:
                print(f"{infoS} Looks like we found [bold green]\\objupdate[white] pattern. Attempting to identify and extraction...")
                self.rtf_check_exploit_parse(exploit_buffer=bin_sec[0][0]+bin_sec[0][1])

        # This method is for detecting {\\objupdate} based patterns
        chek = re.findall(r'{\\objupdate\}'.encode(), buffer, re.IGNORECASE)
        if chek != []:
            bin_sec = re.findall(r'([a-f0-9]+){\\objupdate}([a-f0-9]+)'.encode(), buffer, re.IGNORECASE)
            if bin_sec != []:
                print(f"{infoS} Looks like we found [bold green]\\objupdate[white] pattern. Attempting to identify and extraction...")
                self.rtf_check_exploit_parse(exploit_buffer=bin_sec[0][0]+bin_sec[0][1])

        # This method is for detecting \\objdata based patterns
        chek = re.findall(r'\\objdata[a-f0-9]+'.encode(), buffer, re.IGNORECASE)
        if chek != []:
            bin_sec = re.findall(r'\\objdata([a-f0-9]+)'.encode(), buffer, re.IGNORECASE)
            if bin_sec != []:
                # Looking for hex data existence
                for bsec in bin_sec:
                    if len(bsec) > 15:
                        self.rtf_check_exploit_parse(exploit_buffer=bsec)

        # This method is for detecting \\ods based patterns
        chek = re.findall(r'{\\ods[a-f0-9]+'.encode(), buffer, re.IGNORECASE)
        if chek != []:
            bin_sec = re.findall(r'{\\ods([a-f0-9]+)}([a-f0-9]+)'.encode(), buffer, re.IGNORECASE)
            if bin_sec != []:
                self.rtf_check_exploit_parse(exploit_buffer=bin_sec[0][0]+bin_sec[0][1])
            
    def rtf_check_exploit_parse(self, exploit_buffer):
        if len(exploit_buffer) % 2 == 0:
            self.check_exploit_patterns(buffer=exploit_buffer.decode())
        else:
            if exploit_buffer.decode()[0] == "0":
                new_bin_sec = exploit_buffer.decode()[1:]
                self.check_exploit_patterns(buffer=new_bin_sec)
            elif exploit_buffer.decode()[0] == "f":
                new_bin_sec = exploit_buffer.decode()[1:]
                self.check_exploit_patterns(buffer=new_bin_sec)
            else:
                pass

    def RTFAnalysis(self):
        # Scan file buffer for interesting patterns
        print(f"{infoS} Performing detection of the malicious code patterns...")
        mal_ind = 0
        for pat in self.mal_rtf_code:
            scan_pattern = pat
            if "\\" in scan_pattern:
                scan_pattern = re.escape(scan_pattern)
            regx = re.findall(scan_pattern, allstr)
            if regx != []:
                mal_ind += 1
                self.mal_rtf_code[pat]["count"] = len(regx)
        if mal_ind != 0:
            att_types = []
            rtf_table = Table()
            rtf_table.add_column("[bold green]Pattern", justify="center")
            rtf_table.add_column("[bold green]Description", justify="center")
            rtf_table.add_column("[bold green]Count", justify="center")

            for pat in self.mal_rtf_code:
                if self.mal_rtf_code[pat]["count"] != 0:
                    rtf_table.add_row(str(pat), str(self.mal_rtf_code[pat]["description"]), str(self.mal_rtf_code[pat]["count"]))

                    if self.mal_rtf_code[pat]["type"] not in att_types:
                        att_types.append(self.mal_rtf_code[pat]["type"])
            print(rtf_table)
            print(f"{infoS} Keywords for this sample: [bold red]{att_types}[white]")

            # Check for suspicious unescape pattern
            if self.mal_rtf_code["unescape"]["count"] != 0:
                unesc = re.findall(r'unescape\(\s*\'([^\']*)\'\s*\)', allstr)
                if unesc != []:
                    print(f"\n{infoS} Looks like we have obfuscated value via [bold green]unescape[white]. Performing deobfuscation...")
                    for un in unesc:
                        deobf = urllib.parse.unquote(un)
                        self.output_writer(out_file=f"sc0pe_deobfuscated_unescape-{len(deobf)}.bin", mode="w", buffer=deobf)
        else:
            print(f"{errorS} There is no malicious pattern found!")

        # Exploit detection and extraction
        print(f"\n{infoS} Performing embedded exploit/script detection...")
        fbuffer = open(self.targetFile, "rb").read()
        buf_trim = fbuffer.replace(b"\r", b"").replace(b"\t", b"").replace(b"\n", b"").replace(b" ", b"")
        print(f"{infoS} Looking for embedded binary sections...")
        self.rtf_check_exploit_main(buffer=buf_trim)
        if self.pat_ct == 0:
            print(f"{errorS} There is no suspicious embedded exploit/script pattern detected!")

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        self.DocumentYara()


# Execution area
try:
    docObj = DocumentAnalyzer(targetFile)
    ext = docObj.CheckExt()
    if ext == "docscan":
        docObj.BasicInfoGa()
    elif ext == "pdfscan":
        docObj.PDFAnalysis()
    elif ext == "onenote":
        docObj.OneNoteAnalysis()
    elif  ext == "html":
        docObj.HTMLanalysis()
    elif ext == "rtf":
        docObj.RTFAnalysis()
    elif ext == "unknown":
        print(f"{errorS} Analysis technique is not implemented for now. Please send the file to the developer for further analysis.")
    else:
        print(f"{errorS} File format is not supported.")
except:
    print(f"{errorS} An error occured while analyzing that file.")
    sys.exit(1)