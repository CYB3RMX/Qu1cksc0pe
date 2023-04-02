#!/usr/bin/python3

import re
import os
import sys
import zipfile
import configparser

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
targetFile = str(sys.argv[1])

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# All strings
allstr = open("temp.txt", "r").read()

class DocumentAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile

    # Checking for file extension
    def CheckExt(self):
        if self.targetFile.endswith(".doc") or self.targetFile.endswith(".docx") or self.targetFile.endswith(".xls") or self.targetFile.endswith(".xlsx") or self.targetFile.endswith(".docm") or self.targetFile.endswith(".xlsm"):
            return "docscan"
        elif self.targetFile.endswith(".pdf"):
            return "pdfscan"
        elif self.targetFile.endswith(".one"):
            return "onenote"
        else:
            return "unknown"

    # Yara Scanner
    def DocumentYara(self):
        yara_match_indicator = 0
        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(f"{sc0pe_path}/Systems/Multiple/multiple.conf")
        rule_path = conf["Rule_PATH"]["rulepath"]
        finalpath = f"{sc0pe_path}/{rule_path}"
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
            print(f"[blink bold white on red]Not any rules matched for {self.targetFile}")

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
                print(f"[blink bold white on red]Not any interesting links found.")
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
        print(f"\n{infoS} Searching for interesting links...")
        url_match = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", allstr)
        if url_match != []:
            for lnk in url_match:
                if "schemas.openxmlformats.org" not in lnk and "schemas.microsoft.com" not in lnk and "purl.org" not in lnk and "www.w3.org" not in lnk and "go.microsoft.com" not in lnk:
                    print(f"[bold magenta]>>>[white] {lnk}")

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
        pdata = open(self.targetFile, "rb")
        pdf = PDFParser(pdata)
        doc = PDFDocument(pdf)

        # Gathering meta information
        print(f"\n{infoS} Gathering meta information...")
        metaTable = Table(title="* Meta Information *", title_style="bold italic cyan", title_justify="center")
        metaTable.add_column("[bold green]Key", justify="center")
        metaTable.add_column("[bold green]Value", justify="center")
        if doc.info[0] != {}:
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
            "/Action", "cmd.exe", "system32", "%HOMEDRIVE%"
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
            print(f"{infoS} No suspicious strings found.")

        # Looking for embedded links
        print(f"\n{infoS} Looking for embedded URL\'s...")
        urlTable = Table(title="* Embedded URL\'s *", title_style="bold italic cyan", title_justify="center")
        urlTable.add_column("[bold green]URL", justify="center")
        uustr = 0
        linkz = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", allstr)
        if len(linkz) != 0:
            lcontrol = []
            for l in linkz:
                if "schemas.openxmlformats.org" not in l and "schemas.microsoft.com" not in l and "purl.org" not in l and "www.w3.org" not in l and "go.microsoft.com" not in l and "ns.adobe.com" not in l and "www.adobe.com" not in l and "www.microsoft.com" not in l:
                    if l not in lcontrol:
                        urlTable.add_row(f"[bold yellow]{l}")
                        uustr += 1
                        lcontrol.append(l)
            if uustr != 0:
                print(urlTable)
            else:
                print(f"{infoS} No interesting URL\'s found.")
        else:
            print(f"{errorS} No URL\'s found.")

        # Embedded file extraction Method 1
        if embedded_switch != 0:
            print(f"\n{infoS} Performing embedded file extraction...")
            print(f"{infoS} Locating embedded file streams...")
            for obid in range(100):
                try:
                    tmp = doc.getobj(obid)
                    if "EmbeddedFiles" in str(tmp):
                        print(f"{infoS} Found embedded file stream at object ID: [bold yellow]{obid}")
                        print(f"{infoS} Locating data stream...")
                        if "Names" in str(tmp["EmbeddedFiles"].resolve()) and len(tmp["EmbeddedFiles"].resolve()["Names"]) == 2:
                            if "EF" in str(tmp["EmbeddedFiles"].resolve()["Names"][1].resolve()):
                                if "F" in str(tmp["EmbeddedFiles"].resolve()["Names"][1].resolve()["EF"].resolve()):
                                    print(f"{infoS} Data stream found. Extracting...")
                                    emb = tmp["EmbeddedFiles"].resolve()["Names"][1].resolve()["EF"].resolve()["F"].resolve().get_data()
                                    outfile = open(f"sc0pe_embedded_data.bin", "wb")
                                    outfile.write(emb)
                                    outfile.close()
                                    print(f"{infoS} Embedded file extracted to [bold yellow]sc0pe_embedded_data.bin[white]")
                                    break
                except:
                    continue

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
    elif ext == "unknown":
        print(f"{errorS} Analysis tecnique is not implemented for now. Please send the file to the developer for further analysis.")
    else:
        print(f"{errorS} File format is not supported.")
except:
    print(f"{errorS} An error occured while analyzing that file.")
    sys.exit(1)
