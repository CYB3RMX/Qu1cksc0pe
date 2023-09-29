import os
import sys
import json
import yara
import getpass
import hashlib
import configparser
from rich import print
from rich.table import Table

username = getpass.getuser()
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Make compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

class Sc0peHelper:
    def __init__(self, sc0pe_path):
        self.sc0pe_path = sc0pe_path

    def cleanup_junks(self):
        junkFiles = ["temp.txt", ".path_handler", ".target-file.txt", ".target-folder.txt", "TargetAPK/", "TargetSource/"]
        for junk in junkFiles:
            if os.path.exists(junk):
                if sys.platform != "win32":
                    os.system(f"rm -rf {junk}")
                else:
                    os.system(f"powershell -c \"del {junk} -Force -Recurse\"")

    def setup_virtual_environment(self):
        # Check if Qu1cksc0pe running in virtualenv
        print(f"{infoS} Checking if Qu1cksc0pe is running in virtual environment...")
        if sys.prefix != sys.base_prefix:
            print(f"{foundS} Virtual environment detected. Here you go!\n")
        else:
            print(f"{errorS} Virtual environment not detected. Don\'t worry I will handle it...")
            if os.path.exists("sc0pe_venv"):
                # Activating virtual environment
                if os.environ["SHELL"] == "/usr/bin/fish":
                    print(f"\n{infoS} Execute the following command to activate virtual environment. And then run Qu1cksc0pe!")
                    print("[bold magenta]>>>[white] Command: [bold green]source sc0pe_venv/bin/activate.fish")
                    sys.exit(0)
                elif os.environ["SHELL"] == "/usr/bin/bash" or os.environ["SHELL"] == "/bin/bash" or os.environ["SHELL"] == "/usr/bin/zsh":
                    print(f"\n{infoS} Execute the following command to activate virtual environment. And then run Qu1cksc0pe!")
                    print("[bold magenta]>>>[white] Command: [bold green]source sc0pe_venv/bin/activate")
                    sys.exit(0)
                else:
                    print(f"{errorS} Shell type not detected!")
                    sys.exit(1)
            else:
                print(f"{infoS} Creating a virtual environment...")
                if os.path.exists(f"/home/{username}/.local/bin/virtualenv"):
                    os.system(f"virtualenv -p python sc0pe_venv")
                    print(f"\n{foundS} Virtual environment created. Execute program again for further instructions.")
                    print(f"[bold magenta]>>>[white] Command: [bold green]python qu1cksc0pe.py --setup_venv")
                    sys.exit(0)
                else:
                    print(f"{errorS} Error: >virtualenv< not found. Downloading it for you...")
                    os.system("pip3 install virtualenv")
                    os.system(f"virtualenv -p python sc0pe_venv")
                    print(f"\n{foundS} Virtual environment created. Execute program again for further instructions.")
                    print(f"[bold magenta]>>>[white] Command: [bold green]python qu1cksc0pe.py --setup_venv")
                    sys.exit(0)

    def hash_calculator(self, filename, report_object):
        self.filename = filename
        self.report_object = report_object

        hashmd5 = hashlib.md5()
        hashsha1 = hashlib.sha1()
        hashsha256 = hashlib.sha256()
        try:
            with open(self.filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashmd5.update(chunk)
            ff.close()
            with open(self.filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha1.update(chunk)
            ff.close()
            with open(self.filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha256.update(chunk)
            ff.close()
        except:
            pass
        print(f"[bold red]>>>>[white] MD5: [bold green]{hashmd5.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA1: [bold green]{hashsha1.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA256: [bold green]{hashsha256.hexdigest()}")
        self.report_object["hash_md5"] = hashmd5.hexdigest()
        self.report_object["hash_sha1"] = hashsha1.hexdigest()
        self.report_object["hash_sha256"] = hashsha256.hexdigest()

    def report_writer(self, target_os, report_object):
        self.target_os = target_os
        self.report_object = report_object

        with open(f"sc0pe_{self.target_os}_report.json", "w") as rp_file:
            json.dump(self.report_object, rp_file, indent=4)
        print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]sc0pe_{self.target_os}_report.json\n")

    def yara_rule_scanner(self, target_os, filename, config_path, report_object):
        self.target_os = target_os
        self.filename = filename
        self.config_path = config_path
        self.report_object = report_object

        yara_match_indicator = 0
        # Parsing config file to get rule path
        conf = configparser.ConfigParser()
        conf.read(self.config_path)
        rule_path = conf["Rule_PATH"]["rulepath"]
        if self.target_os == "android":
            try:
                allRules = os.listdir(rule_path)
            except:
                finalpath = f"{self.sc0pe_path}{path_seperator}{rule_path}"
                allRules = os.listdir(finalpath)
        else:
            finalpath = f"{self.sc0pe_path}{path_seperator}{rule_path}"
            allRules = os.listdir(finalpath)

        # This array for holding and parsing easily matched rules
        yara_matches = []
        for rul in allRules:
            try:
                rules = yara.compile(f"{finalpath}{rul}")
                tempmatch = rules.match(self.filename)
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
                self.report_object["matched_rules"].append({str(rul): []})
                for mm in rul.strings:
                    yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
                    try:
                        self.report_object["matched_rules"][-1][str(rul)].append({"offset": hex(mm[0]) ,"matched_pattern": mm[2].decode("ascii")})
                    except:
                        self.report_object["matched_rules"][-1][str(rul)].append({"offset": hex(mm[0]) ,"matched_pattern": str(mm[2])})
                print(yaraTable)
                print(" ")

        if yara_match_indicator == 0:
            print(f"[bold white on red]There is no rules matched for {self.filename}")

    def recursive_dir_scan(self, target_directory):
        self.target_directory = target_directory
        fnames = []
        for root, d_names, f_names in os.walk(self.target_directory):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames