import os
import re
import sys
import json
import yara
import hashlib
import warnings
import subprocess
import configparser
from .go_binary_parser import GolangParser
from .linux_emulator import Linxcution

try:
    # by default, assume we're running as a module, inside a package
    from .utils import (
        err_exit, get_argv, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool,
    )
except ImportError: # fallback for running as "raw" Python file
    from utils import (
        err_exit, get_argv, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool,
    )

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import lief
except:
    err_exit("Error: >lief< module not found.")

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
strings_param = "-a"
if sys.platform == "win32":
    path_seperator = "\\"

CATEGORIES = {
    "Networking": [],
    "File": [],
    "Process": [],
    "Memory Management": [],
    "Information Gathering": [],
    "System/Persistence": [],
    "Cryptography": [],
    "Evasion": [],
    "Other/Unknown": []
}

class LinuxAnalyzer:
    def __init__(self, base_path, target_file, rule_path, strings_lines):
        self.base_path = base_path
        self.target_file = target_file
        self.rule_path = rule_path
        self.strings_output = strings_lines
        self.report = self.__class__.init_blank_report(default="")
        _binary = lief.parse(target_file)
        self.symbol_names = [sym.name for sym in _binary.symbols]
        self.binary = _binary
        self.is_go_binary = None
        self.categorized_func_count = 0

    def parse_section_content(self, sec_name):
        return "".join([chr(unicode_point)
            for unicode_point in self.binary.get_section(sec_name).content if unicode_point != 0])

    def check_bin_security(self):
        binsec_t = init_table("[bold yellow]NX", "[bold yellow]PIE", title="* Security *")
        binsec = {"NX": self.binary.has_nx is True, "PIE": self.binary.is_pie is True}
        binsec_t.add_row(
            stylize_bool(binsec["NX"], invert_style=True),
            stylize_bool(binsec["PIE"])
        )
        print(binsec_t)
        self.report["security"] = binsec

    def calc_hashes(self, filename):
        hashmd5 = hashlib.md5()
        hashsha1 = hashlib.sha1()
        hashsha256 = hashlib.sha256()
        try:
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashmd5.update(chunk)
            ff.close()
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha1.update(chunk)
            ff.close()
            with open(filename, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hashsha256.update(chunk)
            ff.close()
        except: # TODO: more specific; also: handle/raise!
            pass
        print(f"[bold red]>>>>[white] MD5: [bold green]{hashmd5.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA1: [bold green]{hashsha1.hexdigest()}")
        print(f"[bold red]>>>>[white] SHA256: [bold green]{hashsha256.hexdigest()}")
        self.report["hash_md5"] = hashmd5.hexdigest()
        self.report["hash_sha1"] = hashsha1.hexdigest()
        self.report["hash_sha256"] = hashsha256.hexdigest()

    def save_report(self, target_os):
        with open(f"sc0pe_{target_os}_report.json", "w") as report_file:
            json.dump(self.report, report_file, indent=4)
            print(f"\n[bold magenta]>>>[bold white] Report file saved into: [bold blink yellow]{report_file.name}\n")

    def yara_scan(self, filename):
        combined_path = f"{self.base_path}{path_seperator}{self.rule_path}"
        recorded_matches = []
        for rule_fname in os.listdir(combined_path):
            try:
                for matched in yara.compile(f"{combined_path}{rule_fname}").match(filename):
                    if len(matched.strings) > 0 and not matched in recorded_matches:
                        recorded_matches.append(matched)
            except:
                continue

        if len(recorded_matches) == 0:
            print(f"[bold white on red]There is no rule matched for {filename}");return

        for match in recorded_matches:
            print(f">>> Rule name: [i][bold magenta]{match}[/i]")
            yara_t = init_table("Offset", "Matched String/Byte", style="bold green")
            self.report["matched_rules"].append({str(match): []})
            for pi in self.__class__.yara_matches_to_patterninfo(match.strings):
                self.report["matched_rules"][-1][str(match)].append(pi)
                yara_t.add_row(str(pi["offset"]), str(pi["matched_pattern"]))

            print(yara_t)
            print(" ")

    def emit_general_information(self):
        print(f"{infoS} General Informations about [bold green]{self.target_file}")
        print(f"[bold red]>>>>[white] Machine Type: [bold green]{str(self.binary.header.machine_type).split('.')[-1]}")
        print(f"[bold red]>>>>[white] Binary Entrypoint: [bold green]{hex(self.binary.entrypoint)}")
        if self.binary.has_section(".interp"):
            interpreter = self.parse_section_content(".interp")
            print(f"[bold red]>>>>[white] Interpreter: [bold green]{interpreter}")
            self.report["interpreter"] = interpreter
        print(f"[bold red]>>>>[white] Number of Sections: [bold green]{len(self.binary.sections)}")
        print(f"[bold red]>>>>[white] Number of Segments: [bold green]{len(self.binary.segments)}")
        self.report["machine_type"] = str(self.binary.header.machine_type).split('.')[-1]
        self.report["binary_entrypoint"] = str(hex(self.binary.entrypoint))
        self.report["number_of_sections"] = len(self.binary.sections)
        self.report["number_of_segments"] = len(self.binary.segments)
        self.calc_hashes(self.target_file)
        self.check_bin_security()

    def parse_sections(self):
        section_t = init_table(
            "Section Names", "Size(bytes)",
            "Offset", "Virtual Address", "Entropy",
            col_prefix="[bold green]",
            title="* Informations About Sections *",
        )
        for sec in self.binary.sections:
            if sec.name.strip() == "":
                continue
            metadata = { # TODO consider OrderedDict type instead
                "name": sec.name, "size": str(sec.size),
                "offset": str(hex(sec.offset)),
                "virtual_address": str(hex(sec.virtual_address)),
                "entropy": str(sec.entropy)
            }
            self.report["sections"].append(metadata.copy())
            check_go = metadata["name"]
            metadata["name"] = "[bold red]"+metadata["name"]
            # Check for go presence
            if ".go" in check_go[:3] and check_go[:4] != ".got":
                self.is_go_binary = True
            # since 3.7, dict objects guarantee insertion order preservation
            section_t.add_row(*metadata.values()) # so this is ok for filling a row

        print(section_t)

    def handle_debug_sections(self):
        print(f"\n{infoS} Performing debug section hunt...")
        ts = "[bold red]>>>>[white] {sn}"
        section_names = [print(ts.format(sn=s.name)) or s.name for s in self.binary.sections if ".debug_" in s.name]

        if len(section_names) == 0:
            print("[bold white on red]There is no debug sections in this binary!!")
            return

        if not user_confirm(f"\n>> Do you want to analyze debug strings?[Y/n]: "):
            return

        print()
        for name in [n for n in section_names if n == ".debug_str"]:
            print(f"[bold magenta]>>[white] Section: [bold yellow]{self.binary.get_section(name).name}[white] | Content: [bold cyan]{self.parse_section_content(name)}")

    def parse_segments(self):
        segments_t = init_table("[bold green]Segments", "[bold green]Contained Sections",
            title="* Informations About Segments *")

        for seg in self.binary.segments:
            try:
                if str(seg.type).split(".")[-1] == "":
                    continue
                sec_names = [s.name for s in seg.sections]
                segments_t.add_row(f"[bold red]{str(seg.type).split('.')[-1]}", str(sec_names))
                self.report["segments"].append(str(seg.type).split(".")[-1])
            except:
                continue
        print(segments_t)

    def list_libraries(self):
        if len(self.binary.libraries) == 0:
            return

        libs = init_table("[bold green]Libraries")
        for x in self.binary.libraries:
            libs.add_row(f"[bold red]{x}")
            self.report["libraries"].append(x)
        print(libs)

    def analyze(self, indicators_by_category, emit_report=False):
        """Execute all analysis methods, including strings matching based on indicator input."""
        
        self.report["filename"] = self.target_file

        for category in indicators_by_category:
            for func in indicators_by_category[category]["funcs"]:
                chk = re.findall(func, str(self.strings_output), re.IGNORECASE)
                if chk != []:
                    indicators_by_category[category]["occurence"] += 1
                    CATEGORIES[category].append(func)
                    self.categorized_func_count += 1

        for cat in CATEGORIES:
            if CATEGORIES[cat]:
                if cat in str(["Information Gathering", "System/Persistence", "Cryptography", "Evasion"]):
                    single_cat_t = Table(style="yellow", title="* WARNING *", title_style="blink italic yellow")
                else:
                    single_cat_t = Table()
                single_cat_t.add_column(f"Functions or Strings about [bold green]{cat}", justify="center")
                for func in CATEGORIES[cat]:
                    single_cat_t.add_row(f"[bold red]{func}")
                print(single_cat_t)
        self.report["categories"] = CATEGORIES

        print(f"\n{infoS} Performing YARA rule matching...")
        self.yara_scan(self.target_file)

        self.parse_sections()
        self.parse_segments()
        self.list_libraries()
        self.handle_debug_sections()

        # Emulate target binary in the isolated environment (Docker+Qemu)
        print(f"\n{infoS} Do you want to perform binary emulation on the isolated environment?")
        if user_confirm(">>> Choice[Y/n]: "):
            linxc = Linxcution(self.target_file, str(self.binary.header.machine_type).split('.')[-1])
            linxc.perform_analysis()

        # run golang specific analysis if applicable
        if self.is_go_binary:
            print(f"\n{infoS} Qu1cksc0pe was identified this binary as [bold green]Golang[white] binary.")
            if user_confirm(">>> Do you want to perform special analysis[Y/n]?: "):
                golang_parser = GolangParser(self.target_file)
                golang_parser.golang_analysis_main()
                go_report = golang_parser.record_analysis_summary()
                for key in go_report:
                    if go_report[key] != []:
                        CATEGORIES[key] += go_report[key]
                        self.categorized_func_count += len(go_report[key])
                        self.symbol_names += go_report[key]

        if self.categorized_func_count != 0:
            print(f"\n[bold green]->[white] Statistics for: [bold green][i]{self.target_file}[/i]")
            stats = init_table("Categories", "Number of Functions or Strings")
            stats.add_row("[bold green][i]All Functions[/i]", f"[bold green]{len(self.symbol_names)}")
            stats.add_row("[bold green][i]Categorized Functions[/i]", f"[bold green]{self.categorized_func_count}")
            self.report["categorized_functions"] = self.categorized_func_count
            self.report["number_of_functions"] = len(self.symbol_names)
            for cat in CATEGORIES:
                if CATEGORIES[cat]:
                    if cat in str(["Information Gathering", "System/Persistence", "Cryptography", "Evasion"]):
                        stats.add_row(f"[bold yellow]{cat}", f"[bold red]{len(CATEGORIES[cat])}")
                    else:
                        stats.add_row(cat, str(len(CATEGORIES[cat])))
            print(stats)

        if self.categorized_func_count > 0 and self.categorized_func_count < 10:
            print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
            print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")

        if emit_report:
            self.save_report("linux")

    @staticmethod
    def yara_matches_to_patterninfo(patterns):
        out = []
        for pattern in patterns:
            instance = pattern.instances[0]
            pattern_info = {"offset": hex(instance.offset)}
            try:
                pattern_info["matched_pattern"] = instance.matched_data.decode("ascii")
            except:
                pattern_info["matched_pattern"] = str(instance.matched_data)
            finally:
                out.append(pattern_info)
        return out

    @staticmethod
    def init_blank_report(default="NO_RESULT_PRESENT"):
        """
        Generate a blank report object.

        You can pass an argument to control the default value
        for untouched report keys. If nothing is passed, a certain
        string is used. It might be preferrable to pass
        `None`/""/a custom string instead.
        """
        return {
            "filename": default,
            "machine_type": default,
            "hash_md5": default, "hash_sha1": default, "hash_sha256": default,
            "binary_entrypoint": default, "interpreter": default,
            "categorized_functions": 0, "number_of_functions": 0,
            "number_of_sections": 0, "number_of_segments": 0,
            "libraries": [],
            "sections": [], "segments": [],
            "categories": {},
            "matched_rules": [],
            "security": {"NX": False, "PIE": False}
        }


def run(sc0pe_path, target_file, emit_report=False):
    subprocess.run(f"strings {strings_param} \"{target_file}\" > temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    if sys.platform != "win32":
        subprocess.run(f"strings {strings_param} -e l {target_file} >> temp.txt", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

    conf = configparser.ConfigParser()
    conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux.conf")

    # TODO once I sort out the actual filenames to be consistent, we can get rid off all these cases
    _special_cases = {
        "File": "Files",
        "Process": "Processes",
        "Memory Management": "Memory",
        "Information Gathering": "Infoga",
        "System/Persistence": "Persistence",
        "Cryptography": "Crypto",
        "Evasion": "Debug",
        "Other/Unknown": "Others"
    }
    indicators_by_category = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux_func_categories.json"))

    lina = LinuxAnalyzer(
        base_path=sc0pe_path, target_file=target_file,
        rule_path=conf["Rule_PATH"]["rulepath"],
        strings_lines=open("temp.txt", "r").read().split("\n"),
    )
    lina.emit_general_information()
    lina.analyze(indicators_by_category, emit_report=emit_report)

def main():
    warnings.warn("Please opt for importing and directly calling the run function instead.", PendingDeprecationWarning)

    from pathlib import Path
    run(Path(__file__).parent.parent, # execute with autodeduced scope path
        sys.argv[1], emit_report=get_argv(2) == "True")


if __name__ == "__main__":
    main()
