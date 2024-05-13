import os
import sys
import json
import yara
import hashlib
import warnings
import subprocess
import configparser

try:
    # by default, assume we're running as a module, inside a package
    from .utils import (
        err_exit, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool,
    )
except ImportError: # fallback for running as "raw" Python file
    from utils import (
        err_exit, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool,
    )

try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

try:
    import lief
except:
    err_exit("Error: >lief< module not found.")

try:
    import pygore
except:
    err_exit("Error: >pygore< module not found.")

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
strings_param = "--all"
if sys.platform == "win32":
    path_seperator = "\\"
    strings_param = "-a"
elif sys.platform == "darwin":
    strings_param = "-a"

CATEGORIES = (
    "Networking",
    "File",
    "Process",
    "Memory Management",
    "Information Gathering",
    "System/Persistence",
    "Cryptography",
    "Evasion",
    "Other/Unknown"
)


class LinuxAnalyzer:
    def __init__(self, base_path, target_file, rule_path, strings_lines):
        self.base_path = base_path
        self.target_file = target_file
        self.rule_path = rule_path
        self.strings_output = strings_lines

        self.report = self.__class__.init_blank_report(default="")

        self.categorized_strmatches = {cat: [] for cat in CATEGORIES}

        _binary = lief.parse(target_file)
        self.symbol_names = [sym.name for sym in _binary.symbols]
        self.binary = _binary

    def parse_section_content(self, sec_name):
        return "".join([chr(unicode_point)
            for unicode_point in self.binary.get_section(sec_name).content])

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
            print(f"[bold white on red]Not a single rule matched for {filename}");return

        for match in recorded_matches:
            print(f">>> Rule name: [i][bold magenta]{match}[/i]")
            yara_t = init_table("Offset", "Matched String/Byte", style="bold green")
            self.report["matched_rules"].append({str(match): []})
            for pi in self.__class__.yara_matches_to_patterninfo(match.strings):
                self.report["matched_rules"][-1][str(match)].append(pi)
                yara_t.add_row(pi.values())

            print(yara_t)
            print(" ")

    def emit_general_information(self):
        print(f"{infoS} General Informations about [bold green]{self.target_file}")
        print(f"[bold red]>>>>[white] Machine Type: [bold green]{self.binary.header.machine_type.name}")
        print(f"[bold red]>>>>[white] Binary Entrypoint: [bold green]{hex(self.binary.entrypoint)}")
        if self.binary.has_section(".interp"):
            interpreter = self.parse_section_content(".interp")
            print(f"[bold red]>>>>[white] Interpreter: [bold green]{interpreter}")
            self.report["interpreter"] = interpreter
        print(f"[bold red]>>>>[white] Number of Sections: [bold green]{len(self.binary.sections)}")
        print(f"[bold red]>>>>[white] Number of Segments: [bold green]{len(self.binary.segments)}")
        self.report["machine_type"] = self.binary.header.machine_type.name
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
            self.report["sections"].append(metadata)
            metadata["name"] = "[bold red]"+metadata["name"]
            # since 3.6, dict objects guarantee insertion order preservation
            section_t.add_row(*metadata.values()) # so this is ok for filling a row

        print(section_t)

    def handle_debug_sections(self):
        print(f"\n{infoS} Performing debug section hunt...")
        ts = "[bold red]>>>>[white] {sn}"
        section_names = [print(ts.format(sn=s.name)) or s.name for s in self.binary.sections if ".debug_" in s.name]

        if len(section_names) == 0:
            print("[bold white on red]There aren't any debug sections in this binary!!")
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
            if seg.type.name.strip() == "":
                continue
            sec_names = [s.name for s in seg.sections]
            segments_t.add_row(f"[bold red]{seg.type.name}", str(sec_names))
            self.report["segments"].append(seg.type.name)
        print(segments_t)

    def list_libraries(self):
        if len(self.binary.libraries) == 0:
            return

        libs = init_table("[bold green]Libraries")
        for x in self.binary.libraries:
            libs.add_row(f"[bold red]{x}")
            self.report["libraries"].append(x)
        print(libs)

    def golang_analyze(self):
        print(f"\n{infoS} Analyzing [bold green]Golang [white]binary...")
        go_file = pygore.GoFile(self.target_file)
        print(f"\n{infoS} Parsing compiler information...")
        comp = go_file.get_compiler_version()
        print(f"[bold magenta]>>>[white] Compiler Version: [bold green]{comp.name}")
        print(f"[bold magenta]>>>[white] Timestamp: [bold green]{comp.timestamp}")

        go_pkgs = go_file.get_packages()
        print(f"\n{infoS} Performing deep inspection against target binary...")
        pkg_table = init_table("Name", "FilePath", col_prefix="[bold green]", title="* Information About Packages *")
        for pk in go_pkgs:
            pkg_table.add_row(pk.name, pk.filepath)
        print(pkg_table)

        for pk in go_pkgs:
            emit_table(pk.methods, "method", "Name", "Receiver", "Offset",
                row_extractor=lambda m: (m.name, m.receiver, hex(m.offset)), col_prefix="[bold green]")
            emit_table(pk.functions, "function", "Name", "Offset",
                row_extractor=lambda f: (f.name, hex(f.offset)), col_prefix=["bold green"])
        emit_table(go_file.get_std_lib_packages(), "imported libraries",
            "[bold green]Name", row_extractor=lambda i:i.name)

    def analyze(self, indicators_by_category, emit_report=False):
        """Execute all analysis methods, including strings matching based on indicator input."""
        categorized_func_count = 0
        self.report["filename"] = self.target_file

        for category in indicators_by_category:
            for indicator in (i for i in no_blanks(indicators_by_category[category]) if i in self.symbol_names):
                self.categorized_strmatches[category].append(indicator)
                categorized_func_count += 1

        score_per_cat = {}
        for cat, matches in self.categorized_strmatches:
            if cat in ("Information Gathering", "System/Persistence", "Cryptography", "Evasion"):
                single_cat_t = init_table(style="yellow", title="* WARNING *", title_style="blink italic yellow")
            else:
                single_cat_t = init_table()

            single_cat_t.add_column(f"Functions or Strings about [bold green]{cat}", justify="center")
            self.report["categories"].update({cat: []})
            for str_match in no_blanks(matches):
                single_cat_t.add_row(f"[bold red]{str_match}")
                self.report["categories"][cat].append(str_match)

                try:
                    score_per_cat[cat] += 1
                except KeyError:
                    score_per_cat[cat] = 1

            print(single_cat_t)

        print(f"\n{infoS} Performing YARA rule matching...")
        self.yara_scan(self.target_file)

        self.parse_sections()
        self.parse_segments()
        self.list_libraries()
        self.handle_debug_sections()

        print(f"\n[bold green]->[white] Statistics for: [bold green][i]{self.target_file}[/i]")

        stats = init_table("Categories", "Number of Functions or Strings")

        stats.add_row("[bold green][i]All Functions[/i]", f"[bold green]{len(self.symbol_names)}")
        stats.add_row("[bold green][i]Categorized Functions[/i]", f"[bold green]{categorized_func_count}")

        self.report["categorized_functions"] = categorized_func_count
        self.report["number_of_functions"] = len(self.symbol_names)

        for cat, score in score_per_cat.items():
            if cat == "System/Persistence" or cat == "Cryptography" or cat == "Information Gathering":
                stats.add_row(f"[bold yellow]{cat}", f"[bold red]{score}")
            else:
                stats.add_row(cat, str(score))
        print(stats)

        if categorized_func_count < 10:
            print("[blink bold white on red]This file might be obfuscated or encrypted. [white]Try [bold green][i]--packer[/i] [white]to scan this file for packers.")
            print("[bold]You can also use [green][i]--hashscan[/i] [white]to scan this file.")
            sys.exit(0)

        if emit_report:
            self.save_report("linux")

        # run golang specific analysis if applicable
        if "runtime.goexit" in self.strings_output and "runtime.gopanic" in self.strings_output:
            print(f"\n{infoS} Qu1cksc0pe was identified this binary as [bold green]Golang[white] binary.")
            if user_confirm(">>> Do you want to perform special analysis[Y/n]?: "):
                self.golang_analyze()

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
    def map_to_fname(key): # maps to wordlist files
        try:
            return _special_cases[key]
        except KeyError: # for now only "Networking" => "Networking"(.txt), but in the future all mappings will be handled like this
            return key

    indicators_by_category = {}
    spath = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}"
    for cat in CATEGORIES:
        with open(spath + map_to_fname(cat) + ".txt") as catfile:
            indicators_by_category[cat] = catfile.read().split("\n")

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
        sys.argv[1], emit_reports=sys.argv[2])


if __name__ == "__main__":
    main()
