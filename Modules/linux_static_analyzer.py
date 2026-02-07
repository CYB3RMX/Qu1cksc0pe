import re
import sys
import json
import warnings
import configparser
import shutil
import subprocess
from .analysis.multiple.go_binary_parser import GolangParser
from .analysis.linux.linux_emulator import Linxcution

try:
    # by default, assume we're running as a module, inside a package
    from .utils.helpers import (
        err_exit, get_argv, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool, save_report
    )
    from .analysis.multiple.multi import calc_hashes, perform_strings, yara_rule_scanner
except ImportError: # fallback for running as "raw" Python file
    from utils.helpers import (
        err_exit, get_argv, emit_table, init_table,
        no_blanks, user_confirm, stylize_bool, save_report
    )
    from analysis.multiple.multi import calc_hashes, perform_strings, yara_rule_scanner

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
        if not _binary:
            err_exit(f"{errorS} Failed to parse target ELF with LIEF.")

        self.symbol_names = self._collect_function_candidates(_binary, strings_lines)
        self.binary = _binary
        self.is_go_binary = None
        self.categorized_func_count = 0
        # Best-effort hint for debugging/report consumers.
        self.report["number_of_functions_source"] = self._function_count_source

    def _collect_lief_symbol_names(self, binary):
        names = []
        try:
            for sym in getattr(binary, "symbols", []) or []:
                nm = getattr(sym, "name", "")
                if nm:
                    names.append(str(nm))
        except Exception:
            pass

        # Some LIEF builds expose dynamic symbols separately.
        try:
            for sym in getattr(binary, "dynamic_symbols", []) or []:
                nm = getattr(sym, "name", "")
                if nm:
                    names.append(str(nm))
        except Exception:
            pass

        # Some LIEF versions expose imported/exported function names as lists.
        for attr in ("imported_functions", "exported_functions"):
            try:
                vals = getattr(binary, attr, None)
                if vals:
                    for v in vals:
                        if v:
                            names.append(str(v))
            except Exception:
                pass

        # De-dup while preserving order.
        return list(dict.fromkeys([n for n in names if isinstance(n, str) and n.strip()]))

    def _collect_readelf_functions(self):
        readelf = shutil.which("readelf")
        if not readelf:
            return []
        try:
            proc = subprocess.run(
                [readelf, "-Ws", self.target_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception:
            return []
        if proc.returncode != 0 or not proc.stdout:
            return []

        out = []
        for line in proc.stdout.splitlines():
            # Example columns:
            #  123: 00000000     0 FUNC    GLOBAL DEFAULT  UND socket@GLIBC_2.2.5
            if " FUNC " not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            name = parts[-1].strip()
            if name and name != "":
                out.append(name)

        return list(dict.fromkeys(out))

    def _collect_strings_function_candidates(self, strings_lines):
        # Heuristic: keep "identifier-like" tokens, avoid paths/URLs/whitespace.
        out = []
        for s in strings_lines or []:
            if not s or not isinstance(s, str):
                continue
            s = s.strip()
            if not s or len(s) < 3 or len(s) > 128:
                continue
            if any(x in s for x in (" ", "\t", "/", "\\", "://")):
                continue
            # Typical function/symbol formats: foo, foo_bar, foo@GLIBC_2.2.5
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@.]{2,127}", s):
                continue
            low = s.lower()
            if low in ("elf", "gnu", "glibc", "linux"):
                continue
            # Drop obvious shared object names.
            if low.endswith(".so") or ".so." in low:
                continue
            out.append(s)

        return list(dict.fromkeys(out))

    def _collect_function_candidates(self, binary, strings_lines):
        """
        Populate `self.symbol_names` used in stats.

        Order:
        1) LIEF symbols/dynamic symbols/imported/exported functions (if available)
        2) readelf FUNC symbols (if available)
        3) strings-based heuristic (best-effort for stripped/odd-arch binaries)
        """
        self._function_count_source = "unknown"

        names = self._collect_lief_symbol_names(binary)
        if names:
            self._function_count_source = "lief"
            return names

        names = self._collect_readelf_functions()
        if names:
            self._function_count_source = "readelf"
            return names

        names = self._collect_strings_function_candidates(strings_lines)
        if names:
            self._function_count_source = "strings_heuristic"
            return names

        self._function_count_source = "none"
        return []

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
        calc_hashes(self.target_file, self.report)
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
        yara_rule_scanner(self.rule_path, self.target_file, self.report)

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
            save_report("linux", self.report)

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
            "number_of_functions_source": default,
            "number_of_sections": 0, "number_of_segments": 0,
            "libraries": [],
            "sections": [], "segments": [],
            "categories": {},
            "matched_rules": [],
            "security": {"NX": False, "PIE": False}
        }


def run(sc0pe_path, target_file, emit_report=False):
    allstrs = perform_strings(target_file)
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
        strings_lines=allstrs,
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
