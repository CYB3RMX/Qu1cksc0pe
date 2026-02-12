#!/usr/bin/python3

import os
import re
import sys
import json

from utils.helpers import err_exit, get_argv, save_report

try:
    from wh1tem0cha import Wh1teM0cha
except Exception:
    err_exit("Error: >wh1tem0cha< module not found.")

try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< module not found.")

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Sc0pe path
try:
    sc0pe_path = open(".path_handler", "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

_CATEGORY_TEMPLATE = {
    "Networking/Web": [],
    "Cryptography/SSL Handling": [],
    "Information Gathering": [],
    "Memory Management": [],
    "Process/Execution": []
}


def _to_text(v):
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore")
        except Exception:
            return str(v)
    return str(v)


class AppleAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        with open(self.target_file, "rb") as f:
            self._target_binary_buff = f.read()
        self.wmocha_object = None
        self.categ_patterns = {k: [] for k in _CATEGORY_TEMPLATE}
        self.report = {
            "filename": self.target_file,
            "analysis_type": "OSX",
            "target_os": "OSX",
            "target_type": "",
            "binary_info": {},
            "segments": [],
            "sections": [],
            "dynamic_libraries": [],
            "categorized_patterns": {},
            "statistics": {
                "category_pattern_counts": {}
            },
            "errors": [],
        }

    def _check_ipa_file(self):
        # Most common IPA package markers.
        markers = (b"Payload/", b"META-INF/", b".plist")
        occurence = sum(1 for marker in markers if marker in self._target_binary_buff)
        return occurence > 0

    def _check_macho_binary(self):
        # Check MACH-O pattern using wh1tem0cha
        wm = Wh1teM0cha(self.target_file)
        try:
            wm.get_binary_info()
            self.wmocha_object = wm
            return True
        except Exception:
            return False

    def check_target_type(self):
        # This method is for checking if the target file is .ipa or .macho
        if self._check_macho_binary():
            self.report["target_type"] = "mach-o"
            self.analyze_macho_binary()
        elif self._check_ipa_file():
            self.report["target_type"] = "ipa"
            print(f"{infoS} This feature will release coming soon!")
            self.report["errors"].append("ipa_analysis_not_implemented")
        else:
            print(f"{errorS} Unknown file type!")
            self.report["target_type"] = "unknown"
            self.report["errors"].append("unknown_file_type")

    def parse_libraries(self):
        library_dict = self.wmocha_object.get_dylib_names() or []
        parsed = []
        if library_dict:
            ltable = Table()
            ltable.add_column("[bold green]Dynamic Libraries", justify="center")
            for lib in library_dict:
                lib_name = _to_text(lib.get("libname", ""))
                parsed.append(lib_name)
                if "/Security" in lib_name or "/libresolv" in lib_name or "/libSystem" in lib_name:
                    ltable.add_row(f"[bold red]{lib_name} (Possible malicious purposes!)[white]")
                else:
                    ltable.add_row(lib_name)
            print(ltable)
        return parsed

    def _perform_pattern_analysis(self):
        osx_patterns = json.load(
            open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}OSX{path_seperator}osx_sym_categories.json")
        )
        for key in osx_patterns:
            if key not in self.categ_patterns:
                self.categ_patterns[key] = []
            for pattern in osx_patterns[key].get("patterns", []):
                try:
                    hit = re.findall(str(pattern).encode(), self._target_binary_buff)
                except Exception:
                    hit = []
                if hit:
                    osx_patterns[key]["occurence"] = int(osx_patterns[key].get("occurence", 0)) + 1
                    if pattern not in self.categ_patterns[key]:
                        self.categ_patterns[key].append(pattern)
        self._categ_parser()
        self._print_statistics()
        self.report["categorized_patterns"] = {k: v for k, v in self.categ_patterns.items() if v}

    def _categ_parser(self):
        for key in self.categ_patterns:
            if self.categ_patterns[key]:
                ctable = Table()
                ctable.add_column(f"Patterns about [bold green]{key}", justify="center")
                for pattern in self.categ_patterns[key]:
                    ctable.add_row(f"[bold red]{pattern}")
                print(ctable)

    def _print_statistics(self):
        statistics = Table()
        print(f"\n[bold green]->[white] Statistics for: [bold green][i]{self.target_file}[/i]")
        statistics.add_column("Categories", justify="center")
        statistics.add_column("Number of Patterns", justify="center")
        category_counts = {}
        for key in self.categ_patterns:
            if self.categ_patterns[key]:
                category_counts[key] = len(self.categ_patterns[key])
                if key == "Cryptography" or key == "Information Gathering":
                    statistics.add_row(f"[bold yellow]{key}", f"[bold red]{len(self.categ_patterns[key])}")
                else:
                    statistics.add_row(key, str(len(self.categ_patterns[key])))
        self.report["statistics"]["category_pattern_counts"] = category_counts
        print(statistics)

    def analyze_macho_binary(self):
        # Print binary info first
        print(f"{infoS} Binary Information")
        binary_info = self.wmocha_object.get_binary_info() or {}
        bin_info_out = {}
        for key in binary_info:
            value = _to_text(binary_info[key])
            bin_info_out[str(key)] = value
            print(f"[bold magenta]>>>>[white] {key}: [bold green]{value}")
        self.report["binary_info"] = bin_info_out

        # Parse segment information
        print(f"\n{infoS} Parsing segment information...")
        seg_table = Table()
        seg_table.add_column("[bold green]name", justify="center")
        seg_table.add_column("[bold green]offset", justify="center")
        seg_table.add_column("[bold green]cmd", justify="center")
        seg_table.add_column("[bold green]cmdsize", justify="center")
        seg_table.add_column("[bold green]vmaddr", justify="center")
        seg_table.add_column("[bold green]vmsize", justify="center")
        seg_table.add_column("[bold green]filesize", justify="center")
        segments = self.wmocha_object.get_segments() or []
        seg_report = []
        for seg in segments:
            seg_name = _to_text(seg.get("segment_name", ""))
            try:
                seg_inf = self.wmocha_object.segment_info(seg_name)
            except Exception as exc:
                self.report["errors"].append(f"segment_info_error:{seg_name}:{exc}")
                continue

            row = {
                "name": seg_name,
                "offset": _to_text(seg_inf.get("offset", "")),
                "cmd": _to_text(seg_inf.get("cmd", "")),
                "cmdsize": _to_text(seg_inf.get("cmdsize", "")),
                "vmaddr": _to_text(seg_inf.get("vmaddr", "")),
                "vmsize": _to_text(seg_inf.get("vmsize", "")),
                "filesize": _to_text(seg_inf.get("filesize", "")),
            }
            seg_report.append(row)
            seg_table.add_row(
                row["name"],
                row["offset"],
                row["cmd"],
                row["cmdsize"],
                row["vmaddr"],
                row["vmsize"],
                row["filesize"],
            )
        self.report["segments"] = seg_report
        print(seg_table)

        # Parsing sections
        print(f"\n{infoS} Analyzing sections...")
        sec_table = Table()
        sec_table.add_column("[bold green]name", justify="center")
        sec_table.add_column("[bold green]segment", justify="center")
        sec_table.add_column("[bold green]offset", justify="center")
        sec_table.add_column("[bold green]size", justify="center")
        sections = self.wmocha_object.get_sections() or []
        sec_report = []
        for sec in sections:
            sec_name = _to_text(sec.get("section_name", ""))
            try:
                sec_inf = self.wmocha_object.section_info(sec_name)
                segment_name = _to_text(sec_inf.get("segment_name", ""))
                offset = _to_text(sec_inf.get("offset", ""))
                size = _to_text(sec_inf.get("size", ""))
                sec_report.append(
                    {
                        "name": sec_name,
                        "segment": segment_name,
                        "offset": offset,
                        "size": size,
                    }
                )
                if "__gosymtab" in sec_name or "__gopclntab" in sec_name or "__go_buildinfo" in sec_name:
                    sec_table.add_row(f"[bold red]{sec_name}[white]", segment_name, offset, size)
                else:
                    sec_table.add_row(sec_name, segment_name, offset, size)
            except Exception:
                continue
        self.report["sections"] = sec_report
        print(sec_table)

        # Analyze libraries
        print(f"\n{infoS} Analyzing libraries...")
        self.report["dynamic_libraries"] = self.parse_libraries()

        # Pattern scanner
        print(f"\n{infoS} Performing pattern scan...")
        self._perform_pattern_analysis()


def main():
    if len(sys.argv) < 2:
        err_exit("Usage: apple_analyzer.py <file> [save_report=True|False]")

    target_file = sys.argv[1]
    apa = AppleAnalyzer(target_file=target_file)
    apa.check_target_type()
    if get_argv(2) == "True":
        save_report("osx", apa.report)


if __name__ == "__main__":
    main()
