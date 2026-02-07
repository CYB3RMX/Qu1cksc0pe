import sys
import json
try:
    # When imported as `Modules.*`
    from ...utils.helpers import err_exit
except Exception:
    # When executed as a standalone module (sys.path[0] == ".../Modules")
    try:
        from utils.helpers import err_exit
    except Exception:
        # Last resort for some invocation contexts.
        from Modules.utils.helpers import err_exit

try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

#--------------------------------------------- Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

#--------------------------------------------- Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()
fileName = sys.argv[1]

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

CATEGORIES = {
    "Networking": [],
    "Cryptography": [],
    "Process": [],
    "File": [],
    "Memory Management": [],
    "Information Gathering": [],
    "System/Persistence": [],
    "Evasion": [],
    "Dll/Resource Handling": []
}

class GolangParser:
    def __init__(self, target_file_name):
        self._target_file_name = target_file_name
        self._golang_sections = []
        self._all_patterns = open("temp.txt", "r").read().split("\n")
        self._section_buffer = None
        self._pattern_categories = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}golang_categories.json"))

    def categorize_patterns(self):
        print(f"\n{infoS} Categorizing extracted patterns...")
        # Categorize patterns first
        for key in self._pattern_categories:
            for pattern in self._pattern_categories[key]["patterns"]:
                if pattern in self._all_patterns:
                    CATEGORIES[key].append(pattern)
                    self._pattern_categories[key]["occurence"] += 1

        # Write all categorized patterns
        for categ in CATEGORIES:
            if CATEGORIES[categ] != []:
                p_table = Table()
                p_table.add_column(f"Patterns about [bold green]{categ}", justify="center")
                for pattern in CATEGORIES[categ]:
                    p_table.add_row(pattern)
                print(p_table)

    def record_analysis_summary(self):
        return CATEGORIES

    def golang_analysis_main(self):
        self.categorize_patterns()
