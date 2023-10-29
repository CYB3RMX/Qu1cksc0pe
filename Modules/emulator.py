#!/usr/bin/python3

import os
import sys
import time
import math
import requests
import distutils.spawn
from subprocess import Popen, PIPE

try:
    from qiling import *
except ImportError:
    print("Error: >qiling< module not found.")
    sys.exit(1)

try:
    import lief
except ImportError:
    print("Error: >lief< module not found.")
    sys.exit(1)

try:
    from rich import print
except ImportError:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import puremagic as pr
except ImportError:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

try:
    import pefile as pf
except ImportError:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Module: >tqdm< not found.")
    sys.exit(1)

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Target file
targetFile = sys.argv[1]

# Get python binary
if distutils.spawn.find_executable("python3"):
    py_binary = "python3"
else:
    py_binary = "python"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

class DynamicAnalyzer:
    def detect_target_os(self):
        print(f"{infoS} Performing OS detection...")
        ftype = str(pr.magic_file(targetFile))
        if "Windows Executable" in ftype or ".msi" in ftype or ".dll" in ftype or ".exe" in ftype:
            return "Windows"
        elif "ELF" in ftype:
            return "Linux"
        elif "PK" in ftype and "Java archive" in ftype:
            return "Android"
        else:
            return "Unsupported OS"

    def env_downloader(self, target_os, target_arch):
        local_database = f"{sc0pe_path}{path_seperator}Systems{path_seperator}{target_os}{path_seperator}{target_arch}_{target_os.lower()}.tar.gz"
        dbUrl = f"https://media.githubusercontent.com/media/CYB3RMX/Emu-RootFS/main/{target_os}/{target_arch}_{target_os.lower()}.tar.gz"
        req = requests.get(dbUrl, stream=True)
        total_size = int(req.headers.get('content-length', 0))
        block_size = 1024
        wrote = 0
        print(f"\n{infoS} Downloading emulator environment please wait...")
        try:
            with open(local_database, 'wb') as ff:
                for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                    wrote = wrote + len(data)
                    ff.write(data)
        except:
            sys.exit(0)

    def archive_extractor(self, archive_file, target_os):
        print(f"{infoS} Extracting rootfs archive...")
        os.chdir(f"{sc0pe_path}{path_seperator}Systems{path_seperator}{target_os}{path_seperator}")
        cmd = ["tar", "-xzf", f"{sc0pe_path}{path_seperator}Systems{path_seperator}{target_os}{path_seperator}{archive_file}"]
        cmdl = Popen(cmd, stdout=PIPE, stderr=PIPE)
        cmdl.wait()
        os.remove(f"{sc0pe_path}{path_seperator}Systems{path_seperator}{target_os}{path_seperator}{archive_file}")
        print(f"{infoS} Rootfs archive extracted.")

    def init_qiling(self, target_file, target_os, target_arch):
        print(f"{infoS} Emulating {target_arch} {target_os}...")
        print(f"\n{infoS} Preparing emulator...")
        ql = Qiling([target_file], f"{sc0pe_path}{path_seperator}Systems{path_seperator}{target_os}{path_seperator}{target_arch}_{target_os.lower()}{path_seperator}")
        print(f"\n{infoS} Executing emulator...")
        time.sleep(2)
        ql.run()

    def emulator_main(self):
        print(f"{infoS} Performing emulation of: [bold green]{targetFile}")
        target_os = self.detect_target_os()
        print(f"{infoS} Target OS: [bold green]{target_os}")

        # ------Windows emulation side-------
        if target_os == "Windows":
            print(f"{infoS} Determining architecture of [bold green]{targetFile}")
            pe = pf.PE(targetFile)

            # Perform x86 emulation
            if hex(pe.FILE_HEADER.Machine) == "0x14c":
                try:
                    print(f"{infoS} Detected [bold green]x86[white] architecture...")
                    if os.path.exists(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}x86_windows{path_seperator}"):
                        self.init_qiling(targetFile, "Windows", "x86")
                    else:
                        print(f"\n{errorS} x86 Windows rootfs not found.")
                        print(f"{infoS} Downloading x86 Windows rootfs...")
                        self.env_downloader("Windows", "x86")
                        self.archive_extractor("x86_windows.tar.gz", "Windows")
                except:
                    print(f"{errorS} An error occurred while performing x86 emulation.")
                    sys.exit(1)

            # Perform x64 emulation
            elif hex(pe.FILE_HEADER.Machine) == "0x8664":
                try:
                    print(f"{infoS} Detected [bold green]x64[white] architecture...")
                    if os.path.exists(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}x8664_windows{path_seperator}"):
                        self.init_qiling(targetFile, "Windows", "x8664")
                    else:
                        print(f"{errorS} x64 Windows rootfs not found.")
                        print(f"{infoS} Downloading x64 Windows rootfs...")
                        self.env_downloader("Windows", "x8664")
                        self.archive_extractor("x8664_windows.tar.gz", "Windows")
                except:
                    print(f"{errorS} An error occurred while performing x64 emulation.")
                    sys.exit(1)
            else:
                print(f"{errorS} Unsupported architecture.")
                sys.exit(1)
        # ------Linux emulation side-------
        elif target_os == "Linux":
            print(f"{infoS} Determining architecture of [bold green]{targetFile}")
            ll = lief.parse(targetFile)
            if ll.header.machine_type.name == "x86_64":
                try:
                    print(f"{infoS} Detected [bold green]x86_64[white] architecture...")
                    if os.path.exists(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}x8664_linux{path_seperator}"):
                        self.init_qiling(targetFile, "Linux", "x8664")
                    else:
                        print(f"\n{errorS} x86_64 Linux rootfs not found.")
                        print(f"{infoS} Downloading x86_64 Linux rootfs...")
                        self.env_downloader("Linux", "x8664")
                        self.archive_extractor("x8664_linux.tar.gz", "Linux")
                except:
                    print(f"{errorS} An error occurred while performing x86_64 emulation.")
                    sys.exit(1)
        # ------Android emulation side-------
        elif target_os == "Android":
            command = f"{py_binary} {sc0pe_path}{path_seperator}Modules{path_seperator}android_dynamic_analyzer.py \"{targetFile}\""
            os.system(command)
        else:
            print(f"{errorS} Unsupported OS.")
            sys.exit(1)

# Execute
emulator = DynamicAnalyzer()
emulator.emulator_main()