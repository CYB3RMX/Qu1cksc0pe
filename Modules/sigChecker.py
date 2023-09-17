#!/usr/bin/python3

import os
import re
import sys
import json
import struct
import binascii

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    import lief
except:
    print("Error: >lief< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
    from rich.progress import track
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

class SignatureChecker:
    def __init__(self, target_file):
        self.target_file = target_file
        self.target_file_size = os.path.getsize(self.target_file)
        if self.target_file_size < 52428800:
            self.getbins = open(self.target_file, "rb")
            self.getbins_buffer = open(self.target_file, "rb").read()
        else:
            print(f"\n{infoS} Performing pumped file analysis against large file...")
            self.pumped_file_carver()

    def file_carver_for_windows_executables(self, offset_array):
        self.offset_array = offset_array

        for off in self.offset_array:
            self.getbins.seek(off) # Locating executable file offset
            try:
                data_to_trim = self.getbins.read()
                carve_size = self.parse_pe_size(data_to_trim)
                print(f"\n{infoS} Carving executable file found on offset: [bold green]{off}[white] | Size: [bold green]{carve_size}[white] bytes")
                pfile = pf.PE(data=data_to_trim) # Using pefile for PE trim
            except:
                continue

            # Creating dump files
            try:
                dumpfile = open(f"sc0pe_carved-{off}.bin", "wb")
                buffer_to_write = pfile.trim()
                dumpfile.write(buffer_to_write)
                dumpfile.close()
                pfile.close()
                print(f"[bold magenta]>>>[white] Data saved into: [bold green]sc0pe_carved-{off}.bin")
            except:
                continue

    def signature_checker(self):
        print(f"\n{infoS} Performing magic number analysis...")

        # Get file signatures
        fsigs = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}file_sigs.json"))

        # Create tables
        sigTable = Table()
        sigTable.add_column("File Type", justify="center")
        sigTable.add_column("Pattern", justify="center")
        sigTable.add_column("Offset", justify="center")

        # Lets scan!
        mz_offsets = []
        elf_offsets = []
        valid_pattern_switch = 0
        for categ in fsigs:
            for pattern in fsigs[categ]["patterns"]:
                try:
                    regex = re.finditer(binascii.unhexlify(pattern), self.getbins_buffer)
                    for position in regex:
                        # If there is an executable file warn user!
                        if "Executable File" in str(categ) and position.start() != 0:
                            sigTable.add_row(f"[bold red]{str(categ)}[white]", f"[bold green]{str(binascii.unhexlify(pattern))}", f"[bold red]{str(hex(position.start()))}[white]")
                        else:
                            sigTable.add_row(str(categ), f"[bold green]{str(binascii.unhexlify(pattern))}", str(hex(position.start())))

                        # Also check for executable file existence
                        if pattern == "4D5A9000" and position.start() != 0:
                            mz_offsets.append(position.start())
                        elif pattern == "7f454c4602010100" and position.start() != 0:
                            elf_offsets.append(position.start())
                        else:
                            pass
                        valid_pattern_switch += 1
                except:
                    continue
        if valid_pattern_switch == 0:
            print(f"{errorS} There is no valid pattern found!")
        else:
            print(sigTable)

        # Windows side
        if mz_offsets != []:
            choice = str(input(f"{infoC} Do you want to extract executable files from target file[Y/n]?: "))
            if choice == "Y" or choice == "y":
                self.file_carver_for_windows_executables(mz_offsets)

        # ELF side
        if elf_offsets != []:
            choice = str(input(f"{infoC} Do you want to extract executable files from target file[Y/n]?: "))
            if choice == "Y" or choice == "y":
                self.file_carver_for_elf_executables(elf_offsets)

    def search_possible_corrupt_mz_headers(self):
        print(f"\n{infoS} Looking for possible corrupted Windows executable patterns...")
        POSSIBLE_HEADER = "4D5A" # Possible because of false positives

        # Check for headers
        mz_offsets = []
        find = re.finditer(binascii.unhexlify(POSSIBLE_HEADER), self.getbins_buffer)
        for pos in find:
            if pos.start() % 512 == 0: # Check if the header is aligned
                mz_offsets.append(pos.start())

        # Check possible corrupted MZ headers
        corrupted = 0
        for offset in mz_offsets:
            if self.getbins_buffer[offset+2:offset+4] != b"\x90\x00":
                print(f"[bold magenta]>>>[white] Possible corrupted MZ header at: [bold green]{hex(offset)}[white]. Attempting to fix that!")
                new_buffer = self.getbins_buffer[:offset+2] + b"\x90\x00" + self.getbins_buffer[offset+4:]
                corrupted += 1

        if corrupted == 0:
            print(f"{errorS} There is no corrupted Windows executable pattern found!")
        else:
            with open("fixed_corrupted_headers.exe", "wb") as fx:
                fx.write(new_buffer)
            print(f"\n{infoS} Modified data saved into: [bold green]fixed_corrupted_headers.exe")

    def pumped_file_carver(self):
        print(f"{infoS} Performing executable file detection. Please wait...")
        pattern = b'\x4D\x5A\x90\x00'
        detected_executables = []
        with open(self.target_file, "rb") as target:
            for _ in track(range(0, self.target_file_size, 1024), description="Processing buffer..."):
                buffer_read = target.read(1024)
                matches = re.finditer(pattern, buffer_read)
                for mat in matches:
                    exec_offset = mat.start()
                    exec_size = self.parse_pe_size(buffer_read)
                    detected_executables.append([exec_offset, exec_size])
            if detected_executables != []:
                print(f"\n{infoS} Performing embedded binary extraction...")
                for binary in detected_executables:
                    print(f"\n{infoS} Carving executable file found on offset: [bold green]{binary[0]}[white] | Size: [bold green]{binary[1]}[white] bytes")
                    target.seek(binary[0])
                    binary_buffer_size = binary[1]
                    try:
                        pfile = pf.PE(data=target.read(binary_buffer_size))
                    except:
                        continue
                    # Creating dump files
                    try:
                        dumpfile = open(f"sc0pe_carved-{binary[0]}.bin", "wb")
                        buffer_to_write = pfile.trim()
                        if len(buffer_to_write) >= 52428800:
                            print(f"\n{infoS} Looks like the carved file is larger than 50MB. You need to re-execute program against the carved file!\n")
                        print(f"[bold magenta]>>>[white] Data saving into: [bold green]sc0pe_carved-{binary[0]}.bin[white] | Size: [bold green]{len(buffer_to_write)}[white]")
                        dumpfile.write(buffer_to_write)
                        dumpfile.close()
                        pfile.close()
                    except:
                        continue
            else:
                print(f"\n{errorS} There is nothing found to extract!\n")
        target.close()
        sys.exit(0)

    def parse_pe_size(self, pe_data):
        # Parse the PE header to retrieve the SizeOfImage field
        pe_header_offset = struct.unpack('<L', pe_data[0x3C:0x40])[0]
        size_of_image_offset = pe_header_offset + 0x50
        size_of_image = struct.unpack('<L', pe_data[size_of_image_offset:size_of_image_offset + 4])[0]
        return size_of_image

    def file_carver_for_elf_executables(self, offset_array):
        for ofs in offset_array:
            binary = lief.parse(self.getbins_buffer[ofs:])
            if binary is not None:
                with open(f"sc0pe_carved_ELF-{hex(ofs)}.bin", "wb") as ff:
                    ff.write(self.getbins_buffer[ofs:binary.eof_offset+ofs])
                print(f"[bold magenta]>>>[white] Data saved into: [bold green]sc0pe_carved_ELF-{hex(ofs)}.bin")

# Execution
target_file = sys.argv[1]
sig_check = SignatureChecker(target_file=target_file)
sig_check.signature_checker()
sig_check.search_possible_corrupt_mz_headers()