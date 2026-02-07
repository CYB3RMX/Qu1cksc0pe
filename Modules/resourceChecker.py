#!/usr/bin/python3

import os
import re
import sys
import subprocess
import binascii
import base64
import hashlib
from Crypto.Cipher import DES3

from utils.helpers import err_exit

# Testing pyaxmlparser existence
try:
    import pyaxmlparser
except:
    err_exit("Error: >pyaxmlparser< module not found.")

# Testing puremagic existence
try:
    import puremagic as pr
except:
    err_exit("Error: >puremagic< module not found.")

# Check for Pillow
try:
    from PIL import Image
except:
    err_exit("Error: >Pillow< module not found.")

# Testing rich existence
try:
    from rich import print
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Configurating strings parameter
if sys.platform == "darwin" or sys.platform == "win32":
    strings_param = "-a"
else:
    strings_param = "--all"

class ResourceScanner:
    def __init__(self, target_file):
        self.target_file = target_file

    def check_target_os(self):
        fileType = str(pr.magic_file(self.target_file))
        if "PK" in fileType and "Java archive" in fileType:
            print(f"{infoS} Target OS: [bold green]Android[white]\n")
            return "file_android"
        elif "Windows Executable" in fileType:
            print(f"{infoS} Target OS: [bold green]Windows[white]\n")
            return "file_windows"
        else:
            return None

    def android_resource_scanner(self):
        # Categories
        categs = {
            "Presence of Tor": [], "URLs": [], "IP Addresses": []
        }

        # Wordlists for analysis
        dictionary = {
            "Presence of Tor": [
                "obfs4",
                "iat-mode=",
                "meek_lite",
                "found_existing_tor_process",
                "newnym"
            ],
            "URLs": [
                r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
            ],
            "IP Addresses": [
                r'[0-9]+(?:\.[0-9]+){3}:[0-9]+',
                "localhost"
            ]
        }

        # Tables!!
        countTable = Table()
        countTable.add_column("File Type", justify="center")
        countTable.add_column("File Name", justify="center")    
        fileTable = Table()
        fileTable.add_column("Interesting Files", justify="center")

        # Lets begin!
        print(f"{infoS} Parsing file contents...\n")
        apk = pyaxmlparser.APK(self.target_file)

        # Try to find something juicy
        empty = {}
        ftypes = apk.get_files_types()
        for typ in ftypes:
            if ftypes[typ] not in empty.keys():
                empty.update({ftypes[typ]: []})
        for fl in ftypes:
            empty[ftypes[fl]].append(fl)

        # Count file types
        for fl in empty:
            if "image" in fl: # Just get rid of them
                pass
            elif "Dalvik" in fl or "C++ source" in fl or "C source" in fl or "ELF" in fl or "Bourne-Again shell" in fl or "executable" in fl or "JAR" in fl: # Worth to write on the table
                for fname in empty[fl]:
                    countTable.add_row(f"[bold red]{fl}", f"[bold red]{fname}")
            elif "data" in fl:
                for fname in empty[fl]:
                    countTable.add_row(f"[bold yellow]{fl}", f"[bold yellow]{fname}")
            else:
                for fname in empty[fl]:
                    countTable.add_row(str(fl), str(fname))
        print(countTable)

        # Finding .json .bin .dex files
        for fff in apk.get_files():
            if ".json" in fff:
                fileTable.add_row(f"[bold yellow]{fff}")
            elif ".dex" in fff:
                fileTable.add_row(f"[bold red]{fff}")
            elif ".bin" in fff:
                fileTable.add_row(f"[bold cyan]{fff}")
            elif ".sh" in fff:
                fileTable.add_row(f"[bold red]{fff}")
            else:
                pass
        print(fileTable)

        # Analyzing all files
        for key in empty:
            try:
                for kfile in empty[key]:
                    fcontent = apk.get_file(kfile)
                    for ddd in dictionary:
                        for regex in dictionary[ddd]:
                            matches = re.findall(regex, fcontent.decode())
                            if matches != []:
                                categs[ddd].append([matches[0], kfile])
            except:
                continue

        # Output
        counter = 0
        for key in categs:
            if categs[key] != []:
                resTable = Table(title=f"* {key} *", title_style="bold green", title_justify="center")
                resTable.add_column("Pattern", justify="center")
                resTable.add_column("File", justify="center")
                for elements in categs[key]:
                    resTable.add_row(f"[bold yellow]{elements[0]}", f"[bold cyan]{elements[1]}")
                print(resTable)
                counter += 1
        if counter == 0:
            print("\n[bold white on red]There is no interesting things found!\n")

    def windows_resource_scanner_strings_method(self, strings_type):
        self.strings_type = strings_type
        if self.strings_type == "16-bit":
            print(f"{infoS} Using Method 1: [bold yellow]Hidden PE signature scan via strings[white] ([bold green]16-bit[white])")
        else:
            print(f"{infoS} Using Method 1: [bold yellow]Hidden PE signature scan via strings[white]")

        # Scan strings and find potential embedded PE executables
        possible_patterns = {
            "method_1": {
                "patterns": [
                    r"4D!5A!90",
                    r"4D-5A-90O"
                ]
            },
            "method_2": {
                "patterns": [
                    r"4D5A9ZZZ"
                ]
            },
            "method_3": {
                "patterns": [
                    r"~~~9A5D4",
                    r"09~A5~D4"
                ]
            },
            "method_4": {
                "patterns": [
                    r"09}A5}D4",
                    r"WP09PA5PD4",
                    r"X-09-A5-D4",
                    r"ZZ-09-A5-D4",
                    r"\?3\?\?9A5D4"
                ]
            },
            "method_5": {
                "patterns": [
                    r"4D~5A~90O~"
                ]
            },
            "method_6": {
                "patterns": [
                    r"300009A5D4"
                ]
            },
            "method_7": {
                "patterns": [
                    r"ABjAHUAZABvAHIAUAABAAEAIgAAAAAAbABsAGQAL"
                ]
            },
            "method_8": {
                "patterns": [
                    r"4D5A9ZZZZ3"
                ]
            }
        }
        if self.strings_type == "16-bit":
            strings_data = subprocess.run(["strings", strings_param, "-e", "l", self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            strings_data = subprocess.run(["strings", strings_param, self.target_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        executable_buffer = ""
        for dat in strings_data.stdout.decode().split("\n"):
            for pat in possible_patterns: # Look for methods
                for mpat in possible_patterns[pat]["patterns"]:
                    matcc = re.findall(mpat, dat)
                    if matcc != []:
                        print(f"{infoS} Found potential embedded PE executable pattern: [bold green]{mpat}")
                        executable_buffer = dat
                        target_method = pat
                        target_pattern = mpat

        # After finding pattern and potential data we need to deobfuscate it
        if executable_buffer != "":
            print(f"{infoS} Attempting to deobfuscate PE file data. Please wait...")
            # Using method 1: Replace characters and split one character
            if target_method == "method_1":
                if target_pattern == r"4D!5A!90":
                    self.method_1_replace_split(r1="^", r2="!00", sp1="!", executable_buffer=executable_buffer)
                elif target_pattern == r"4D-5A-90O":
                    self.method_1_replace_split(r1="O", r2="-00", sp1='-', executable_buffer=executable_buffer)
                else:
                    pass

            # Using method 2: Double replace
            elif target_method == "method_2":
                if target_pattern == r"4D5A9ZZZ" and "YY" in executable_buffer:
                    self.method_2_double_replace(r1="ZZ", r2="0", r3="YY", r4="F", executable_buffer=executable_buffer)
                else:
                    pass

            # Using method 3: Reverse replace
            elif target_method == "method_3":
                if target_pattern == r"~~~9A5D4":
                    self.method_3_reverse_and_replace(r1="~", r2="0", executable_buffer=executable_buffer)
                elif target_pattern == r"09~A5~D4":
                    self.method_3_reverse_and_replace(r1="~", r2="", executable_buffer=executable_buffer)
                else:
                    pass

            # Using method 4: Reverse and double replace
            elif target_method == "method_4":
                if target_pattern == r"09}A5}D4":
                    self.method_4_reverse_and_double_replace(r1="Q", r2="00", r3="}", r4="", executable_buffer=executable_buffer)
                elif target_pattern == r"WP09PA5PD4":
                    self.method_4_reverse_and_double_replace(r1="W", r2="00", r3="P", r4="", executable_buffer=executable_buffer)
                elif target_pattern == r"X-09-A5-D4":
                    self.method_4_reverse_and_double_replace(r1="X", r2="00", r3="-", r4="", executable_buffer=executable_buffer)
                elif target_pattern == r"ZZ-09-A5-D4":
                    self.method_4_reverse_and_double_replace(r1="ZZ", r2="00", r3="-", r4="", executable_buffer=executable_buffer)
                elif target_pattern == r"\?3\?\?9A5D4":
                    self.method_4_reverse_and_double_replace(r1="--", r2="0", r3="?", r4="00", executable_buffer=executable_buffer)
                else:
                    pass

            # Using method 5: Triple replace
            elif target_method == "method_5":
                if target_pattern == r"4D~5A~90O~":
                    self.method_5_triple_replace(r1="O", r2="-00", r3="~", r4="-", r5="-", r6="", executable_buffer=executable_buffer)
                else:
                    pass
            # Using method 6: Simple reverse
            elif target_method == "method_6":
                if target_pattern == r"300009A5D4":
                    self.method_6_simple_reverse(executable_buffer=executable_buffer)
                else:
                    pass
            # Using method 7: Base64 and reverse
            elif target_method == "method_7":
                if target_pattern == r"ABjAHUAZABvAHIAUAABAAEAIgAAAAAAbABsAGQAL":
                    self.method_7_base64_and_reverse(executable_buffer=executable_buffer)
                else:
                    pass
            # Using method 8: Simple replace
            elif target_method == "method_8":
                if target_pattern == r"4D5A9ZZZZ3":
                    self.method_8_simple_replace(r1="ZZ", r2="00", executable_buffer=executable_buffer)
                else:
                    pass
            else:
                print(f"{errorS} There is no method implemented for that data type!")
        else:
            print(f"{errorS} There is no embedded PE executable pattern found!\n")

    def method_1_replace_split(self, r1, r2, sp1, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.sp1 = sp1 # Split character
        self.executable_buffer = executable_buffer

        # First replace and split characters
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2)
        executable_array = self.executable_buffer.split(self.sp1)

        # Second extract and sanitize data
        output_buffer = ""
        for buf in executable_array:
            output_buffer += buf

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=output_buffer)

        # Finally save data into file
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)
    def method_2_double_replace(self, r1, r2, r3, r4, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.r3 = r3 # Replace 3
        self.r4 = r4 # Replace 4
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2).replace(self.r3, self.r4)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Finally save data into file
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)
    def method_3_reverse_and_replace(self, r1, r2, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer[::-1].replace(self.r1, self.r2)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Finally save data into file
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)
    def method_4_reverse_and_double_replace(self, r1, r2, r3, r4, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.r3 = r3 # Replace 3
        self.r4 = r4 # Replace 4
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer[::-1].replace(self.r1, self.r2).replace(self.r3, self.r4)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Finally save data into file
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)
    def method_5_triple_replace(self, r1, r2, r3, r4, r5, r6, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.r3 = r3 # Replace 3
        self.r4 = r4 # Replace 4
        self.r5 = r5 # Replace 5
        self.r6 = r6 # Replace 6
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2).replace(self.r3, self.r4).replace(self.r5, self.r6)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Save data
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)
    def method_6_simple_reverse(self, executable_buffer):
        self.executable_buffer = executable_buffer

        # Deobfuscation
        revz = self.executable_buffer[::-1]

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=revz)

        # Save data
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)

    def method_7_base64_and_reverse(self, executable_buffer):
        self.executable_buffer = executable_buffer

        # Deobfuscation
        decode1 = base64.b64decode(self.executable_buffer)
        final_buffer = decode1[::-1]

        # Save data
        with open("qu1cksc0pe_carved_deobfuscated.exe", "wb") as ff:
            ff.write(final_buffer)
        print(f"{infoS} Data saved into: [bold green]qu1cksc0pe_carved_deobfuscated.exe[white]\n")

    def method_8_simple_replace(self, r1, r2, executable_buffer):
        self.r1 = r1 # Replace 1
        self.r2 = r2 # Replace 2
        self.executable_buffer = executable_buffer

        # Deobfuscation
        self.executable_buffer = self.executable_buffer.replace(self.r1, self.r2)

        # Data sanitization
        sanitized_data = self.buffer_sanitizer(executable_buffer=self.executable_buffer)

        # Save data
        self.save_data_into_file("qu1cksc0pe_carved_deobfuscated.exe", sanitized_data)

    def buffer_sanitizer(self, executable_buffer):
        self.executable_buffer = executable_buffer

        # Unwanted characters
        unwanted = ['@', '\t', '\n']
        for uc in unwanted:
            if uc in self.executable_buffer:
                self.executable_buffer = self.executable_buffer.replace(uc, "")

        return self.executable_buffer
    def windows_resource_scanner_split_data_carver_method(self):
        print(f"{infoS} Using Method 2: [bold yellow]Detecting and merging split data[white]")
        # Signature information we needed
        resource_sigs = {
            "Quartz": {
                "signature_start": "74656d61",
                "signature_end": "905a4d",
                "additional_bytes": 3,
                "offset_start": [],
                "offset_end": []
            },
            "Versa": {
                "signature_start": "65725078",
                "signature_end": "f8afcfc0",
                "additional_bytes": 4,
                "offset_start": [],
                "offset_end": []
            },
            "Zinc": {
                "signature_start": "abf4dbbf",
                "signature_end": "abf4dbbf",
                "additional_bytes": 0,
                "offset_start": [],
                "offset_end": []
            },
            "Zar": {
                "signature_start": "4d5a90",
                "signature_end": "4d5a90",
                "additional_bytes": 0,
                "offset_start": [],
                "offset_end": []
            },
            "Yar": {
                "signature_start": "051f6d91208e",
                "signature_end": "01ff35f8",
                "additional_bytes": 4,
                "offset_start": [],
                "offset_end": []
            },
            "Xar": {
                "signature_start": "f7934c0931",
                "signature_end": "f7934c0931",
                "additional_bytes": 0,
                "offset_start": [],
                "offset_end": []
            }
        }

        # We need target executable buffer and file handler
        target_executable_buffer = open(self.target_file, "rb").read()
        target_file_handler = open(self.target_file, "rb")

        # Switch
        founder_switch = 0

        # Locate start offsets
        print(f"{infoS} Locating start offsets...")
        for rs in resource_sigs:
            find = re.finditer(binascii.unhexlify(resource_sigs[rs]["signature_start"]), target_executable_buffer)
            for pos in find:
                if pos.start() != 0: # If there is another MZ pattern
                    resource_sigs[rs]["offset_start"].append(pos.start())
                    founder_switch += 1
        # Locate end offsets
        print(f"{infoS} Locating end offsets...")
        for rs in resource_sigs:
            find = re.finditer(binascii.unhexlify(resource_sigs[rs]["signature_end"]), target_executable_buffer)
            for pos in find:
                if pos.start() != 0:
                    resource_sigs[rs]["offset_end"].append(pos.start())
                    founder_switch += 1

        # Okay now we need to retrieve all data for deobfuscation
        if founder_switch != 0:
            print(f"{infoS} Deobfuscating split data. Please wait...")
            output_buffer = b""
            for rf in resource_sigs:
                if resource_sigs[rf]["offset_start"] != [] and resource_sigs[rf]["offset_end"] != []:
                    if len(resource_sigs[rf]["offset_start"]) == len(resource_sigs[rf]["offset_end"]):
                        for ofst, ofnd in zip(resource_sigs[rf]["offset_start"], resource_sigs[rf]["offset_end"]):
                            temporary_buffer = self.file_carver_for_method_2(
                                file_handler=target_file_handler,
                                start_offset=ofst,
                                end_offset=ofnd,
                                additional_bytes=resource_sigs[rf]["additional_bytes"],
                                partition_name=rf
                            )
                            if rf == "Quartz":
                                # Now first we need to convert this data to "bytearray" and reverse it
                                byte_array = bytearray(temporary_buffer)
                                byte_array.reverse()
                                output_buffer += binascii.hexlify(byte_array)
                            else:
                                byte_array = bytearray(temporary_buffer)
                                output_buffer += binascii.hexlify(byte_array)

            # After retrieve and obfuscate all data we need to save it!
            self.save_data_into_file("qu1cksc0pe_carved_deobfuscated_split.exe", output_buffer)
        else:
            print(f"{errorS} There is no split data found!\n")

    def file_carver_for_method_2(self, file_handler, start_offset, end_offset, additional_bytes, partition_name):
        self.file_handler = file_handler
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.additional_bytes = additional_bytes
        self.partition_name = partition_name

        # Seek start offset
        self.file_handler.seek(self.start_offset)

        # Calculating data size and carving
        if self.partition_name == "Zinc":
            data_size = 8876 # Fixed size
            carved_data = self.file_handler.read(data_size)
        elif self.partition_name == "Zar":
            data_size = 18090 # Fixed size
            carved_data = self.file_handler.read(data_size)
        elif self.partition_name == "Xar":
            data_size = 18092 # Fixed size
            carved_data = self.file_handler.read(data_size)
        else:
            data_size = self.end_offset - self.start_offset
            carved_data = self.file_handler.read(data_size+self.additional_bytes)

        # Return carved data for deobfuscation phase
        return carved_data
    def windows_resource_scanner_bitmap_carver_method(self):
        print(f"{infoS} Using Method 3: [bold yellow]Extract PE file from Bitmap data[white]")
        # We need target executable buffer and file handler
        target_executable_buffer = open(self.target_file, "rb").read()
        target_file_handler = open(self.target_file, "rb")

        # Locate Bitmap headers
        offsets = []
        loc = re.finditer(r"BM".encode(), target_executable_buffer)
        for pos in loc:
            if pos.start() != 0:
                offsets.append(pos.start())
        valid_offsets = {}
        for of in offsets:
            target_file_handler.seek(of)
            bitmap_header = binascii.hexlify(target_file_handler.read(8))
            if b"424d" in bitmap_header and b"0000" in bitmap_header:
                valid_offsets.update({of: bitmap_header})

        # Calculate size of file
        if valid_offsets != {}:
            for offset in valid_offsets:
                try:
                    pattern = bytes.fromhex(valid_offsets[offset][4:12].decode())
                    reverz = pattern[::-1] # Little endian stuff
                    size_of_file = int(binascii.hexlify(reverz), 16) # Convert to decimal
                    print(f"{infoS} Found a valid Bitmap file on: [bold green]{hex(offset)}[white] | Size: [bold magenta]{size_of_file}")
                    print(f"{infoS} Performing extraction. Please wait...")
                    data_carve = target_executable_buffer[offset:offset+size_of_file]
                    with open("carved.bmp", "wb") as ff:
                        ff.write(data_carve)
                    if os.path.exists("carved.bmp"):
                        print(f"{infoS} Extraction was successful. Performing PE extraction...")
                        img = Image.open("carved.bmp")
                        self.bitmap_carver_1(image_handler=img) # Testing for technique 1
                        self.bitmap_carver_2(image_handler=img) # Testing for technique 2
                    else:
                        err_exit(f"{errorS} An error occured while extracting Bitmap file!!\n")
                except:
                    continue
        else:
            print(f"{errorS} There is no valid Bitmap file pattern found!\n")

    def bitmap_carver_1(self, image_handler):
        if os.path.exists("carved.bmp"):
            b_array = bytearray()
            for x in range(image_handler.width):
                for y in range(image_handler.height):
                    red = image_handler.getpixel((x, y))[0]
                    b_array.append(red)
            if b"4d5a90" in binascii.hexlify(b_array):
                print(f"{infoS} Hidden PE file found. Extracting...")
                with open("qu1cksc0pe_hidden_pe.exe", "wb") as ff:
                    ff.write(b_array)
                print(f"{infoS} Data saved into: [bold green]qu1cksc0pe_hidden_pe.exe[white]\n")
                os.system("rm -rf carved.bmp")
            else:
                pass
    def bitmap_carver_2(self, image_handler):
        if os.path.exists("carved.bmp"):
            width, height = image_handler.size
            b_array = bytearray(width  * height)
            i = 0
            for x in range(width):
                for y in range(height):
                    pixel = image_handler.getpixel((x, y))
                    red = pixel[2]
                    b_array[i] = red
                    i += 1
            if b"4d5a90" in binascii.hexlify(b_array):
                print(f"{infoS} Hidden PE file found. Extracting...")
                with open("qu1cksc0pe_hidden_pe.exe", "wb") as ff:
                    ff.write(b_array)
                print(f"{infoS} Data saved into: [bold green]qu1cksc0pe_hidden_pe.exe[white]\n")
                os.system("rm -rf carved.bmp")
            else:
                pass

    def windows_resource_scanner_locate_encrypted(self):
        print(f"{infoS} Using Method 4: [bold yellow]Locate and decrypt hidden PE file[white]")
        # We need target executable buffer and file handler
        target_executable_buffer = open(self.target_file, "rb").read()
        target_file_handler = open(self.target_file, "rb")

        # Signatures
        encrypted_sigs = {
            "Bvdohovalgmkvczfebimk": {
                "signature_start": "d6278ed277bfe2fcb77ee67c0eb03dde",
                "size_of_data": 2220040,
                "key_to_decrypt": "Oaxvkmfiubpynfqupmzypmbr",
                "additional_bytes": 1740
            }
        }

        # Iterate and decrypt
        founz = 0
        for artifact in encrypted_sigs:
            offsets = []
            matchs = re.finditer(binascii.unhexlify(encrypted_sigs[artifact]["signature_start"]), target_executable_buffer)
            for mm in matchs:
                offsets.append(mm.start())
            if offsets != []:
                founz += 1
                print(f"{infoS} Carving encrypted resource on: [bold green]{hex(offsets[0])}[white] | Size: [bold green]{encrypted_sigs[artifact]['size_of_data']}")
                carve_data = target_executable_buffer[offsets[0]:encrypted_sigs[artifact]["size_of_data"]+encrypted_sigs[artifact]["additional_bytes"]]
                print(f"{infoS} Performing decryption...")
                key = hashlib.md5(encrypted_sigs[artifact]["key_to_decrypt"].encode('utf-8')).digest()
                barr = bytearray(carve_data)
                cipher = DES3.new(key, DES3.MODE_ECB)
                decr = cipher.decrypt(barr)
                with open(f"qu1cksc0pe_carved_decrypted-{hex(offsets[0])}.exe", "wb") as ff:
                    ff.write(decr)
                print(f"{infoS} Data saved into: [bold green]qu1cksc0pe_carved_decrypted-{hex(offsets[0])}.exe[white]\n")
        if founz == 0:
            print(f"{errorS} There is no encrypted PE pattern found!\n")

    def save_data_into_file(self, output_name, save_buffer):
        self.output_name = output_name
        self.save_buffer = save_buffer

        with open(self.output_name, "wb") as cf:
            cf.write(binascii.unhexlify(self.save_buffer))
        print(f"{infoS} Data saved into: [bold green]{self.output_name}[white]\n")

# Execution zone
targFile = sys.argv[1]
resource_scan = ResourceScanner(targFile)
if os.path.isfile(targFile):
    ostype = resource_scan.check_target_os()
    if ostype == "file_android":
        resource_scan.android_resource_scanner()
    elif ostype == "file_windows":
        resource_scan.windows_resource_scanner_strings_method(strings_type="normal")
        if sys.platform != "win32":
            resource_scan.windows_resource_scanner_strings_method(strings_type="16-bit")
        resource_scan.windows_resource_scanner_split_data_carver_method()
        resource_scan.windows_resource_scanner_bitmap_carver_method()
        resource_scan.windows_resource_scanner_locate_encrypted()
    else:
        print("\n[bold white on red]Target OS couldn\'t detected!\n")
else:
    print("\n[bold white on red]Target file not found!\n")