#!/usr/bin/python3

import os
import sys

try:
    import exiftool
except:
    print("Error: >PyExifTool< module not found.")
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
green = Fore.LIGHTGREEN_EX
yellow = Fore.LIGHTYELLOW_EX
magenta = Fore.LIGHTMAGENTA_EX

# Legends
infoS = f"{cyan}[{red}*{cyan}]{white}"
foundS = f"{cyan}[{red}+{cyan}]{white}"
errorS = f"{cyan}[{red}!{cyan}]{white}"

def GetExif(mfile):
    print(f"{infoS} Extracting metadata from target file...\n")

    # Extracting metadata with exiftool
    with exiftool.ExifTool() as et:
        mdata = et.get_metadata(mfile)

    # Parsing metadata
    print(f"{infoS} Exif/Metadata information")
    for md in mdata:
        try:
            if "ExifTool" in md or "Error" in md:
                pass
            else:
                print(f"{magenta}>>>{white} {md.split(':')[1]}: {green}{mdata[md]}{white}")
        except:
            continue

# Execution zone
mfile = sys.argv[1]
if os.path.isfile(mfile):
    GetExif(mfile)
else:
    print(f"{errorS} Target file not found.")