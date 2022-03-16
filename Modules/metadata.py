#!/usr/bin/python3

import os
import sys

try:
    import exiftool
except:
    print("Error: >PyExifTool< module not found.")
    sys.exit(1)

try:
    from rich import print
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

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
                print(f"[magenta]>>>[white] {md.split(':')[1]}: [green][i]{mdata[md]}[/i]")
        except:
            continue

# Execution zone
mfile = sys.argv[1]
if os.path.isfile(mfile):
    GetExif(mfile)
else:
    print("[blink bold white on red]Target file not found!")