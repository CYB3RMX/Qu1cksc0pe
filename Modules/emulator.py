#!/usr/bin/python3

import os
import re
import sys
import time
import math
import requests
import threading
from subprocess import Popen, PIPE, check_output

try:
    from qiling import *
except:
    print("Error: >qiling< module not found.")
    sys.exit(1)

try:
    import lief
except:
    print("Error: >lief< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import puremagic as pr
except:
    print("Error: >puremagic< module not found.")
    sys.exit(1)

try:
    import pefile as pf
except:
    print("Error: >pefile< module not found.")
    sys.exit(1)

try:
    from tqdm import tqdm
except:
    print("Module: >tqdm< not found.")
    sys.exit(1)

# Testing pyaxmlparser existence
try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Target file
targetFile = str(sys.argv[1])

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Disabling pyaxmlparser's logs
pyaxmlparser.core.log.disabled = True

# Initialize a dictionary to store the current state of the folders
previous_states = {
    "/files": {
        "contents": [],
        "changes": 0
    },
    "/shared_prefs": {
        "contents": [],
        "changes": 0
    },
    "/app_DynamicOptDex": {
        "contents": [],
        "changes": 0
    }
}

def RecursiveDirScan(targetDir):
    fnames = []
    for root, d_names, f_names in os.walk(targetDir):
        for ff in f_names:
            fnames.append(os.path.join(root, ff))
    return fnames

def Downloader(target_os, target_arch):
    local_database = f"{sc0pe_path}/Systems/{target_os}/{target_arch}_{target_os.lower()}.tar.gz"
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

def Archiver(archive_file, target_os):
    print(f"{infoS} Extracting rootfs archive...")
    os.chdir(f"{sc0pe_path}/Systems/{target_os}/")
    cmd = ["tar", "-xzf", f"{sc0pe_path}/Systems/{target_os}/{archive_file}"]
    cmdl = Popen(cmd, stdout=PIPE, stderr=PIPE)
    cmdl.wait()
    os.remove(f"{sc0pe_path}/Systems/{target_os}/{archive_file}")
    print(f"{infoS} Rootfs archive extracted.")

def DetectOS():
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

def InitQil(target_file, target_os, target_arch):
    print(f"{infoS} Emulating {target_arch} {target_os}...")
    print(f"\n{infoS} Preparing emulator...")
    ql = Qiling([target_file], f"{sc0pe_path}/Systems/{target_os}/{target_arch}_{target_os.lower()}/")
    print(f"\n{infoS} Executing emulator...")
    time.sleep(2)
    ql.run()

def SearchPackageName(package_name, device):
    print(f"{infoS} Searching for existing installation...")
    exist_install = check_output("adb shell pm list packages", shell=True).decode().split("\n")
    matchh = re.findall(rf"{package_name}", str(exist_install))
    if len(matchh) > 0:
        print(f"{infoS} Package found.")
        return True
    else:
        print(f"{infoS} Package not found.")
        return False

def ProgramTracer(package_name, device):
    print(f"{infoS} Now you can launch the app from your device. So you can see method class/calls etc.")
    temp_act = ""
    tmp_file = ""
    tmp_file2 = ""
    tmp_int = ""
    tmp_p = ""
    tmp_role = ""
    try:
        while True:
            logcat_output = check_output(["adb", "-s", f"{device}", "logcat", "-d", package_name + ":D"])
            payload = logcat_output.decode()

            # File calls for /data/user/0/
            f_calls = re.findall(r"(/data/user/0/{}[a-zA-Z0-9_\-/]+)".format(package_name), payload)
            if len(f_calls) != 0:
                if tmp_file != f_calls[-1]:
                    print(f"[bold red][FILE CALL] [bold green]{f_calls[-1]}")
                    tmp_file = f_calls[-1]

            # File calls for /data/data/
            f_calls = re.findall(r"(/data/data/{}[a-zA-Z0-9_\-/]+)".format(package_name), payload)
            if len(f_calls) != 0:
                if tmp_file2 != f_calls[-1]:
                    print(f"[bold red][FILE CALL] [bold green]{f_calls[-1]}")
                    tmp_file2 = f_calls[-1]

            # Intent calls
            i_calls = re.findall(r"android.intent.*", payload)
            if len(i_calls) != 0:
                if tmp_int != i_calls[-1]:
                    print(f"[bold yellow][INTENT CALL] [bold green]{i_calls[-1]}")
                    tmp_int = i_calls[-1]

            # Provider calls
            p_calls = re.findall(r"android.provider.*", payload)
            if len(p_calls) != 0:
                if tmp_p != p_calls[-1]:
                    print(f"[bold magenta][PROVIDER CALL] [bold green]{p_calls[-1]}")
                    tmp_p = p_calls[-1]

            # APP role calls
            a_calls = re.findall(r"android.app.role.*", payload)
            if len(a_calls) != 0:
                if tmp_role != a_calls[-1]:
                    print(f"[bold pink][APP ROLE CALL] [bold green]{a_calls[-1]}")
                    tmp_role = a_calls[-1]

            # Method calls
            m_calls = re.findall(r"ActivityManager:.*cmp={}/.*".format(package_name), payload)
            if len(m_calls) != 0:
                if temp_act != m_calls[-1]:
                    print(f"[bold blue][METHOD CALL] [bold green]{m_calls[-1]}")
                    temp_act = m_calls[-1]
            time.sleep(0.5)
    except:
        print(f"{infoS} Closing tracer...")
        sys.exit(0)

def Crawler1(target_directory):
    if os.path.exists(f"{sc0pe_path}/{target_directory}"):
        # Create a simple table for better view
        dirTable = Table(title=f"* {target_directory} Directory *", title_justify="center", title_style="bold magenta")
        dirTable.add_column("File Name", justify="center", style="bold green")
        dirTable.add_column("Type", justify="center", style="bold green")

        # Crawl the directory
        dircontent = RecursiveDirScan(f"{sc0pe_path}/{target_directory}")
        if dircontent != []:
            print(f"\n[bold cyan][INFO][white] Crawling [bold green]{target_directory} [white]directory.")
            for file in dircontent:
                # Checking file types using "file" command
                file_type = check_output(f"file {file}", shell=True).decode().split(":")[1].strip()
                dirTable.add_row(file.split(sc0pe_path)[1].split("//")[1], file_type)

            # Print the table
            print(dirTable)

def CrawlTargetApp(package_name, device):
    time.sleep(3)
    target_dirs = ["/files", "/shared_prefs", "/app_DynamicOptDex"]

    # First we need to fetch the directories
    for di in target_dirs:
        try:
            adb_output = check_output(["adb", "-s", f"{device}", "pull", f"/data/data/{package_name}{di}"])
            if "No such file" in adb_output.decode():
                continue
            else:
                # Get the current state of the folder
                current_state = os.listdir(os.path.join(f"{sc0pe_path}", di.replace("/", "")))
                if previous_states[di]['contents'] != current_state:
                    print(f"[bold cyan][INFO][white] {di} directory fetched.")
                    previous_states[di]['contents'] = current_state
                    previous_states[di]['changes'] += 1
                else:
                    previous_states[di]['changes'] = 0
        except:
            pass

    # Now we can crawl the directories
    for di in target_dirs:
        if previous_states[di]['changes'] != 0:
            Crawler1(di)

    # There is a recursion so we fetch these directories every time
    CrawlTargetApp(package_name, device)

def AnalyzeAPK(target_file):
    device_index = []
    apk = pyaxmlparser.APK(target_file)
    if apk.is_valid_APK():
        package_name = apk.get_package()
        print(f"[bold magenta]>>>[white] Package name: [bold green]{package_name}\n")
        # Gathering devices
        print(f"{infoS} Searching for devices...")
        get_dev_cmd = ["adb", "devices"]
        get_dev_cmdl = Popen(get_dev_cmd, stdout=PIPE, stderr=PIPE).communicate()
        get_dev_cmdl = str(get_dev_cmdl[0]).split("\\n")
        get_dev_cmdl = get_dev_cmdl[1:-1]
        dindex = 0
        for device in get_dev_cmdl:
            if device.split("\\t")[0] != "":
                device_index.append(
                    {
                        dindex: device.split("\\t")[0]
                    }
                )
                dindex += 1

        # Print devices
        if len(device_index) == 0:
            print(f"{errorS} No devices found. Try to connect a device and try again.\n{infoS} You can use [bold cyan]\"adb connect <device_ip>:<device_port>\"[white] to connect a device.")
            sys.exit(0)
        else:
            print(f"{infoS} Available devices:")
            for device in device_index:
                print(f"[bold magenta]>>>[white] [bold yellow]{list(device.keys())[0]} [white]| [bold green]{list(device.values())[0]}")

            # Select device
            dnum = int(input("\n>>> Select device: "))
            if dnum > len(device_index) - 1:
                print(f"{errorS} Invalid device number.")
                sys.exit(0)
            else:
                mbool = SearchPackageName(package_name, list(device_index[dnum].values())[0])
                if not mbool:
                    print(f"{infoS} Installing [bold yellow]{package_name} [white]on [bold yellow]{list(device_index[dnum].values())[0]}")
                    install_cmd = ["adb", "-s", f"{list(device_index[dnum].values())[0]}", "install", f"{target_file}"]
                    install_cmdl = Popen(install_cmd, stdout=PIPE, stderr=PIPE)
                    install_cmdl.wait()
                    if "Success" in str(install_cmdl.communicate()):
                        print(f"{infoS} [bold yellow]{package_name} [white]installed successfully.\n")
                        tracer_thread = threading.Thread(target=ProgramTracer, args=(package_name, list(device_index[dnum].values())[0],))
                        crawler_thread = threading.Thread(target=CrawlTargetApp, args=(package_name, list(device_index[dnum].values())[0],))
                        tracer_thread.start()
                        crawler_thread.start()
                        tracer_thread.join()
                        crawler_thread.join()
                    else:
                        print(f"{errorS} Installation failed.")
                        print(f"\n{infoS} Trying to uninstall the existing app...\n")
                        uninstall_cmd = ["adb", "-s", f"{list(device_index[dnum].values())[0]}", "uninstall", f"{package_name}"]
                        uninstall_cmdl = Popen(uninstall_cmd, stdout=PIPE, stderr=PIPE)
                        uninstall_cmdl.wait()
                        if "Success" in str(uninstall_cmdl.communicate()):
                            print(f"{infoS} [bold yellow]{package_name} [white]uninstalled successfully.")
                            AnalyzeAPK(target_file)
                else:
                    tracer_thread = threading.Thread(target=ProgramTracer, args=(package_name, list(device_index[dnum].values())[0],))
                    crawler_thread = threading.Thread(target=CrawlTargetApp, args=(package_name, list(device_index[dnum].values())[0],))
                    tracer_thread.start()
                    crawler_thread.start()
                    tracer_thread.join()
                    crawler_thread.join()

def Emulator():
    print(f"{infoS} Performing emulation of: [bold green]{targetFile}")
    target_os = DetectOS()
    print(f"{infoS} Target OS: [bold green]{target_os}")

    # ------Windows emulation side-------
    if target_os == "Windows":
        print(f"{infoS} Determining architecture of [bold green]{targetFile}")
        pe = pf.PE(targetFile)

        # Perform x86 emulation
        if hex(pe.FILE_HEADER.Machine) == "0x14c":
            try:
                print(f"{infoS} Detected [bold green]x86[white] architecture...")
                if os.path.exists(f"{sc0pe_path}/Systems/Windows/x86_windows/"):
                    InitQil(targetFile, "Windows", "x86")
                else:
                    print(f"\n{errorS} x86 Windows rootfs not found.")
                    print(f"{infoS} Downloading x86 Windows rootfs...")
                    Downloader("Windows", "x86")
                    Archiver("x86_windows.tar.gz", "Windows")
            except:
                print(f"{errorS} An error occurred while performing x86 emulation.")
                sys.exit(1)

        # Perform x64 emulation
        elif hex(pe.FILE_HEADER.Machine) == "0x8664":
            try:
                print(f"{infoS} Detected [bold green]x64[white] architecture...")
                if os.path.exists(f"{sc0pe_path}/Systems/Windows/x8664_windows/"):
                    InitQil(targetFile, "Windows", "x8664")
                else:
                    print(f"{errorS} x64 Windows rootfs not found.")
                    print(f"{infoS} Downloading x64 Windows rootfs...")
                    Downloader("Windows", "x8664")
                    Archiver("x8664_windows.tar.gz", "Windows")
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
                if os.path.exists(f"{sc0pe_path}/Systems/Linux/x8664_linux/"):
                    InitQil(targetFile, "Linux", "x8664")
                else:
                    print(f"\n{errorS} x86_64 Linux rootfs not found.")
                    print(f"{infoS} Downloading x86_64 Linux rootfs...")
                    Downloader("Linux", "x8664")
                    Archiver("x8664_linux.tar.gz", "Linux")
            except:
                print(f"{errorS} An error occurred while performing x86_64 emulation.")
                sys.exit(1)
    # ------Android emulation side-------
    elif target_os == "Android":
        AnalyzeAPK(targetFile)

    else:
        print(f"{errorS} Unsupported OS.")
        sys.exit(1)

# Execute
Emulator()