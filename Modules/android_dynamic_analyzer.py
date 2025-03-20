#!/usr/bin/python3

import re
import os
import sys
import json
import shutil
import asyncio
import subprocess
from utils import err_exit
from utils import chk_wlist
from utils import recursive_dir_scan
from utils import update_table

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
except:
    err_exit("Error: >rich< module not found.")

try:
    import frida
except:
    err_exit("Error: >frida< module not found.")

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    from prompt_toolkit.completion import WordCompleter
except:
    err_exit("Error: >prompt_toolkit< module not found.")

try:
    from colorama import Fore, Style
except ModuleNotFoundError as e:
    print("Error: >colorama< module not found.")
    raise e

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Compatibility
path_seperator = "/"
adb_path = shutil.which("adb")
downloader = "wget"
if sys.platform == "win32":
    path_seperator = "\\"
    # Get adb path for windows
    adb_conf = configparser.ConfigParser()
    adb_conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf")
    adb_path = adb_conf["ADB_PATH"]["win_adb_path"]

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Path completer object
path_completer = PathCompleter()

# Initialize a dictionary to store the current state of the folders
previous_states = {
    "files": {
        "contents": [],
        "changes": 0
    },
    "shared_prefs": {
        "contents": [],
        "changes": 0
    },
    "app_DynamicOptDex": {
        "contents": [],
        "changes": 0
    },
    "cache": {
        "contents": [],
        "changes": 0
    },
    "app_apk": {
        "contents": [],
        "changes": 0
    },
    "code_cache": {
        "contents": [],
        "changes": 0
    }
}

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}detections.json"))

# Report
report = {
    "extracted_urls": [],
    "application_files": [],
    "logcat_outputs": {
        "file": [],
        "intent": [],
        "provider": [],
        "app_role": [],
        "method": []
    }
}

class AndroidDynamicAnalyzer:
    def __init__(self, target_file, is_installed):
        self.target_file = target_file
        self.is_installed = is_installed
        self.device = None
        self.target_package = None
        self.target_appname = None
        self.frida_version = frida.__version__
        self.device_arch = None
        self.frida_script = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}FridaScripts{path_seperator}sc0pe_android_enumeration.js", "r").read()
        self.PERMS = "rw-"
        self.MAX_SIZE = 20971520
        self.target_acquired = False
        self.device_frida = None

    # ----- These functions are for preparing all stuff before the dynamic execution -----
    #   ----- ADB side -----
    def enumerate_adb_devices(self):
        print(f"{infoS} Enumerating ADB devices...")
        devices = subprocess.run(f"{adb_path} devices", shell=True, stdout=subprocess.PIPE).stdout
        if len(devices) > 26:
            select_devices = []
            d_table = Table()
            d_table.add_column("[bold green]Devices", justify="center")
            for dev in devices.split(b"\n"):
                if b"\t" in dev:
                    if "\tdevice" in dev.decode():
                        d_table.add_row(dev.decode().split("\t")[0])
                        select_devices.append(dev.decode().split("\t")[0])
            print(d_table)
            dev_completer = WordCompleter(select_devices)
            self.device = prompt(">>> Enter Target Device [Press TAB to auto-complete]: ", completer=dev_completer)
        else:
            print(f"{errorS} There is no android device found. You should check your ADB connections!")
            sys.exit(1)

    #   ----- FRIDA side -----
    def check_frida_existence(self):
        chk = subprocess.run(f"{adb_path} -s {self.device} shell ls /data/local/tmp", shell=True, stdout=subprocess.PIPE).stdout.decode()
        if "frida-server" in chk:
            return True
        else:
            return False
    def install_setup_frida(self):
        print(f"{infoS} Frida server not found! Installing it for you...")
        self.device_arch = subprocess.run(f"{adb_path} -s {self.device} shell getprop ro.product.cpu.abi", shell=True, stdout=subprocess.PIPE).stdout.decode().strip("\n")
        if "arm" in self.device_arch:
            self.device_arch = "arm" # Handling arm based systems

        # Download and setup the server
        print(f"{infoS} Downloading: [bold green]frida-server-{self.frida_version}-android-{self.device_arch}.xz")
        proc = subprocess.run(f"{downloader} -q https://github.com/frida/frida/releases/download/{self.frida_version}/frida-server-{self.frida_version}-android-{self.device_arch}.xz", shell=True)
        if proc.returncode == 0:
            print(f"{infoS} Installing FRIDA server to: [bold green]{self.device}")
            _ = subprocess.run(f"unxz frida-server-{self.frida_version}-android-{self.device_arch}.xz", shell=True)
            _ = subprocess.run(f"{adb_path} -s {self.device} push frida-server-{self.frida_version}-android-{self.device_arch} /data/local/tmp", shell=True)
            _ = subprocess.run(f"{adb_path} -s {self.device} shell chmod +x /data/local/tmp/frida-server-{self.frida_version}-android-{self.device_arch}", shell=True)
            _ = subprocess.run(f"{adb_path} -s {self.device} shell /data/local/tmp/frida-server-{self.frida_version}-android-{self.device_arch} &", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            print(f"{infoS} Frida server is ready!")
    def bootup_frida_server(self):
        self.device_arch = subprocess.run(f"{adb_path} -s {self.device} shell getprop ro.product.cpu.abi", shell=True, stdout=subprocess.PIPE).stdout.decode().strip("\n")
        if "arm" in self.device_arch:
            self.device_arch = "arm" # Handling arm based systems

        _ = subprocess.run(f"{adb_path} -s {self.device} shell /data/local/tmp/frida-server-{self.frida_version}-android-{self.device_arch} &", shell=True)
        cf = subprocess.run("adb shell netstat -antp", shell=True, stdout=subprocess.PIPE).stdout
        if b"frida-server" in cf:
            return True
        else:
            return True
    def create_frida_session(self):
        try:
            process_id = self.get_process_id(self.device_frida)
            frida_session = frida.get_usb_device().attach(process_id)
            return frida_session
        except:
            return None
    def get_process_id(self, device_object):
        for procs in device_object.enumerate_processes():
            if procs.name == self.target_package or procs.name == self.target_appname:
                return int(procs.pid)
        return None

    #   ----- Target application side -----
    def install_target_application(self):
        print(f"\n{infoS} Installing target app to: [bold green]{self.device}")
        out = subprocess.run(f"{adb_path} -s {self.device} install {self.target_file}", shell=True, stdout=subprocess.PIPE).stdout
        if b"Success" in out:
            return True
        else:
            return False
    def enumerate_packages_and_select(self):
        print(f"\n{infoS} Enumerating user installed packages...")
        packages = subprocess.run(f"{adb_path} -s {self.device} shell pm list packages -3", shell=True, stdout=subprocess.PIPE).stdout
        p_array = []
        p_table = Table()
        p_table.add_column("[bold green]Package List", justify="center")
        for pack in packages.replace(b"package:", b"").split(b"\n"):
            if pack != b"":
                p_array.append(pack.decode())
                p_table.add_row(pack.decode())
        print(p_table)
        package_completer = WordCompleter(p_array)
        self.target_package = prompt(">>> Enter Target Package [Press TAB to auto-complete]: ", completer=package_completer)
    def get_target_app_name(self):
        if self.device_frida:
            for app in self.device_frida.enumerate_applications():
                if app.identifier == self.target_package:
                    self.target_appname = app.name
                    break

    def preparation_phase_main(self):
        # Check devices
        self.enumerate_adb_devices()

        # Check frida server existence
        if not self.check_frida_existence():
            self.install_setup_frida()
        else:
            self.bootup_frida_server()

        # Install target package and select it
        if not self.is_installed:
            self.install_target_application()
        self.enumerate_packages_and_select()

        # Remove old memory dump file
        if self.target_package and os.path.exists(f"mem_dump-{self.target_package}.dmp"):
            os.remove(f"mem_dump-{self.target_package}.dmp")

        # Create frida session
        device_manager = frida.enumerate_devices()
        self.device_frida = device_manager[-1]

        # Get target appname
        self.get_target_app_name()
        print(f"{infoS} For detailed information please check: [bold green]sc0pe_android-{self.target_package}.json[white]")
        print(f"{infoS} Monitoring: [bold green]{self.target_package}[white]. ([bold yellow][blink]Ctrl+C to stop![/blink][white])")

    # ----- These functions are for actual dynamic execution processes -----
    # ----- Logcat Parser -----
    async def logcat_parser(self, table_object):
        last_activity_log = ""
        last_file_user_log = ""
        last_file_data_log = ""
        last_intent_log = ""
        last_provider_log = ""
        last_approle_log = ""
        callstack = 0
        while True:
            try:
                logcat_output = subprocess.check_output([f"{adb_path}", "-s", f"{self.device}", "logcat", "-d", self.target_package + ":D"])
                payload = logcat_output.decode()

                # File calls: /data/user/0/
                f_calls = re.findall(r"(/data/user/0/{}[a-zA-Z0-9_\-/]+)".format(self.target_package), payload)
                if len(f_calls) != 0:
                    if last_file_user_log != f_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[FILE CALL]", f_calls[-1])
                        else:
                            table_object.add_row("[bold red][FILE CALL][white]", f_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["file"].append(f_calls[-1])
                        last_file_user_log = f_calls[-1]

                # File calls: /data/data
                f_calls = re.findall(r"(/data/data/{}[a-zA-Z0-9_\-/]+)".format(self.target_package), payload)
                if len(f_calls) != 0:
                    if last_file_data_log != f_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[FILE CALL]", f_calls[-1])
                        else:
                            table_object.add_row("[bold red][FILE CALL][white]", f_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["file"].append(f_calls[-1])
                        last_file_data_log = f_calls[-1]

                # Intent calls
                i_calls = re.findall(r"android.intent.*", payload)
                if len(i_calls) != 0:
                    if last_intent_log != i_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[INTENT CALL]", i_calls[-1])
                        else:
                            table_object.add_row("[bold yellow][INTENT CALL][white]", i_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["intent"].append(i_calls[-1])
                        last_intent_log = i_calls[-1]

                # Provider calls
                p_calls = re.findall(r"android.provider.*", payload)
                if len(p_calls) != 0:
                    if last_provider_log != p_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[PROVIDER CALL]", p_calls[-1])
                        else:
                            table_object.add_row("[bold magenta][PROVIDER CALL][white]", p_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["provider"].append(p_calls[-1])
                        last_provider_log = p_calls[-1]

                # APP role calls
                a_calls = re.findall(r"android.app.role.*", payload)
                if len(a_calls) != 0:
                    if last_approle_log != a_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[APP ROLE CALL]", a_calls[-1])
                        else:
                            table_object.add_row("[bold pink][APP ROLE CALL][white]", a_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["app_role"].append(a_calls[-1])
                        last_approle_log = a_calls[-1]

                # Method calls
                m_calls = re.findall(r"ActivityManager:.*cmp={}/.*".format(self.target_package), payload)
                if len(m_calls) != 0:
                    if last_activity_log != m_calls[-1]:
                        if callstack >= 15:
                            update_table(table_object, "[METHOD CALL]", m_calls[-1])
                        else:
                            table_object.add_row("[bold blue][METHOD CALL][white]", m_calls[-1])
                        callstack += 1
                        report["logcat_outputs"]["method"].append(m_calls[-1])
                        last_activity_log = m_calls[-1]
                await asyncio.sleep(1)
            except:
                sys.exit(1)

    # ----- File Crawler -----
    async def file_crawler(self, table_object):
        logged_files = []
        while True:
            for dirz in previous_states.keys():
                pull = subprocess.run(f"{adb_path} -s {self.device} pull /data/data/{self.target_package}/{dirz}", shell=True, stdout=subprocess.PIPE).stdout
                if b"No such file" in pull:
                    continue
                else:
                    current_state = os.listdir(dirz)
                    if previous_states[dirz]["contents"] != current_state:
                        previous_states[dirz]["contents"] = current_state
                        previous_states[dirz]["changes"] += 1
                    else:
                        previous_states[dirz]["changes"] = 0

            for dd in previous_states.keys():
                if previous_states[dd]["changes"] != 0:
                    dircontent = recursive_dir_scan(dd)
                    if dircontent != []:
                        for ff in dircontent:
                            file_type = subprocess.check_output(f"file \"{ff}\"", shell=True).decode().split(":")[1].strip()
                            if ff not in logged_files:
                                if "Dalvik dex" in file_type or "Android package" in file_type:
                                    update_table(table_object, ff, f"[bold red]{file_type}[white]")
                                else:
                                    update_table(table_object, ff, f"[white]{file_type}")
                                logged_files.append(ff)
                                report["application_files"].append({ff: file_type})
            await asyncio.sleep(1)

    # ----- Memory Analyzer -----
    def split_data(self, agent, base, size, max_size):
        times = size/max_size
        diff = size % max_size
        cr_base = int(base, 0)
        for ttm in range(int(times)):
            self.save_to_file(agent, cr_base, max_size)
            cr_base += max_size

        if diff != 0:
            self.save_to_file(agent, cr_base, diff)
    def save_to_file(self, agent, base, size):
        try:
            buffer = agent.read_bytes(base, size)
            filex = open(f"mem_dump-{self.target_package}.dmp", "ab")
            filex.write(buffer)
            filex.close()
        except:
            pass
    def memory_analyzer(self, table_object):
        try:
            if not os.path.exists(f"mem_dump-{self.target_package}.dmp"):
                f_session = self.create_frida_session()
                f_script = f_session.create_script(self.frida_script)
                f_script.load()
                agent = f_script.exports_sync
                memory_ranges = agent.enumerate_ranges(self.PERMS)

                # Dumping application memory progress
                for memr in range(len(memory_ranges)):
                    try:
                        if memory_ranges[memr]['size'] > self.MAX_SIZE:
                            mem_acs_viol = self.split_data(agent, memory_ranges[memr]['base'], memory_ranges[memr]['size'], self.MAX_SIZE)
                            continue
                        else:
                            mem_acs_viol = self.save_to_file(agent, memory_ranges[memr]['base'], memory_ranges[memr]['size'])
                    except:
                        continue

                # Analyze memory dump
                if os.path.exists(f"mem_dump-{self.target_package}.dmp"):
                    memory_dmp_buffer = open(f"mem_dump-{self.target_package}.dmp", "rb").read()
                    
                    # Extract urls
                    urlz = re.findall(rb"http[s]?://[a-zA-Z0-9./?=_%:-]*", memory_dmp_buffer)
                    if urlz != []:
                        for u in urlz:
                            if (b"." in u) and (chk_wlist(u.decode()) and u.decode() not in report["extracted_urls"]):
                                report["extracted_urls"].append(u.decode())
                        if report["extracted_urls"] != []:
                            for u in report["extracted_urls"]:
                                update_table(table_object, u)
        except:
            pass
    async def check_alive_process(self):
        while True:
            pid = self.get_process_id(self.device_frida)
            if pid:
                self.target_acquired = True
            await asyncio.sleep(1)
    async def panel_updater(self, program_layout):
        # Create table
        url_table = Table()
        url_table.add_column("[bold green]Extracted URL Values", justify="center")
        while True:
            if self.target_acquired:
                self.memory_analyzer(url_table)
                if os.path.exists(f"mem_dump-{self.target_package}.dmp"):
                    top_left_panel = Panel(url_table, border_style="bold magenta", title="Memory Analyzer")
                    program_layout["top_left"].update(top_left_panel)
            await asyncio.sleep(1)

    # Logger
    async def create_log_file(self):
        while True:
            with open(f"sc0pe_android-{self.target_package}.json", "w") as rp_file:
                json.dump(report, rp_file, indent=4)
            rp_file.close()
            await asyncio.sleep(1)

# This function is a skeleton for our program
def skeleton_program():
    print("\n[bold cyan][[bold red]1[bold cyan]][white] Install APK and analyze")
    print("[bold cyan][[bold red]2[bold cyan]][white] Analyze pre-installed package")
    choice = int(input(f"\n{infoC} Select: "))
    if choice == 1:
        target_file = prompt("[>>>] Enter Full Path of The Target File [Press TAB to auto-complete]: ", completer=path_completer)
        ada = AndroidDynamicAnalyzer(target_file, False)
    else:
        ada = AndroidDynamicAnalyzer(None, True)
    ada.preparation_phase_main()

    # ----- TUI Zone -----
    program_layout = Layout(name="RootLayout")

    # Split screen horizontal
    program_layout.split_column(
        Layout(name="Top"),
        Layout(name="Bottom")
    )
    # Split top vertical
    program_layout["Top"].split_row(
        Layout(name="top_left"),
        Layout(name="top_right")
    )

    # Table for logcat outputs
    logtable = Table()
    logtable.add_column("[bold green]Call Type", justify="center")
    logtable.add_column("[bold green]Logs", justify="center")

    # Panel for logcat
    bottom_panel = Panel(logtable, border_style="bold yellow", title="Logcat Outputs")
    program_layout["Bottom"].update(bottom_panel)

    # Table for application files
    file_table = Table()
    file_table.add_column("[bold green]Name", justify="center")
    file_table.add_column("[bold green]Type", justify="center")

    # Panel for application files
    top_right_panel = Panel(file_table, border_style="bold green", title="Application Files")
    program_layout["top_right"].update(top_right_panel)

    # Panel for memory analyzer (default)
    top_left_panel = Panel("\n\n\n\t\tDumping memory of the application. Please wait!!!\n\n\t\t[blink][bold green]Make sure the target application is running!!![/blink]", border_style="bold red", title="Memory Analyzer")
    program_layout["top_left"].update(top_left_panel)

    # ----- Tasks -----
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    event_loop.create_task(ada.file_crawler(file_table))
    event_loop.create_task(ada.logcat_parser(logtable))
    event_loop.create_task(ada.check_alive_process())
    event_loop.create_task(ada.panel_updater(program_layout))
    event_loop.create_task(ada.create_log_file())
    with Live(program_layout, refresh_per_second=1.8):
        event_loop.run_forever()

# Execution
if __name__ == "__main__":
    try:
        skeleton_program()
    except:
        print(f"{infoS} Program terminated!")
        sys.exit(1)