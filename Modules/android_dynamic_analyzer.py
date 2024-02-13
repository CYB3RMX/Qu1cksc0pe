#!/usr/bin/python3

import os
import re
import sys
import time
import json
import warnings
import threading
import subprocess
import configparser
import distutils.spawn

try:
    import pyaxmlparser
except:
    print("Error: >pyaxmlparser< module not found.")
    sys.exit(1)

try:
    import frida
except:
    print("Error: >frida< module not found.")
    sys.exit(1)

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
except:
    print("Error: >prompt_toolkit< module not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.progress import track
    from rich.table import Table
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Compatibility
homeD = os.path.expanduser("~")
path_seperator = "/"
setup_scr = "setup.sh"
strings_param = "--all"
adb_path = distutils.spawn.find_executable("adb")
del_com = "rm -rf"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"
    strings_param = "-a"
    del_com = "del"
    # Get adb path for windows
    adb_conf = configparser.ConfigParser()
    adb_conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows.conf")
    adb_path = adb_conf["ADB_PATH"]["win_adb_path"]

# Disabling pyaxmlparser's logs
pyaxmlparser.core.logging.disable()
warnings.filterwarnings("ignore") # Suppressing another warnings

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
    },
    "/cache": {
        "contents": [],
        "changes": 0
    },
    "/app_apk": {
        "contents": [],
        "changes": 0
    }
}

# Gathering code patterns
pattern_file = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}detections.json"))

# Categories
categs = {
    "Banker": [], "SMS Bot": [], "Base64": [], "VNC Implementation": [], "Keylogging": [],
    "Camera": [], "Phone Calls": [], "Microphone Interaction": [],
    "Information Gathering/Stealing": [], "Database": [], "File Operations": [],
    "Windows Operations": [],
    "Persistence/Managing": [], "Network/Internet": [], "SSL Pining/Certificate Handling": [],
    "Dynamic Class/Dex Loading": [], "Java Reflection": [], "Root Detection": [],
    "Cryptography": [], "Command Execution": [], "Anti-VM/Anti-Debug": [], "BOT Activity": [],
    "Obfuscation": []
}

class AndroidDynamicAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.PERMS = "rw-"
        self.target_dirs = ["/files", "/shared_prefs", "/app_DynamicOptDex", "/cache", "/app_apk"]
        self.MAX_SIZE = 20971520
        self.url_regex = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        self.ip_addr_regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        self.frida_script = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}FridaScripts{path_seperator}sc0pe_android_enumeration.js", "r").read()
        try:
            self.axmlobj = pyaxmlparser.APK(self.target_file)
        except:
            self.axmlobj = None

    def recursive_dir_scan(self, target_directory):
        fnames = []
        for root, d_names, f_names in os.walk(target_directory):
            for ff in f_names:
                fnames.append(os.path.join(root, ff))
        return fnames

    def search_package_name(self, package_name):
        print(f"{infoS} Searching for existing installation...")
        exist_install = subprocess.check_output(f"{adb_path} shell pm list packages", shell=True).decode().split("\n")
        matchh = re.findall(rf"{package_name}", str(exist_install))
        if len(matchh) > 0:
            print(f"{infoS} Package found.")
            return True
        else:
            print(f"{infoS} Package not found.")
            return False

    def create_frida_session(self, app_name, package_name):
        try:
            print(f"\n{infoS} Trying to connect USB device for performing memory dump against: [bold green]{app_name}[white]")
            device_manager = frida.enumerate_devices()
            device = device_manager[-1] # Usb connected device
            proc_id = self.gather_process_id_android(app_name, package_name, device)
            frida_session = frida.get_usb_device().attach(int(proc_id)) # Attach target app process
            print(f"{infoS} Connection successfull...")
            return frida_session
        except:
            print(f"{errorS} Error: Unable to create frida session! Make sure your USB device connected properly...")
            print(f"{infoS} Hint: Make sure the target application [bold green]is running[white] on device! (If you sure about USB connection!)")
            return None

    def program_tracer(self, package_name, device):
        print(f"{infoS} Now you can launch the app from your device. So you can see method class/calls etc.\n")
        temp_act = ""
        tmp_file = ""
        tmp_file2 = ""
        tmp_int = ""
        tmp_p = ""
        tmp_role = ""
        try:
            while True:
                logcat_output = subprocess.check_output([f"{adb_path}", "-s", f"{device}", "logcat", "-d", package_name + ":D"])
                payload = logcat_output.decode()

                # File calls for /data/user/0/
                f_calls = re.findall(r"(/data/user/0/{}[a-zA-Z0-9_\-/]+)".format(package_name), payload)
                if len(f_calls) != 0:
                    if tmp_file != f_calls[-1]:
                        print(f"[bold red][FILE CALL] [white]{f_calls[-1]}")
                        tmp_file = f_calls[-1]

                # File calls for /data/data/
                f_calls = re.findall(r"(/data/data/{}[a-zA-Z0-9_\-/]+)".format(package_name), payload)
                if len(f_calls) != 0:
                    if tmp_file2 != f_calls[-1]:
                        print(f"[bold red][FILE CALL] [white]{f_calls[-1]}")
                        tmp_file2 = f_calls[-1]

                # Intent calls
                i_calls = re.findall(r"android.intent.*", payload)
                if len(i_calls) != 0:
                    if tmp_int != i_calls[-1]:
                        print(f"[bold yellow][INTENT CALL] [white]{i_calls[-1]}")
                        tmp_int = i_calls[-1]

                # Provider calls
                p_calls = re.findall(r"android.provider.*", payload)
                if len(p_calls) != 0:
                    if tmp_p != p_calls[-1]:
                        print(f"[bold magenta][PROVIDER CALL] [white]{p_calls[-1]}")
                        tmp_p = p_calls[-1]

                # APP role calls
                a_calls = re.findall(r"android.app.role.*", payload)
                if len(a_calls) != 0:
                    if tmp_role != a_calls[-1]:
                        print(f"[bold pink][APP ROLE CALL] [white]{a_calls[-1]}")
                        tmp_role = a_calls[-1]

                # Method calls
                m_calls = re.findall(r"ActivityManager:.*cmp={}/.*".format(package_name), payload)
                if len(m_calls) != 0:
                    if temp_act != m_calls[-1]:
                        print(f"[bold blue][METHOD CALL] [white]{m_calls[-1]}")
                        temp_act = m_calls[-1]
                time.sleep(0.5)
        except:
            sys.exit(0)

    def crawler_for_adb_analysis(self, target_directory):
        if os.path.exists(f"{sc0pe_path}{path_seperator}{target_directory}"):
            # Create a simple table for better view
            dirTable = Table(title=f"* {target_directory} Directory *", title_justify="center", title_style="bold magenta")
            dirTable.add_column("File Name", justify="center", style="bold green")
            dirTable.add_column("Type", justify="center", style="bold green")

            # Crawl the directory
            dircontent = self.recursive_dir_scan(target_directory=f"{sc0pe_path}{path_seperator}{target_directory}")
            if dircontent != []:
                print(f"\n[bold cyan][INFO][white] Crawling [bold green]{str(target_directory)} [white]directory.")
                for file in dircontent:
                    # Checking file types using "file" command
                    file_type = subprocess.check_output(f"file \"{file}\"", shell=True).decode().split(":")[1].strip()
                    if "Dalvik dex" in file_type:
                        dirTable.add_row(file.split(sc0pe_path)[1].split("//")[1], f"[bold red]{file_type}[white]")
                    else:
                        dirTable.add_row(file.split(sc0pe_path)[1].split("//")[1], f"[white]{file_type}")

                # Print the table
                print(dirTable)
                print("")

    def target_app_crawler(self, package_name, device):
        while True:
            time.sleep(1)
            # First we need to fetch the directories
            for di in self.target_dirs:
                try:
                    adb_output = subprocess.check_output([f"{adb_path}", "-s", f"{device}", "pull", f"/data/data/{package_name}{di}"])
                    if "No such file" in adb_output.decode():
                        continue
                    else:
                        # Get the current state of the folder
                        if not os.path.exists("/etc/qu1cksc0pe.conf") and not os.path.exists("/usr/bin/qu1cksc0pe"):
                            current_state = os.listdir(os.path.join(f"{sc0pe_path}", di.replace(f"{path_seperator}", "")))
                        else:
                            current_state = os.listdir(os.path.join(".", di.replace(f"{path_seperator}", "")))
                        if previous_states[di]['contents'] != current_state:
                            print(f"[bold cyan][INFO][white] {di} directory fetched.")
                            previous_states[di]['contents'] = current_state
                            previous_states[di]['changes'] += 1
                        else:
                            previous_states[di]['changes'] = 0
                except:
                    continue

            # Now we can crawl the directories
            for di in self.target_dirs:
                if previous_states[di]['changes'] != 0:
                    self.crawler_for_adb_analysis(di)

    def install_target_application(self, device, target_application):
        install_cmd = [f"{adb_path}", "-s", f"{device}", "install", f"{target_application}"]
        install_cmdl = subprocess.Popen(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        install_cmdl.wait()
        if "Success" in str(install_cmdl.communicate()):
            return True
        else:
            return None
    def uninstall_target_application(self, device, package_name):
        uninstall_cmd = [f"{adb_path}", "-s", f"{device}", "uninstall", f"{package_name}"]
        uninstall_cmdl = subprocess.Popen(uninstall_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        uninstall_cmdl.wait()
        if "Success" in str(uninstall_cmdl.communicate()):
            return True
        else:
            return None

    def enumerate_adb_devices(self):
        print(f"{infoS} Searching for devices...")
        device_index = []
        get_dev_cmd = [f"{adb_path}", "devices"]
        get_dev_cmdl = subprocess.Popen(get_dev_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        get_dev_cmdl = str(get_dev_cmdl[0]).split("\\n")
        get_dev_cmdl = get_dev_cmdl[1:-1]
        dindex = 0
        for device in get_dev_cmdl:
            if device.split("\\t")[0] != "" and device.split("\\t")[0] != "\\r":
                device_index.append({dindex: device.split("\\t")[0]})
                dindex += 1
        return device_index

    def analyze_apk_via_adb(self):
        if self.axmlobj:
            package_name = self.axmlobj.get_package()
            # If the package_name is still "" or None we need to decompile it
            if package_name == "" or package_name is None:
                package_name = subprocess.check_output(f"aapt2 dump packagename \"{self.target_file}\"", shell=True, stderr=subprocess.PIPE).strip(b"\n").decode()
                print(f"[bold magenta]>>>[white] Package name: [bold green]{package_name}\n")
            else:
                print(f"[bold magenta]>>>[white] Package name: [bold green]{package_name}\n")
        else:
            package_name = subprocess.check_output(f"aapt2 dump packagename \"{self.target_file}\"", shell=True, stderr=subprocess.PIPE).strip(b"\n").decode()
            print(f"[bold magenta]>>>[white] Package name: [bold green]{package_name}\n")

        # Remove old files
        if not os.path.exists("/etc/qu1cksc0pe.conf") and not os.path.exists("/usr/bin/qu1cksc0pe"):
            for rem in self.target_dirs:
                if os.path.exists(f"{sc0pe_path}{rem}"):
                    os.system(f"rm -rf {sc0pe_path}{rem}")
        else:
            for rem in self.target_dirs:
                if os.path.exists(f".{rem}"):
                    os.system(f"rm -rf .{rem}")

        # Gathering devices
        device_indexes = self.enumerate_adb_devices()

        # Print devices
        if len(device_indexes) == 0:
            print(f"{errorS} No devices found. Try to connect a device and try again.\n{infoS} You can use [bold cyan]\"adb connect <device_ip>:<device_port>\"[white] to connect a device.")
            sys.exit(0)
        else:
            print(f"{infoS} Available devices:")
            for device in device_indexes:
                print(f"[bold magenta]>>>[white] [bold yellow]{list(device.keys())[0]} [white]| [bold green]{list(device.values())[0]}")

            # Select device
            dnum = int(input("\n>>> Select device: "))
            if dnum > len(device_indexes) - 1:
                print(f"{errorS} Invalid device number.")
                sys.exit(0)
            else:
                mbool = self.search_package_name(package_name)
                if not mbool:
                    print(f"{infoS} Installing [bold yellow]{package_name} [white]on [bold yellow]{list(device_indexes[dnum].values())[0]}")
                    install_state = self.install_target_application(device=str(list(device_indexes[dnum].values())[0]), target_application=self.target_file)
                    if install_state:
                        print(f"{infoS} [bold yellow]{package_name} [white]installed successfully.\n")
                        tracer_thread = threading.Thread(target=self.program_tracer, args=(package_name, list(device_indexes[dnum].values())[0],))
                        crawler_thread = threading.Thread(target=self.target_app_crawler, args=(package_name, list(device_indexes[dnum].values())[0],))
                        try:
                            tracer_thread.start()
                            crawler_thread.start()
                            tracer_thread.join()
                            crawler_thread.join()
                        except:
                            print(f"{infoS} Press [blink][bold yellow]CTRL+C[white][/blink] again to stop!")
                            sys.exit(1)
                    else:
                        print(f"{errorS} Installation failed.")
                        print(f"\n{infoS} Trying to uninstall the existing app...\n")
                        unstate = self.uninstall_target_application(device=str(list(device_indexes[dnum].values())[0]), package_name=package_name)
                        if unstate:
                            print(f"{infoS} [bold yellow]{package_name} [white]uninstalled successfully.")
                            self.analyze_apk_via_adb(self.target_file)
                else:
                    tracer_thread = threading.Thread(target=self.program_tracer, args=(package_name, list(device_indexes[dnum].values())[0],))
                    crawler_thread = threading.Thread(target=self.target_app_crawler, args=(package_name, list(device_indexes[dnum].values())[0],))
                    try:
                        tracer_thread.start()
                        crawler_thread.start()
                        tracer_thread.join()
                        crawler_thread.join()
                    except:
                        print(f"{infoS} Press [blink][bold yellow]CTRL+C[white][/blink] again to stop!")
                        sys.exit(1)

    def gather_process_id_android(self, target_app, package_name, device):
        # Look process for name
        for procs in device.enumerate_processes():
            if procs.name == target_app:
                return procs.pid

        # Look process for package name
        for procs in device.enumerate_processes():
            if procs.name == package_name:
                return procs.pid
        return None

    def save_to_file(self, agent, base, size):
        try:
            buffer = agent.read_bytes(base, size)
            filex = open("temp_dump.dmp", "ab")
            filex.write(buffer)
            filex.close()
        except:
            pass
    def split_data(self, agent, base, size, max_size):
        times = size/max_size
        diff = size % max_size
        cr_base = int(base, 0)
        for ttm in range(int(times)):
            self.save_to_file(agent, cr_base, max_size)
            cr_base += max_size

        if diff != 0:
            self.save_to_file(agent, cr_base, diff)

    def parse_frida_output(self):
        # First we need to get frida-ps output
        command = "frida-ps -Uaij > package.json"
        os.system(command)

        # After that get contents of json file and delete junks
        jfile = json.load(open("package.json"))

        os.system(f"{del_com} package.json")

        return jfile

    def table_generator(self, data_array, data_type):
        if data_array != []:
            data_table = Table()
            data_table.add_column("[bold green]Extracted Values", justify="center")
            for dmp in data_array:
                data_table.add_row(dmp)
            print(data_table)
        else:
            print(f"{errorS} There is no pattern about {data_type}")

    def check_adb_connection(self):
        chek = subprocess.check_output(f"{adb_path} devices", shell=True)
        if len(chek) != 26:
            return True
        else:
            return None

    def installed_app_selector(self):
        target_apps = self.parse_frida_output()
        temp_dict = {}
        for ap in target_apps:
            temp_dict.update({ap['name']: ap['identifier']})

        print(f"{infoS} Enumerating installed applications...")
        app_table = Table()
        app_table.add_column("[bold green]Name", justify="center")
        app_table.add_column("[bold green]Identifier", justify="center")
        for ap in temp_dict:
            app_table.add_row(ap, temp_dict[ap])
        print(app_table)
        print("\n[bold cyan][[bold red]1[bold cyan]][white] Select Target via Its [bold green]Name[white]")
        print("[bold cyan][[bold red]2[bold cyan]][white] Select Target via Its [bold green]Package Name[white]")
        print(f"{infoS} NOTE: If you couldn\'t find your target in the table then It is recommended to choose [bold green]2nd[white] option to scan it!")
        choice = int(input("\n>>> Enter choice: "))
        if choice == 1:
            app_completer = WordCompleter(temp_dict.keys())
            app_name = prompt(">>> Enter Target App Name [Press TAB to auto-complete]: ", completer=app_completer)
            if app_name not in temp_dict:
                print(f"{errorS} Application name not found!")
                return None
            else:
                return [app_name, temp_dict[app_name]]
        elif choice == 2:
            print(f"\n{infoS} Enumerating all installed packages...")
            pack_completer = WordCompleter(self.user_installed_packages())
            package_name = prompt("\n>>> Enter Target Package Name [Press TAB to auto-complete]: ", completer=pack_completer)
            return [package_name, package_name]
        else:
            print(f"{errorS} Wrong choice :(")
            sys.exit(1)

    def perform_pattern_categorization(self, mem_dump_buf):
        for code_categ in track(range(len(pattern_file)), description="Processing buffer..."):
            for patt in pattern_file[list(pattern_file.keys())[code_categ]]["patterns"]:
                regx = re.findall(patt.encode(), mem_dump_buf)
                if regx != [] and '' not in regx:
                    categs[list(pattern_file.keys())[code_categ]].append(str(patt))

        # Table for statistics about categories and components
        statTable = Table(title="* Statistics About Categories and Components *", title_style="bold magenta", title_justify="center")
        statTable.add_column("[bold red]Category", justify="center")
        statTable.add_column("[bold red]Number of Found Patterns", justify="center")

        # Parsing area
        for cat in categs:
            if categs[cat] != []:
                sanalTable = Table(title=f"* {cat} *", title_style="bold green", title_justify="center")
                sanalTable.add_column("Code/Pattern", justify="center")
                for element in categs[cat]:
                    sanalTable.add_row(f"[bold yellow]{element}")
                print(sanalTable)
                statTable.add_row(cat, str(len(categs[cat])))
                print(" ")
        print(statTable)

    def locate_main_activity(self, package_name):
        print(f"\n{infoS} Locating MainActivity of the target application...")
        if self.axmlobj:
            print(f"{infoS} MainActivity: [bold green]{self.axmlobj.get_main_activity()}[white]")
            return self.axmlobj.get_main_activity()
        else:
            result = subprocess.run([f"{adb_path}", "shell", "dumpsys", "package", package_name], capture_output=True, check=True, text=True)
            lines = result.stdout.split("\n")
            for index, line in enumerate(lines):
                if "android.intent.action.MAIN:" in line:
                    main_activity_line = lines[index + 1]
                    main_activity = main_activity_line.strip()
                    print(f"{infoS} MainActivity: [bold green]{main_activity.split(' ')[1]}[white]")
                    return str(main_activity.split(" ")[1])

    def save_dump_for_further(self, app_name):
        print(f"\n{infoS} Do you want to save dump file for further analysis (y/n)?")
        choice = str(input(">>>> Choice: "))
        if choice == "Y" or choice == "y":
            os.system(f"mv temp_dump.dmp mem_dump-{app_name}.dmp")
            print(f"{infoS} File saved as: [bold green]mem_dump-{app_name}.dmp[white]")
        else:
            os.system(f"{del_com} temp_dump.dmp")

    def user_installed_packages(self):
        plist = subprocess.run([f"{adb_path}", "shell", "pm", "list", "packages"], stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        pack_l = plist.stdout.decode().split("\n")
        all_packs = []
        if pack_l:
            ptable = Table()
            ptable.add_column("[bold green]Package Name", justify="center")
            for p in pack_l:
                try:
                    ptable.add_row(str(p.split(":")[1]))
                    all_packs.append(str(p.split(":")[1]))
                except:
                    continue
            print(ptable)
            return all_packs
        else:
            print(f"{errorS} There is no package found!")
            return None

    def analyze_apk_memory_dump(self):
        # Check for adb connection first
        con_state = self.check_adb_connection()
        if not con_state:
            print(f"\n{errorS} You need to connect a device via adb first!\n")
            sys.exit(1)

        # Check for junks if exist
        if os.path.exists("temp_dump.dmp"):
            print(f"\n{infoS} Removing old memory dump file...\n")
            os.system(f"{del_com} temp_dump.dmp")

        print(f"\n{infoS} Performing memory dump analysis against: [bold green]{self.target_file}[white]")
        if self.axmlobj:
            # This code block will work if the given file is not being corrupted
            app_name = self.axmlobj.get_app_name() # We need it for fetching process ID
            package_name = self.axmlobj.get_package()

            # If we dont able to fetch app_name/package_name then look for installed applications list
            if app_name == '' or package_name == '':
                print(f"\n{infoS} An error occured while fetching [bold green]application name/package name[white]. Looks like this sample has [bold red]anti-analysis[white] techniques.")
                print(f"{infoS} By the way you can select your target application from here!")
                app_inf = self.installed_app_selector()
                if app_inf:
                    app_name = app_inf[0]
                    package_name = app_inf[1]
                    print(f"\n{infoS} Application Name: [bold green]{app_name}[white]")
                    print(f"{infoS} Package Name: [bold green]{package_name}[white]\n")
                else:
                    sys.exit(1)
            else:
                print(f"\n{infoS} Application Name: [bold green]{app_name}[white]")
                print(f"{infoS} Package Name: [bold green]{package_name}[white]\n")
        else:
            # Otherwise you can also select any installed application
            print(f"{infoS} Looks like the target file is [bold red]corrupted[white]. [bold green]If you installed the target file anyway on your system then you can select it from here![white]")
            app_inf = self.installed_app_selector()
            if app_inf:
                app_name = app_inf[0]
                package_name = app_inf[1]
                print(f"\n{infoS} Application Name: [bold green]{app_name}[white]")
                print(f"{infoS} Package Name: [bold green]{package_name}[white]\n")
            else:
                sys.exit(1)

        # Check if the target apk installed in system!
        is_installed = self.search_package_name(package_name)
        if not is_installed:
            print(f"{errorS} Target application not found on the device. Please install it and try again!")
            sys.exit(1)

        # Locate main_activity: Helpfull against samples wiht corrupted manifest file
        main_act = self.locate_main_activity(package_name=package_name)

        # Starting frida session
        frida_session = self.create_frida_session(app_name=app_name, package_name=package_name)
        if not frida_session:
            sys.exit(1)

        # Create script and agent
        script = frida_session.create_script(self.frida_script)
        script.load()
        agent = script.exports
        memory_ranges = agent.enumerate_ranges(self.PERMS)

        # Iterate over memory ranges and read data
        print(f"\n{infoS} Performing memory dump. Please wait...")
        for memr in track(range(len(memory_ranges)), description="Dumping memory..."):
            try:
                # Inspired by: https://github.com/eldan-dex/betterdump
                if memory_ranges[memr]['size'] > self.MAX_SIZE:
                    mem_acs_viol = self.split_data(agent, memory_ranges[memr]['base'], memory_ranges[memr]['size'], self.MAX_SIZE)
                    continue
                else:
                    mem_acs_viol = self.save_to_file(agent, memory_ranges[memr]['base'], memory_ranges[memr]['size'])
            except:
                continue

        # Perform strings scan
        if os.path.exists("temp_dump.dmp"):
            print(f"\n{infoS} Analyzing memory dump. Please wait...")
            dump_bufffer = open("temp_dump.dmp", "rb").read()

            # Look for URLS
            print(f"{infoS} Looking for interesting URL values...")
            dump_urls = []
            dont_need = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Android{path_seperator}blacklist_patterns.txt", "r").read().split("\n")
            matchs = re.findall(self.url_regex.encode(), dump_bufffer)
            if matchs != []:
                for url in matchs:
                    if url.decode() not in dump_urls:
                        dont_c = 0
                        # Check for url values we doesnt need
                        for dont in dont_need:
                            if dont in url.decode():
                                dont_c += 1
                        # If not found append
                        if dont_c == 0:
                            dump_urls.append(url.decode())
                # Print
                self.table_generator(data_array=dump_urls, data_type="interesting URL\'s")
            else:
                print(f"{errorS} There is no valid URL pattern found!")

            # Check for class names/methods
            if self.axmlobj:
                print(f"\n{infoS} Looking for pattern contains: [bold green]{package_name}[white]")
                methodz = []
                all_things = []
                all_things += self.axmlobj.get_activities()
                all_things += self.axmlobj.get_providers()
                all_things += self.axmlobj.get_services()
                our_regex = rf"{package_name}.[a-zA-Z0-9]*"
                matchs = re.findall(our_regex.encode(), dump_bufffer)
                if matchs != []:
                    for reg in matchs:
                        try:
                            if reg.decode() not in methodz:
                                if reg.decode() in all_things:
                                    methodz.append(reg.decode())
                        except:
                            continue

                # Print
                self.table_generator(data_array=methodz, data_type="methods")

            # Check for file paths
            print(f"\n{infoS} Looking for path values related to: [bold green]{package_name}[white]")
            path_vals = []
            matches = re.findall(rf"/data/data/{package_name}/[a-zA-Z0-9./_]*".encode(), dump_bufffer) # /data/data
            if matches != []:
                for mat in matches:
                    if mat.decode() not in path_vals:
                        path_vals.append(mat.decode())
            matches = re.findall(rf"/data/user/0/{package_name}/[a-zA-Z0-9./_]*".encode(), dump_bufffer)
            if matches != []:
                for mat in matches:
                    if mat.decode() not in path_vals:
                        path_vals.append(mat.decode())

            # Print
            self.table_generator(data_array=path_vals, data_type="path")

            # Pattern categorization
            print(f"\n{infoS} Performing pattern categorization. Please wait...")
            self.perform_pattern_categorization(mem_dump_buf=dump_bufffer)

            # Check for apk names
            print(f"\n{infoS} Looking for APK files. Please wait...")
            matchs = re.findall(r"[a-zA-Z0-9_.]*apk".encode(), dump_bufffer)
            apk_names = []
            if matchs != []:
                for apkn in matchs:
                    if apkn.decode() not in apk_names:
                        apk_names.append(apkn.decode())
            # Print
            self.table_generator(data_array=apk_names, data_type="filenames with .apk extension")

            # Check for services
            print(f"\n{infoS} Checking for services started by: [bold green]{package_name}[white]")
            matchs = re.findall(r"(serviceStart: ServiceArgsData\{([^}]*)\})|(serviceCreate: CreateServiceData\{([^}]*)\})".encode(), dump_bufffer)
            sanitize_val = []
            if matchs != []:
                for tup in matchs:
                    for val in tup:
                        if package_name in val.decode():
                            if "serviceStart" in val.decode() or "serviceCreate" in val.decode():
                                sanitize_val.append(val.decode())
                                print(f"[bold magenta]>>>[white] {val.decode()}")
            # Handle error
            if len(sanitize_val) == 0:
                print(f"{errorS} There is no information about services!")

            # Hook socket connections
            print(f"\n{infoS} Performing hook against socket connections. (Ctrl+C to stop)")
            try:
                agent.hook_socket_connect()
                agent.hook_inet_address_get_all_by_name()

                # Keep the script running
                sys.stdin.read()
            except:
                print(f"\n{errorS} Program terminated!")
                self.save_dump_for_further(app_name)
                sys.exit(1)

            # Cleanup
            self.save_dump_for_further(app_name)

    def analyzer_main(self):
        print(f"\n{infoS} What do you want to perform?\n")
        print("[bold cyan][[bold red]1[bold cyan]][white] Logcat Analysis")
        print("[bold cyan][[bold red]2[bold cyan]][white] Application Memory Analysis\n")
        choice = int(input(">>> Choice: "))
        if choice == 1:
            self.analyze_apk_via_adb()
        elif choice == 2:
            self.analyze_apk_memory_dump()
        else:
            print(f"{errorS} Wrong choice :(")
            sys.exit(1)

# Execution
androdyn = AndroidDynamicAnalyzer(target_file=str(sys.argv[1]))
androdyn.analyzer_main()