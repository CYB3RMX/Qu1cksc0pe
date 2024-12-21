import re
import os
import sys
import json
import psutil
import asyncio
import warnings
from utils import err_exit
from windows_process_reader import WindowsProcessReader

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.panel import Panel
except:
    err_exit("Error: >rich< module not found.")

try:
    import pymem
except:
    err_exit("Error: >pymem< module not found.")

try:
    import frida
except:
    err_exit("Error: >frida< module not found.")

try:
    import pefile as pf
except:
    err_exit("Error: >pefile< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
yellow = Fore.LIGHTYELLOW_EX
green = Fore.LIGHTGREEN_EX
white = Style.RESET_ALL

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
infoC = f"{cyan}[{red}*{cyan}]{white}"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Target process and ignore warnings
warnings.filterwarnings("ignore")

# Report object
report_obj = {
    "network_connections": [],
    "api_calls": [],
    "commandline_args": {},
    "process_ids": {},
    "open_files": {},
    "loaded_modules": {},
    "extracted_urls": {}
}

class WindowsDynamicAnalyzer:
    def __init__(self, target_pid):
        self.target_pid = target_pid
        self.target_processes = []
        self.dumped_files = []
        self.whitelist_domains = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r").read().split("\n")
        self.frida_script = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}FridaScripts{path_seperator}sc0pe_windows_dynamic.js", "r").read()
        self.target_api_list = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_trace_list.txt", "r").read().split("\n")
        self.proc_handler = psutil.Process(self.target_pid)
        self.target_processes.append(self.target_pid)

    async def gather_processes(self, table_object):
        tmp_rep = {
            self.target_pid: {
                "childs": []
            }
        }
        while True:
            try:
                if self.proc_handler.children() != []:
                    for chld in self.proc_handler.children():
                        # Add childs to tmp_rep first
                        if chld.pid not in tmp_rep[self.target_pid]["childs"]:
                            tmp_rep[self.target_pid]["childs"].append(chld.pid)

                        # Check if the child process are dangerous
                        if chld.pid not in self.target_processes:
                            if "cmd.exe" in chld.name() or "powershell.exe" in chld.name() or "rundll32.exe" in chld.name():
                                self._update_table(table_object, f"[bold red]{chld.name()}[white]", f"[bold red]{str(chld.pid)}[white]")
                            else:
                                self._update_table(table_object, chld.name(), str(chld.pid))
                            self.target_processes.append(chld.pid)

                    # Finally add the tmp_rep to the report_object
                    if self.target_pid not in report_obj["process_ids"].keys():
                        report_obj["process_ids"].update(tmp_rep)    
                else:
                    if str(self.proc_handler.pid) not in table_object.columns[1]._cells:
                        self._update_table(table_object, self.proc_handler.name(), str(self.proc_handler.pid))
                    if self.target_pid not in report_obj["process_ids"].keys():
                        report_obj["process_ids"].update(tmp_rep)
                await asyncio.sleep(0.5)
            except psutil.NoSuchProcess:
                continue

    async def enumerate_network_connections(self, table_object):
        while True:
            try:
                for pid_n in self.target_processes:
                    proc_net = psutil.Process(pid_n)
                    if proc_net.net_connections() != []:
                        for conn in proc_net.net_connections():
                            if conn.raddr:
                                conn_str = f"{proc_net.pid}|{proc_net.name()}|{conn.raddr.ip}:{conn.raddr.port}|{conn.status}"
                                if conn_str not in report_obj["network_connections"]:
                                    self._update_table(table_object, *conn_str.split("|"))
                                    report_obj["network_connections"].append(conn_str)
                await asyncio.sleep(0.5)
            except psutil.NoSuchProcess:
                continue

    async def check_alive_process(self):
        while True:
            if self.target_processes != []:
                for tp in self.target_processes:
                    if not psutil.pid_exists(tp):
                        self.target_processes.remove(tp)
            else:
                sys.exit(0)
            await asyncio.sleep(0.5)

    async def parse_cmdline_arguments(self):
        while True:
            # Check all the process ids in the same time
            if self.target_processes:
                for tpcmd in self.target_processes:
                    try:
                        if tpcmd not in report_obj["commandline_args"].keys():
                            cmd_tp = psutil.Process(tpcmd)
                            if len(cmd_tp.cmdline()) > 1:
                                cmdl_t = []
                                for cmc in cmd_tp.cmdline():
                                    if cmc != cmd_tp.cmdline()[0]:
                                        cmdl_t.append(cmc)
                                report_obj["commandline_args"].update({tpcmd: cmdl_t})
                    except:
                        continue
            await asyncio.sleep(1)

    async def get_loaded_modules(self):
        while True:
            # Check the processes forever
            if self.target_processes != []:
                for proc_pid in self.target_processes:
                    try:
                        if proc_pid not in report_obj["loaded_modules"].keys(): # If the target pid not logged
                            mem = pymem.Pymem(psutil.Process(int(proc_pid)).name())
                            pid_modules = {
                                proc_pid: []
                            }
                            for mod in list(mem.list_modules())[1:]:
                                pid_modules[proc_pid].append(mod.name)
                            report_obj["loaded_modules"].update(pid_modules)
                    except:
                        continue
            await asyncio.sleep(1)

    async def memory_dumper(self, table_obj):
        self.dumped_files = []
        while True:
            for t_p in self.target_processes:
                if f"qu1cksc0pe_memory_dump_{t_p}.bin" not in self.dumped_files:
                    w_p_r = WindowsProcessReader(t_p)
                    state = w_p_r.dump_memory()
                    if state:
                        self.dumped_files.append(f"qu1cksc0pe_memory_dump_{t_p}.bin")
                        table_obj.add_row(str(t_p), f"qu1cksc0pe_memory_dump_{t_p}.bin", str(os.path.getsize(f"qu1cksc0pe_memory_dump_{t_p}.bin")))
            await asyncio.sleep(1)

    async def extract_url_from_memory(self, table_object):
        while True:
            try:
                for tpu in self.target_processes:
                    if tpu not in report_obj["extracted_urls"].keys():
                        if os.path.exists(f"qu1cksc0pe_memory_dump_{tpu}.bin"):
                            dump_buffer = open(f"qu1cksc0pe_memory_dump_{tpu}.bin", "rb").read()
                            urls = re.findall(rb"http[s]?://[a-zA-Z0-9./?=_%:-]*", dump_buffer)
                            tpu_url = {tpu: []}
                            for url in urls:
                                if self._is_valid_url(url) and url.decode() not in tpu_url[tpu]:
                                    self._update_table(table_object, url.decode())
                                    tpu_url[tpu].append(url.decode())
                            report_obj["extracted_urls"].update(tpu_url)
                await asyncio.sleep(1)
            except Exception as e:
                print(e)

    async def scan_for_suspicious_directories(self, table_object):
        suspicious_directories = ["\\AppData\\Local\\Temp", "\\AppData\\Roaming"] # Will be extended
        logged_process = []
        while True:
            for proc_element in psutil.process_iter():
                try:
                    if proc_element.pid != 0:
                        if proc_element.children() != []:
                            for pec in proc_element.children():
                                # Check suspicious directories
                                for sd in suspicious_directories: # Not the best practice to implement but why not?
                                    if (sd in pec.exe()) and (pec.name() not in logged_process):
                                        table_object.add_row(str(pec.pid), pec.name(), pec.exe())
                                        logged_process.append(pec.name())
                        else:
                            for sd in suspicious_directories:
                                if (sd in proc_element.exe()) and (proc_element.name() not in logged_process):
                                    table_object.add_row(str(proc_element.pid), proc_element.name(), proc_element.exe())
                                    logged_process.append(proc_element.name())
                except:
                    continue
            await asyncio.sleep(1)

    async def attach_process_to_frida(self):
        try:
            frida_session = frida.attach(self.target_pid)
            script = frida_session.create_script(self.frida_script)
            script.on("message", on_message)
            script.load()
            agent = script.exports

            # API Hooking zone
            for api_name in self.target_api_list:
                try:
                    agent.hook_windows_api(api_name)
                except:
                    continue
        except:
            pass

    async def get_open_files(self):
        while True:
            # Check all the process ids in the same time
            if self.target_processes: # If there is target pid
                for tprc in self.target_processes:
                    if tprc not in report_obj["open_files"].keys():
                        try:
                            opfl = psutil.Process(tprc)
                            if opfl.open_files(): # If the target has open_files
                                tprc_ofl = []
                                for ff in opfl.open_files():
                                    if ff[0] not in tprc_ofl:
                                        tprc_ofl.append(ff[0])
                                report_obj["open_files"].update({tprc: tprc_ofl})
                        except:
                            continue
            await asyncio.sleep(1)

    def _is_valid_url(self, buf):
        return (len(buf) >= 13) and (buf not in {b"http://", b"https://"}) and not any(wl in buf.decode() for wl in self.whitelist_domains)

    def _update_table(self, table, *args):
        if len(table.columns[0]._cells) < 15:
            table.add_row(*args)
        else:
            ans_ind = len(table.columns[0]._cells)
            for i, arg in enumerate(args):
                table.columns[i]._cells[ans_ind-1] = Text(str(arg), style="bold italic cyan")

    async def create_log_file(self):
        while True:
            with open(f"sc0pe_process-{self.target_pid}.json", "w") as rp_file:
                json.dump(report_obj, rp_file, indent=4)
            rp_file.close()
            await asyncio.sleep(1)

def main_app(target_pid):
    wda = WindowsDynamicAnalyzer(target_pid)
    global on_message
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

    # Split top_right horizontal
    program_layout["top_right"].split_column(
        Layout(name="top_right_up"),
        Layout(name="top_right_down")
    )

    # Split bottom
    program_layout["Bottom"].split_row(
        Layout(name="bottom_left"),
        Layout(name="bottom_right")
    )

    # Create table for net connections
    conn_table = Table()
    conn_table.add_column("[bold green]PID", justify="center")
    conn_table.add_column("[bold green]Process Name", justify="center")
    conn_table.add_column("[bold green]Connection", justify="center")
    conn_table.add_column("[bold green]Status")

    # Create table for process information
    proc_info_table = Table()
    proc_info_table.add_column("[bold green]Process Name", justify="center")
    proc_info_table.add_column("[bold green]PID", justify="center")

    # Create table for windows api calls
    win_api_ct = Table()
    win_api_ct.add_column("[bold green]API/Function Name", justify="center")
    win_api_ct.add_column("[bold green]Arguments", justify="center")

    # Create table for extracted urls from memory
    ex_url_mem = Table()
    ex_url_mem.add_column("[bold green]Extracted URL Values", justify="center")

    # Create table for dumped executables
    mem_dumpy = Table()
    mem_dumpy.add_column("[bold green]PID", justify="center")
    mem_dumpy.add_column("[bold green]File Name", justify="center")
    mem_dumpy.add_column("[bold green]Size", justify="center")

    # Create table for suspicious paths
    sd_table = Table()
    sd_table.add_column("[bold green]PID", justify="center")
    sd_table.add_column("[bold green]Name", justify="center")
    sd_table.add_column("[bold green]Path", justify="center")

    # Upper grid for left
    upper_grid_left = Table.grid()
    upper_grid_left.add_row(
        conn_table
    )
    upper_panel_left = Panel(upper_grid_left, border_style="bold green", title="Network Connection Tracer")
    program_layout["top_left"].update(upper_panel_left)

    # Upper right grid zone
    upper_right_up = Table.grid()
    upper_right_up.add_row(
        Panel(proc_info_table, border_style="bold yellow", title="Process Information")
    )
    program_layout["top_right_up"].update(upper_right_up)

    # Upper down grid zone
    upper_right_down = Table.grid()
    upper_right_down.add_row(
        Panel(mem_dumpy, border_style="bold magenta", title="Dumped Files From Memory")
    )
    
    program_layout["top_right_down"].update(upper_right_down)

    # on_message wrapper
    def on_message(message, data):
        if message["type"] == "send":
            api_name = message["payload"]["target_api"]
            arguments = message["payload"]["args"]
            wda._update_table(win_api_ct, api_name, arguments)
            report_obj["api_calls"].append((api_name, arguments))

    # Bottom zone
    bottom_zone_left = Table.grid()
    bottom_zone_left.add_row(
        Panel(
            win_api_ct,
            border_style="bold red",
            title="Windows API Tracer"
        ),
        Panel(
            ex_url_mem,
            border_style="bold blue",
            title="Extracted URL Values"
        )
    )
    program_layout["bottom_left"].update(bottom_zone_left)
    bottom_zone_right = Table.grid()
    bottom_zone_right.add_row(
        Panel(sd_table, border_style="bold cyan", title="Suspicious Execution Paths")
    )
    program_layout["bottom_right"].update(bottom_zone_right)

    # Create tasks
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(wda.gather_processes(proc_info_table))
    event_loop.create_task(wda.check_alive_process())
    event_loop.create_task(wda.enumerate_network_connections(conn_table))
    event_loop.create_task(wda.memory_dumper(mem_dumpy))
    event_loop.create_task(wda.parse_cmdline_arguments())
    event_loop.create_task(wda.create_log_file())
    event_loop.create_task(wda.get_loaded_modules())
    event_loop.create_task(wda.extract_url_from_memory(ex_url_mem))
    event_loop.create_task(wda.scan_for_suspicious_directories(sd_table))
    event_loop.create_task(wda.attach_process_to_frida())
    event_loop.create_task(wda.get_open_files())
    with Live(program_layout, refresh_per_second=1.8):
        event_loop.run_forever()

if __name__ == "__main__":
    try:
        target_pid_or_name = input(f"{infoC} Enter target PID or Process Name: ")
        # Check if given input is a PID value
        if target_pid_or_name.isnumeric():
            target_pid = int(target_pid_or_name)
        else:
            # If given input is not a PID value then maybe we have target_file?
            if path_seperator in target_pid_or_name:
                target_pid_or_name = target_pid_or_name.split(path_seperator)[-1] # we need only name not path

            # After getting target we need to check if its executed or not
            print(f"\n{infoS} Target acquired! Now you need to [bold blink green]execute the target file![white]")
            target_pid = None
            while True:
                for pr in psutil.process_iter():
                    if target_pid_or_name in pr.name():
                        target_pid = int(pr.pid)
                        break
                if target_pid:
                    break
            if psutil.Process(target_pid).parent() and "explorer.exe" not in psutil.Process(target_pid).parent().name(): # We need parent only
                target_pid = psutil.Process(target_pid).ppid()

        # Execution
        print(f"\n{infoS} Monitoring PID: [bold green]{target_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
        print(f"{infoS} For detailed information please check: [bold green]sc0pe_process-{target_pid}.json[white]")
        main_app(target_pid)
    except:
        err_exit(f"{errorS} Program terminated!")