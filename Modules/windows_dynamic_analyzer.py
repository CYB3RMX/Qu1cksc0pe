import re
import sys
import json
import psutil
import asyncio
import struct
import binascii
import warnings
from utils import err_exit

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
    "process_ids": [],
    "open_files": {},
    "loaded_modules": {},
    "extracted_urls": {}
}

class WindowsDynamicAnalyzer:
    def __init__(self, target_pid):
        self.target_pid = target_pid
        self.target_processes = []
        self.whitelist_domains = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r").read().split("\n")
        self.frida_script = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}FridaScripts{path_seperator}sc0pe_windows_dynamic.js", "r").read()
        self.target_api_list = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_trace_list.txt", "r").read().split("\n")
        self.proc_handler = psutil.Process(self.target_pid)
        self.target_processes.append(self.target_pid)

    async def gather_processes(self, table_object):
        while True:
            if self.proc_handler.children():
                for chld in self.proc_handler.children():
                    if chld.pid not in self.target_processes:
                        # Handling table
                        if len(table_object.columns[0]._cells) < 6:
                            # Warn about dangerous processes
                            if "cmd.exe" in chld.name() or "powershell.exe" in chld.name() or "rundll32.exe" in chld.name():
                                table_object.add_row(f"[bold red]{chld.name()}[white]", f"[bold red]{chld.pid}[white]")
                            else:
                                table_object.add_row(chld.name(), str(chld.pid))
                        else:
                            ans_ind = len(table_object.columns[0]._cells)
                            table_object.columns[0]._cells[ans_ind-1] = Text(str(chld.name()), style="bold italic cyan")
                            table_object.columns[1]._cells[ans_ind-1] = Text(str(chld.pid), style="bold italic cyan")

                        # Report
                        if (chld.pid, chld.name()) not in report_obj["process_ids"]:
                            report_obj["process_ids"].append((chld.pid, chld.name()))
                        self.target_processes.append(chld.pid)
            else:
                if str(self.proc_handler.pid) not in table_object.columns[1]._cells:
                    table_object.add_row(self.proc_handler.name(), str(self.proc_handler.pid))

                # Report
                if (self.proc_handler.pid, self.proc_handler.name()) not in report_obj["process_ids"]:
                    report_obj["process_ids"].append((self.proc_handler.pid, self.proc_handler.name()))
            await asyncio.sleep(1)

    async def enumerate_network_connections(self, table_object):
        while True:
            if self.target_processes:

                # Iterate over all pids and check their connections
                for chldz in self.target_processes:
                    try:
                        proc_net = psutil.Process(chldz)
                        chk_net = proc_net.net_connections()
                        if chk_net:
                            for conn in chk_net:

                                # If there is a remote_address
                                if "raddr" in str(conn):
                                    try:
                                        conn_str = f"{str(proc_net.pid)}|{proc_net.name()}|{conn.raddr.ip}:{conn.raddr.port}|{conn.status}"
                                        if conn_str not in report_obj["network_connections"]:
                                            parsed = conn_str.split("|")

                                            # Handle table
                                            if len(table_object.columns[0]._cells) < 14:
                                                table_object.add_row(parsed[0], parsed[1], parsed[2], parsed[3])
                                            else:
                                                ans_ind = len(table_object.columns[0]._cells)
                                                table_object.columns[0]._cells[ans_ind-1] = Text(str(parsed[0]), style="bold italic cyan")
                                                table_object.columns[1]._cells[ans_ind-1] = Text(str(parsed[1]), style="bold italic cyan")
                                                table_object.columns[2]._cells[ans_ind-1] = Text(str(parsed[2]), style="bold italic cyan")
                                                table_object.columns[3]._cells[ans_ind-1] = Text(str(parsed[3]), style="bold italic cyan")

                                            # Report
                                            report_obj["network_connections"].append(conn_str)
                                    except:
                                        continue
                    except:
                        continue
            await asyncio.sleep(1)

    async def check_alive_process(self):
        while True:
            try:
                # Check the main process
                if self.target_pid in self.target_processes:
                    main_proc = psutil.Process(self.target_pid)

                if self.target_processes:
                    for cid in self.target_processes:
                        if self.target_pid != cid: # We dont need to check main process
                            try:
                                ckpr = psutil.Process(cid)
                            except:
                                self.target_processes.remove(cid) # Delete process if its ended
            except:
                try:
                    self.target_processes.remove(self.target_pid) # If target_pid is no longer active
                except:
                    pass
            await asyncio.sleep(1)

    async def check_all_process(self):
        while True:
            if self.target_processes == []: # If there is no process terminate the monitor
                sys.exit(0)
            await asyncio.sleep(1)

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
        dumped_files = []
        while True:
            if self.target_processes != []:
                for proc_pid in self.target_processes:
                    try:
                        # Get memory object of the target pid
                        p_name = psutil.Process(int(proc_pid)).name()
                        mem = pymem.Pymem(p_name)
                        if f"{proc_pid}-{p_name}" in str(dumped_files):
                            pass
                        else:
                            # Get MZ offsets and calculate image size
                            mz_offsets = mem.pattern_scan_all(binascii.unhexlify("4D5A9000"), return_multiple=True)
                            buffer = mem.read_bytes(mz_offsets[0], 512)
                            pe_header_offset = struct.unpack("<L", buffer[0x3C:0x40])[0]
                            size_of_image_offset = pe_header_offset + 0x50
                            size_of_image = struct.unpack("<L", buffer[size_of_image_offset:size_of_image_offset + 4])[0]
                            outfile_buffer = mem.read_bytes(mz_offsets[0], size_of_image)

                            # Trim and sanitize output buffer
                            pef = pf.PE(data=outfile_buffer)
                            buffer_to_write = pef.trim()

                            # Name output file and dump
                            outfile_name = list(mem.list_modules())[0].name
                            if outfile_name not in dumped_files:
                                with open(f"qu1cksc0pe_dump-{proc_pid}-{outfile_name}", "wb") as ff:
                                    ff.write(buffer_to_write)
                                table_obj.add_row(str(proc_pid), outfile_name, str(size_of_image))
                                dumped_files.append(outfile_name)
                            pef.close()
                    except:
                        continue
            await asyncio.sleep(1)

    async def extract_url_from_memory(self, table_object):
        while True:
            if self.target_processes != []:
                for procp in self.target_processes:
                    try:
                        if procp not in report_obj["extracted_urls"].keys():
                            memp = pymem.Pymem(psutil.Process(int(procp)).name())
                            urls = memp.pattern_scan_all(rb"http[s]?://[a-zA-Z0-9./?=_%:-]*", return_multiple=True)
                            pid_url = {
                                procp: []
                            }
                            for url in urls:
                                data = memp.read_bytes(url, 128)
                                buffer = re.findall(rb"http[s]?://[a-zA-Z0-9./?=_%:-]*", data)
                                for buf in buffer:
                                    check = 0
                                    # Check valid url length
                                    if (len(buf) >= 13) and (buf != b"http://" and buf != b"https://"):
                                        # Check if the url is whitelisted
                                        for wl in self.whitelist_domains:
                                            if wl in str(buf.decode()):
                                                check += 1
                                        if (check == 0) and (buf.decode() not in pid_url[procp]):
                                            if len(table_object.columns[0]._cells) < 15:
                                                table_object.add_row(str(buf.decode()))
                                            else:
                                                ans_ind = len(table_object.columns[0]._cells)
                                                table_object.columns[0]._cells[ans_ind-1] = Text(str(buf.decode()), style="bold italic cyan")
                                            pid_url[procp].append(buf.decode())
                            report_obj["extracted_urls"].update(pid_url)
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
        Panel(Text(f"For detailed information please check: sc0pe_process-{target_pid}.json"), border_style="bold yellow", title="Detailed Information"),
        Panel(mem_dumpy, border_style="bold magenta", title="Dumped Files From Memory")
    )
    
    program_layout["top_right_down"].update(upper_right_down)

    # on_message wrapper
    def on_message(message, data):
        if message["type"] == "send":
            api_name = message["payload"]["target_api"]
            arguments = message["payload"]["args"]
            if len(win_api_ct.columns[0]._cells) < 15:
                win_api_ct.add_row(str(api_name), str(arguments))
            else:
                ans_ind = len(win_api_ct.columns[0]._cells)
                win_api_ct.columns[0]._cells[ans_ind-1] = Text(str(api_name), style="bold italic cyan")
                win_api_ct.columns[1]._cells[ans_ind-1] = Text(str(arguments), style="bold italic cyan")

            # Report
            report_obj["api_calls"].append((api_name, arguments))

    # Bottom zone
    bottom_zone = Table.grid()
    bottom_zone.add_row(
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
    program_layout["Bottom"].update(bottom_zone)

    # Create tasks
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(wda.gather_processes(proc_info_table))
    event_loop.create_task(wda.check_all_process())
    event_loop.create_task(wda.memory_dumper(mem_dumpy))
    event_loop.create_task(wda.parse_cmdline_arguments())
    event_loop.create_task(wda.enumerate_network_connections(conn_table))
    event_loop.create_task(wda.check_alive_process())
    event_loop.create_task(wda.create_log_file())
    event_loop.create_task(wda.get_loaded_modules())
    event_loop.create_task(wda.extract_url_from_memory(ex_url_mem))
    event_loop.create_task(wda.attach_process_to_frida())
    event_loop.create_task(wda.get_open_files())
    with Live(program_layout, refresh_per_second=1.1):
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

        # Execution
        print(f"\n{infoS} Monitoring PID: [bold green]{target_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
        main_app(target_pid)
    except:
        err_exit(f"{errorS} Program terminated!")