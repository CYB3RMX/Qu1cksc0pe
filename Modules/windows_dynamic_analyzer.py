import sys
import json
import psutil
import asyncio
import warnings

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.panel import Panel
except:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    import frida
except:
    print("Error: >frida< module not found.")
    sys.exit(1)

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(".path_handler", "r").read()

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Target process and ignore warnings
target_pid = int(sys.argv[1])
warnings.filterwarnings("ignore")

# Report object
report_obj = {
    "network_connections": [],
    "api_calls": [],
    "commandline_args": {},
    "process_ids": [],
    "open_files": {}
}

class WindowsDynamicAnalyzer:
    def __init__(self):
        self.target_processes = []
        self.frida_script = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}FridaScripts{path_seperator}sc0pe_windows_dynamic.js", "r").read()
        self.target_api_list = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_trace_list.txt", "r").read().split("\n")
        self.proc_handler = psutil.Process(target_pid)
        self.target_processes.append(target_pid)

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
                        chk_net = proc_net.connections()
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
                if target_pid in self.target_processes:
                    main_proc = psutil.Process(target_pid)

                if self.target_processes:
                    for cid in self.target_processes:
                        if target_pid != cid: # We dont need to check main process
                            try:
                                ckpr = psutil.Process(cid)
                            except:
                                self.target_processes.remove(cid) # Delete process if its ended
            except:
                try:
                    self.target_processes.remove(target_pid) # If target_pid is no longer active
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
                            cmd_tp = psutil.Process(cmd_tp)
                            if len(cmd_tp.cmdline()) > 1:
                                cmdl_t = []
                                for cmc in cmd_tp.cmdline():
                                    if cmc != cmd_tp.cmdline()[0]:
                                        cmdl_t.append(cmc)
                                report_obj["commandline_args"].update({tpcmd: cmdl_t})
                    except:
                        continue
            await asyncio.sleep(1)

    async def attach_process_to_frida(self):
        frida_session = frida.attach(target_pid)
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
            with open(f"sc0pe_process-{target_pid}.json", "w") as rp_file:
                json.dump(report_obj, rp_file, indent=4)
            rp_file.close()
            await asyncio.sleep(1)

def main_app():
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
        Panel(Text(f"For detailed information please check: sc0pe_process-{target_pid}.json"), border_style="bold yellow", title="Detailed Information")
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
        )
    )
    program_layout["Bottom"].update(bottom_zone)

    # Create tasks
    wda = WindowsDynamicAnalyzer()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(wda.gather_processes(proc_info_table))
    event_loop.create_task(wda.parse_cmdline_arguments())
    event_loop.create_task(wda.enumerate_network_connections(conn_table))
    event_loop.create_task(wda.check_alive_process())
    event_loop.create_task(wda.create_log_file())
    event_loop.create_task(wda.attach_process_to_frida())
    event_loop.create_task(wda.get_open_files())
    event_loop.create_task(wda.check_all_process())
    with Live(program_layout, refresh_per_second=1.1):
        event_loop.run_forever()

if __name__ == "__main__":
    try:
        print(f"\n{infoS} Monitoring PID: [bold green]{target_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
        main_app()
    except:
        print(f"{errorS} Program terminated!")
        sys.exit(1)