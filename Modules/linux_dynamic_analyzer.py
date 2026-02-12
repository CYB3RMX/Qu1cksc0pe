import os
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
except Exception:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.completion import PathCompleter, WordCompleter
    _PATH_COMPLETER = PathCompleter(expanduser=True)
except Exception:
    pt_prompt = None
    _PATH_COMPLETER = None
    WordCompleter = None

try:
    import frida
except Exception:
    frida = None

try:
    from analysis.linux.linux_emulator import Linxcution
except Exception:
    try:
        from .analysis.linux.linux_emulator import Linxcution
    except Exception:
        Linxcution = None

try:
    import lief
except Exception:
    lief = None

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(".path_handler", "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Ignore warnings
warnings.filterwarnings("ignore")


def _fresh_report():
    return {
        "network_connections": [],
        "syscalls": {},
        "commandline_args": {},
        "process_ids": [],
        "open_files": {}
    }


report_obj = _fresh_report()


def _read_ptrace_scope():
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8", errors="ignore") as fp:
            return int((fp.read() or "").strip())
    except Exception:
        return None


def _input_path(prompt_text):
    """
    Read a filesystem path with TAB-completion when prompt_toolkit is available.
    Falls back to plain input() in non-interactive/unsupported environments.
    """
    return _input_text(prompt_text, completer=_PATH_COMPLETER)


def _input_text(prompt_text, completer=None):
    """
    Read generic text with optional TAB-completion when prompt_toolkit is available.
    Falls back to plain input() in non-interactive/unsupported environments.
    """
    if pt_prompt is not None and _PATH_COMPLETER is not None and sys.stdin and sys.stdin.isatty():
        try:
            if completer is not None:
                return pt_prompt(prompt_text, completer=completer, complete_while_typing=True)
            return pt_prompt(prompt_text)
        except Exception:
            pass
    return input(prompt_text)


def _build_menu_completer():
    if WordCompleter is None:
        return None
    return WordCompleter(
        ["1", "2", "binary", "emulation", "pid", "monitor"],
        ignore_case=True,
        sentence=True,
    )


def _build_pid_name_completer():
    if WordCompleter is None:
        return None

    candidates = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info.get("pid")
            name = str(proc.info.get("name") or "").strip()
            if pid:
                candidates.add(str(pid))
            if name:
                candidates.add(name)
    except Exception:
        pass

    # Keep completion list compact for responsiveness.
    return WordCompleter(sorted(list(candidates))[:500], ignore_case=True, sentence=True)


def _is_descendant_of_current_process(pid):
    cur = os.getpid()
    try:
        proc = psutil.Process(pid)
    except Exception:
        return False
    try:
        while True:
            ppid = proc.ppid()
            if ppid == cur:
                return True
            if ppid <= 1:
                return False
            proc = psutil.Process(ppid)
    except Exception:
        return False


class LinuxDynamicAnalyzer:
    def __init__(self, target_pid, on_message_cb):
        self.target_pid = int(target_pid)
        self.target_processes = []
        self.frida_script = open(
            f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}FridaScripts{path_seperator}sc0pe_linux_dynamic.js",
            "r",
        ).read()
        self.target_api_list = json.load(
            open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Linux{path_seperator}linux_trace_list.json")
        )
        self.proc_handler = psutil.Process(self.target_pid)
        self.target_processes.append(self.target_pid)
        self.on_message_cb = on_message_cb
        self.frida_sessions = {}
        self.frida_scripts = {}
        self.frida_warn_counts = {}
        self.frida_hint_printed = False
        self.ptrace_scope = _read_ptrace_scope()

    async def gather_processes(self, table_object):
        while True:
            if self.proc_handler.children():
                for chld in self.proc_handler.children():
                    if chld.pid not in self.target_processes:
                        # Handling table
                        if len(table_object.columns[0]._cells) < 6:
                            table_object.add_row(chld.name(), str(chld.pid))
                        else:
                            ans_ind = len(table_object.columns[0]._cells)
                            table_object.columns[0]._cells[ans_ind - 1] = Text(str(chld.name()), style="bold italic cyan")
                            table_object.columns[1]._cells[ans_ind - 1] = Text(str(chld.pid), style="bold italic cyan")

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
                                                table_object.columns[0]._cells[ans_ind - 1] = Text(str(parsed[0]), style="bold italic cyan")
                                                table_object.columns[1]._cells[ans_ind - 1] = Text(str(parsed[1]), style="bold italic cyan")
                                                table_object.columns[2]._cells[ans_ind - 1] = Text(str(parsed[2]), style="bold italic cyan")
                                                table_object.columns[3]._cells[ans_ind - 1] = Text(str(parsed[3]), style="bold italic cyan")

                                            # Report
                                            report_obj["network_connections"].append(conn_str)
                                    except Exception:
                                        continue
                    except Exception:
                        continue
            await asyncio.sleep(1)

    async def check_alive_process(self):
        while True:
            try:
                # Check the main process
                if self.target_pid in self.target_processes:
                    _ = psutil.Process(self.target_pid)

                if self.target_processes:
                    for cid in self.target_processes:
                        if self.target_pid != cid:  # We dont need to check main process
                            try:
                                _ = psutil.Process(cid)
                            except Exception:
                                self.target_processes.remove(cid)  # Delete process if its ended
            except Exception:
                try:
                    self.target_processes.remove(self.target_pid)  # If target_pid is no longer active
                except Exception:
                    pass
            await asyncio.sleep(1)

    async def check_all_process(self):
        while True:
            if self.target_processes == []:  # If there is no process terminate the monitor
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
                    except Exception:
                        continue
            await asyncio.sleep(1)

    def _cleanup_frida_sessions(self):
        dead_pids = []
        for pid in list(self.frida_sessions.keys()):
            try:
                _ = psutil.Process(pid)
            except Exception:
                dead_pids.append(pid)
        for pid in dead_pids:
            try:
                self.frida_sessions[pid].detach()
            except Exception:
                pass
            self.frida_sessions.pop(pid, None)
            self.frida_scripts.pop(pid, None)

    def _can_try_attach(self, pid):
        try:
            proc = psutil.Process(pid)
        except Exception:
            return False
        if os.geteuid() != 0:
            try:
                owner_uid = proc.uids().real
            except Exception:
                owner_uid = None
            if owner_uid is not None and owner_uid != os.geteuid():
                return False
        return True

    def _print_non_root_hint_once(self):
        if self.frida_hint_printed:
            return
        if os.geteuid() == 0:
            return
        if self.ptrace_scope is None:
            return
        if self.ptrace_scope < 1:
            return
        if _is_descendant_of_current_process(self.target_pid):
            return
        print(
            f"{infoS} Non-root Frida attach can be blocked by ptrace_scope={self.ptrace_scope}. "
            f"Try same-user child processes, set ptrace_scope=0, or run with elevated privileges."
        )
        self.frida_hint_printed = True

    def _attach_single_pid(self, pid):
        sess = frida.attach(pid)
        script = sess.create_script(self.frida_script)
        script.on("message", self.on_message_cb)
        script.load()
        agent = script.exports

        for api_name in self.target_api_list:
            if api_name not in report_obj["syscalls"]:
                report_obj["syscalls"].update({api_name: []})
            try:
                agent.hook_linux_syscall(api_name, self.target_api_list[api_name]["target_arg"])
            except Exception:
                continue

        self.frida_sessions[pid] = sess
        self.frida_scripts[pid] = script
        return True

    async def attach_process_to_frida(self):
        if frida is None:
            print(f"{errorS} >frida< module not found. Install frida to use PID monitoring.")
            return

        try:
            while True:
                if not self.target_processes:
                    return

                self._cleanup_frida_sessions()
                candidates = [self.target_pid] + [p for p in self.target_processes if p != self.target_pid]
                for cand_pid in candidates:
                    if cand_pid in self.frida_sessions:
                        continue
                    if not self._can_try_attach(cand_pid):
                        continue
                    try:
                        self._attach_single_pid(cand_pid)
                        if cand_pid == self.target_pid:
                            print(f"{infoS} Frida attached to PID: [bold green]{cand_pid}[white]")
                        else:
                            print(f"{infoS} Frida attached to child PID: [bold green]{cand_pid}[white]")
                    except Exception as exc:
                        msg = str(exc).strip()
                        cnt = int(self.frida_warn_counts.get(cand_pid, 0)) + 1
                        self.frida_warn_counts[cand_pid] = cnt
                        if cnt == 1 or cnt % 20 == 0:
                            print(f"{errorS} Frida attach pending for PID [bold red]{cand_pid}[white] (attempt {cnt}): {msg}")
                        self._print_non_root_hint_once()
                        continue

                await asyncio.sleep(1)
        finally:
            for pid in list(self.frida_sessions.keys()):
                try:
                    self.frida_sessions[pid].detach()
                except Exception:
                    pass
            self.frida_sessions.clear()
            self.frida_scripts.clear()

    async def get_open_files(self):
        while True:
            # Check all the process ids in the same time
            if self.target_processes:  # If there is target pid
                for tprc in self.target_processes:
                    if tprc not in report_obj["open_files"].keys():
                        try:
                            opfl = psutil.Process(tprc)
                            if opfl.open_files():  # If the target has open_files
                                tprc_ofl = []
                                for ff in opfl.open_files():
                                    if ff[0] not in tprc_ofl:
                                        tprc_ofl.append(ff[0])
                                report_obj["open_files"].update({tprc: tprc_ofl})
                        except Exception:
                            continue
            await asyncio.sleep(1)

    async def create_log_file(self):
        while True:
            with open(f"sc0pe_process-{self.target_pid}.json", "w") as rp_file:
                json.dump(report_obj, rp_file, indent=4)
            await asyncio.sleep(1)


def _detect_machine_type(target_binary):
    if lief is None:
        print(f"{errorS} >lief< module not found. Cannot detect machine type for emulation.")
        return None
    try:
        parsed = lief.parse(target_binary)
        if not parsed:
            return None
        return str(parsed.header.machine_type).split(".")[-1]
    except Exception as exc:
        print(f"{errorS} Failed to parse target binary with LIEF: {exc}")
        return None


def run_binary_emulation_menu():
    if Linxcution is None:
        print(f"{errorS} Linux emulator module is not available.")
        return
    target_binary = _input_path(">>> Enter target binary path [TAB for autocomplete]: ").strip().strip("\"'")
    if not target_binary:
        print(f"{errorS} Empty path!")
        return
    target_binary = os.path.abspath(os.path.expanduser(target_binary))
    if not os.path.isfile(target_binary):
        print(f"{errorS} Target binary not found: [bold red]{target_binary}[white]")
        return

    machine_type = _detect_machine_type(target_binary)
    if not machine_type:
        print(f"{errorS} Could not determine machine type for emulation.")
        return

    try:
        linxc = Linxcution(target_binary, machine_type)
        linxc.perform_analysis()
    except Exception as exc:
        print(f"{errorS} Binary emulation failed: {exc}")


def _parse_pid_input(raw):
    try:
        pid = int(str(raw).strip())
    except Exception:
        return None
    if pid <= 0:
        return None
    return pid


def _normalize_process_name(raw_name):
    name = str(raw_name or "").strip().strip("\"'")
    if not name:
        return ""
    # If full path is provided, keep only basename.
    if path_seperator in name:
        name = name.split(path_seperator)[-1]
    return name.strip()


def _find_pid_by_process_name(target_name):
    name_l = str(target_name or "").strip().lower()
    if not name_l:
        return None

    exact = []
    partial = []
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            pname = str(proc.info.get("name") or "")
            if not pname:
                continue
            pl = pname.lower()
            if pl == name_l:
                exact.append((proc.info.get("create_time") or 0, int(proc.info["pid"])))
            elif name_l in pl:
                partial.append((proc.info.get("create_time") or 0, int(proc.info["pid"])))
        except Exception:
            continue

    if exact:
        # Prefer newest exact-match process.
        exact.sort(reverse=True)
        return exact[0][1]
    if partial:
        # Fallback: newest partial-match process.
        partial.sort(reverse=True)
        return partial[0][1]
    return None


def _resolve_target_pid(value, wait_for_name=True, wait_seconds=45):
    # First: treat as PID if numeric
    pid = _parse_pid_input(value)
    if pid is not None:
        try:
            _ = psutil.Process(pid)
            return pid
        except Exception:
            return None

    # Else: treat as process name.
    proc_name = _normalize_process_name(value)
    if not proc_name:
        return None

    found = _find_pid_by_process_name(proc_name)
    if found is not None:
        return found

    if not wait_for_name:
        return None

    print(f"{infoS} Target acquired! Now you need to [bold blink green]execute the target process[white].")
    for _ in range(max(1, int(wait_seconds))):
        found = _find_pid_by_process_name(proc_name)
        if found is not None:
            return found
        try:
            # short sleep without blocking event loop usage elsewhere
            import time
            time.sleep(1)
        except Exception:
            break
    return None


def main_app(target_pid):
    global report_obj
    report_obj = _fresh_report()
    program_layout = Layout(name="RootLayout")

    # Split screen horizontal
    program_layout.split_column(Layout(name="Top"), Layout(name="Bottom"))
    # Split top vertical
    program_layout["Top"].split_row(Layout(name="top_left"), Layout(name="top_right"))

    # Split top_right horizontal
    program_layout["top_right"].split_column(Layout(name="top_right_up"), Layout(name="top_right_down"))
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

    # Create table for linux syscalls
    win_api_ct = Table()
    win_api_ct.add_column("[bold green]API/Function Name", justify="center")
    win_api_ct.add_column("[bold green]Arguments", justify="center")

    # Upper grid for left
    upper_grid_left = Table.grid()
    upper_grid_left.add_row(conn_table)
    upper_panel_left = Panel(upper_grid_left, border_style="bold green", title="Network Connection Tracer")
    program_layout["top_left"].update(upper_panel_left)

    # Upper right grid zone
    upper_right_up = Table.grid()
    upper_right_up.add_row(Panel(proc_info_table, border_style="bold yellow", title="Process Information"))
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
            if api_name not in report_obj["syscalls"]:
                report_obj["syscalls"][api_name] = []
            if len(win_api_ct.columns[0]._cells) < 11:
                win_api_ct.add_row(str(api_name), str(arguments))
            else:
                ans_ind = len(win_api_ct.columns[0]._cells)
                win_api_ct.columns[0]._cells[ans_ind - 1] = Text(str(api_name), style="bold italic cyan")
                win_api_ct.columns[1]._cells[ans_ind - 1] = Text(str(arguments), style="bold italic cyan")

            # Report
            if arguments not in report_obj["syscalls"][api_name]:
                report_obj["syscalls"][api_name].append(arguments)

    # Bottom zone
    bottom_zone = Table.grid()
    bottom_zone.add_row(Panel(win_api_ct, border_style="bold red", title="Syscall Tracer"))
    program_layout["Bottom"].update(bottom_zone)

    # Create tasks
    lda = LinuxDynamicAnalyzer(target_pid, on_message)
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        event_loop.create_task(lda.gather_processes(proc_info_table))
        event_loop.create_task(lda.parse_cmdline_arguments())
        event_loop.create_task(lda.enumerate_network_connections(conn_table))
        event_loop.create_task(lda.check_alive_process())
        event_loop.create_task(lda.create_log_file())
        event_loop.create_task(lda.attach_process_to_frida())
        event_loop.create_task(lda.get_open_files())
        event_loop.create_task(lda.check_all_process())
        with Live(program_layout, refresh_per_second=1.1):
            try:
                event_loop.run_forever()
            except KeyboardInterrupt:
                # Graceful stop on Ctrl+C without traceback.
                print(f"\n{infoS} Monitoring stopped by user.")
    finally:
        try:
            pending = asyncio.all_tasks(event_loop)
            for task in pending:
                task.cancel()
            if pending:
                event_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        try:
            event_loop.close()
        except Exception:
            pass


def run_pid_monitoring_menu():
    raw_target = _input_text(
        ">>> Enter target PID or Process Name [TAB for autocomplete]: ",
        completer=_build_pid_name_completer(),
    ).strip()
    pid = _resolve_target_pid(raw_target, wait_for_name=True, wait_seconds=45)
    if pid is None:
        print(f"{errorS} PID/Process not found or is not accessible.")
        return

    print(f"\n{infoS} Monitoring PID: [bold green]{pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
    main_app(pid)


def linux_dynamic_menu():
    print(f"\n{infoS} Linux Dynamic Analysis Menu")
    print("[bold cyan][[bold red]1[bold cyan]][white] Binary Emulation (isolated environment)")
    print("[bold cyan][[bold red]2[bold cyan]][white] PID Monitoring (Frida/psutil)")
    choice = _input_text(">>> Select [1/2] [TAB for autocomplete]: ", completer=_build_menu_completer()).strip().lower()

    if choice in {"1", "binary", "emulation"}:
        run_binary_emulation_menu()
    elif choice in {"2", "pid", "monitor"}:
        run_pid_monitoring_menu()
    else:
        print(f"{errorS} Wrong option :(")


if __name__ == "__main__":
    try:
        # Backward compatible mode: if PID argument provided, start monitoring directly.
        if len(sys.argv) > 1:
            arg_pid = _resolve_target_pid(sys.argv[1], wait_for_name=False)
            if arg_pid is None:
                print(f"{errorS} PID/Process not found or is not accessible.")
                sys.exit(1)
            print(f"\n{infoS} Monitoring PID: [bold green]{arg_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
            main_app(arg_pid)
        else:
            linux_dynamic_menu()
    except KeyboardInterrupt:
        print(f"\n{infoS} Program terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"{errorS} Program terminated: {exc}")
        sys.exit(1)
