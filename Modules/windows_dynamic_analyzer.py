import re
import os
import sys
import json
import psutil
import asyncio
import warnings
from utils.helpers import err_exit
from utils.helpers import update_table
from windows_process_reader import WindowsProcessReader

try:
    from rich import print, box
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
except Exception:
    err_exit("Error: >rich< module not found.")

from datetime import datetime

try:
    import pymem
except Exception:
    err_exit("Error: >pymem< module not found.")

try:
    from windows_api_hooker import WindowsAPIHooker
except Exception:
    err_exit("Error: >windows_api_hooker< could not be loaded.")

try:
    from colorama import Fore, Style
except Exception:
    err_exit("Error: >colorama< module not found.")

# Colors
red    = Fore.LIGHTRED_EX
cyan   = Fore.LIGHTCYAN_EX
yellow = Fore.LIGHTYELLOW_EX
green  = Fore.LIGHTGREEN_EX
white  = Style.RESET_ALL

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS  = f"[bold cyan][[bold red]*[bold cyan]][white]"
infoC  = f"{cyan}[{red}*{cyan}]{white}"

# Sc0pe path
try:
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Ignore warnings
warnings.filterwarnings("ignore")

# Processes commonly abused by malware (LOLBins + shells)
_SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "certutil.exe", "bitsadmin.exe",
    "schtasks.exe", "at.exe",
    "wmic.exe", "wmiprvse.exe",
    "cmstp.exe", "control.exe",
    "odbcconf.exe", "pcalua.exe",
    "forfiles.exe", "bash.exe",
    "msiexec.exe",
    "net.exe", "net1.exe",
    "sc.exe", "bcdedit.exe",
    "vssadmin.exe", "wbadmin.exe",
    "nltest.exe", "whoami.exe",
    "curl.exe", "wget.exe",
}

# Compiled regex patterns
_URL_RE     = re.compile(r"https?://[a-zA-Z0-9./@?=_%:&#+\-\[\]~!$'()*,;]{8,}")
_IP_RE      = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                         r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
_EMAIL_RE   = re.compile(r"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,6}")
_TG_TOKEN   = re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{35})\b")
_TG_CHATID  = re.compile(r"chat_id=(-?\d{5,15})")
_DISCORD_WH = re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}")
_DISCORD_TK = re.compile(r"[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}")
_REG_RE     = re.compile(
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU|HKCR)"
    r"\\[\\A-Za-z0-9_\\ ]{5,80}", re.IGNORECASE
)
_ENC_CMD    = re.compile(r"(?:-[Ee]ncodedCommand|-[Ee]nc?)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)


class WindowsDynamicAnalyzer:
    def __init__(self, target_pid):
        self.target_pid       = target_pid
        self.target_processes = []
        self.dumped_files     = []
        self.logged_things    = []
        self._dump_mtimes     = {}   # pid -> last mtime, avoids re-reading unchanged dumps

        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r") as f:
            self.whitelist_domains = f.read().split("\n")

        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_trace_list.txt", "r") as f:
            self.target_api_list = f.read().split("\n")

        self.proc_handler = psutil.Process(self.target_pid)
        self.target_processes.append(self.target_pid)

        self._hooker = None   # kept alive so hooks remain active

        self.report = {
            "network_connections": [],
            "api_calls":           [],
            "commandline_args":    {},
            "process_ids":         {},
            "open_files":          {},
            "loaded_modules":      {},
            "extracted_urls":      {},
            "hook_info": {
                "hooked": [],
                "failed": [],
            },
            "interesting_findings": {
                "telegram_bot_token": [],
                "telegram_chat_id":   [],
                "discord_webhook":    [],
                "discord_token":      [],
                "email":              [],
                "email_password":     [],
                "ip_addresses":       [],
                "registry_keys":      [],
                "encoded_commands":   [],
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_valid_url(self, url: str) -> bool:
        if len(url) < 13 or url in {"http://", "https://"}:
            return False
        return not any(wl in url for wl in self.whitelist_domains if wl)

    def _extract_strings_from_raw(self, raw: bytes):
        """Return (ascii_strings, wide_strings) extracted from a raw byte buffer."""
        ascii_strs = [m.decode(errors="ignore")
                      for m in re.findall(rb"[^\x00-\x1F\x7F-\xFF]{4,}", raw)]
        wide_raw   = re.findall(rb"(?:[\x20-\x7E]\x00){4,}", raw)
        wide_strs  = [s.replace(b"\x00", b"").decode(errors="ignore") for s in wide_raw]
        return ascii_strs, wide_strs

    def _search(self, pattern: re.Pattern, strings: list) -> list:
        """Apply a compiled pattern across a list of strings; return unique matches."""
        seen, results = set(), []
        for s in strings:
            for m in pattern.findall(s):
                val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
                if val and val not in seen:
                    seen.add(val)
                    results.append(val)
        return results

    def _add_finding(self, key: str, values: list):
        """Add unique values to an interesting_findings category."""
        bucket = self.report["interesting_findings"][key]
        for v in values:
            if v not in bucket:
                bucket.append(v)

    # ------------------------------------------------------------------
    # Async coroutines
    # ------------------------------------------------------------------

    async def gather_processes(self, table_object):
        tmp_rep = {self.target_pid: {"childs": []}}
        while True:
            try:
                children = self.proc_handler.children()
                if children:
                    for chld in children:
                        if chld.pid not in tmp_rep[self.target_pid]["childs"]:
                            tmp_rep[self.target_pid]["childs"].append(chld.pid)
                        if chld.pid not in self.target_processes:
                            if chld.name().lower() in _SUSPICIOUS_PROCESSES:
                                update_table(table_object, 8,
                                             f"[bold red]{chld.name()}[white]",
                                             f"[bold red]{chld.pid}[white]")
                            else:
                                update_table(table_object, 8, chld.name(), str(chld.pid))
                            self.target_processes.append(chld.pid)
                    if self.target_pid not in self.report["process_ids"]:
                        self.report["process_ids"].update(tmp_rep)
                else:
                    if str(self.proc_handler.pid) not in table_object.columns[1]._cells:
                        update_table(table_object, 8,
                                     self.proc_handler.name(), str(self.proc_handler.pid))
                    if self.target_pid not in self.report["process_ids"]:
                        self.report["process_ids"].update(tmp_rep)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            await asyncio.sleep(0.5)

    async def enumerate_network_connections(self, table_object):
        while True:
            for pid_n in list(self.target_processes):
                try:
                    proc_net = psutil.Process(pid_n)
                    for conn in proc_net.net_connections():
                        if conn.raddr:
                            conn_str = (f"{proc_net.pid}|{proc_net.name()}|"
                                        f"{conn.raddr.ip}:{conn.raddr.port}|{conn.status}")
                            if conn_str not in self.report["network_connections"]:
                                update_table(table_object, 15, *conn_str.split("|"))
                                self.report["network_connections"].append(conn_str)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(0.5)

    async def check_alive_process(self):
        while True:
            for tp in list(self.target_processes):
                if not psutil.pid_exists(tp):
                    self.target_processes.remove(tp)
            if not self.target_processes:
                sys.exit(0)
            await asyncio.sleep(0.5)

    async def parse_cmdline_arguments(self):
        while True:
            for tpcmd in list(self.target_processes):
                try:
                    if tpcmd not in self.report["commandline_args"]:
                        cmd_tp  = psutil.Process(tpcmd)
                        cmdline = cmd_tp.cmdline()
                        if len(cmdline) > 1:
                            self.report["commandline_args"][tpcmd] = cmdline[1:]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(1)

    async def get_loaded_modules(self):
        while True:
            for proc_pid in list(self.target_processes):
                try:
                    proc_name = psutil.Process(int(proc_pid)).name()
                    mem       = pymem.Pymem(proc_name)
                    modules   = [mod.name for mod in list(mem.list_modules())[1:]]
                    self.report["loaded_modules"][proc_pid] = modules
                except Exception:
                    continue
            await asyncio.sleep(2)

    async def memory_dumper(self, table_obj):
        loop = asyncio.get_running_loop()
        while True:
            try:
                for t_p in list(self.target_processes):
                    dump_name = f"qu1cksc0pe_memory_dump_{t_p}.bin"
                    if dump_name in self.dumped_files:
                        continue  # already dumped this PID, don't re-dump
                    w_p_r = WindowsProcessReader(t_p)
                    try:
                        state = await loop.run_in_executor(None, w_p_r.dump_memory)
                    except Exception:
                        state = False
                    if state:
                        self.dumped_files.append(dump_name)
                        try:
                            size = os.path.getsize(dump_name)
                        except (OSError, KeyboardInterrupt):
                            size = 0
                        update_table(table_obj, 8, str(t_p), dump_name, str(size))
            except (Exception, KeyboardInterrupt):
                pass
            await asyncio.sleep(1.5)

    def _load_and_extract(self, dump_path):
        """Read dump file and extract strings — runs in thread executor."""
        with open(dump_path, "rb") as fh:
            raw = fh.read()
        return self._extract_strings_from_raw(raw)

    async def extract_url_and_interesting_from_memory(self, table_object):
        loop = asyncio.get_running_loop()
        while True:
            for tpu in list(self.target_processes):
                dump_path = f"qu1cksc0pe_memory_dump_{tpu}.bin"
                if not os.path.exists(dump_path):
                    continue

                # Skip re-processing if the dump file hasn't changed
                try:
                    mtime = os.path.getmtime(dump_path)
                except OSError:
                    continue
                if self._dump_mtimes.get(tpu) == mtime:
                    continue
                self._dump_mtimes[tpu] = mtime

                # File read + regex string extraction run in a thread so they
                # don't block the event loop (50 MB file + re.findall is slow)
                try:
                    ascii_strs, wide_strs = await loop.run_in_executor(
                        None, self._load_and_extract, dump_path
                    )
                except OSError:
                    continue

                all_strs = ascii_strs + wide_strs
                fi       = self.report["interesting_findings"]

                # Telegram bot token
                self._add_finding("telegram_bot_token",
                    [t.replace("bot", "") if t.startswith("bot") else t
                     for t in self._search(_TG_TOKEN, all_strs)])

                # Telegram chat_id
                self._add_finding("telegram_chat_id", self._search(_TG_CHATID, all_strs))

                # Discord webhook URL
                self._add_finding("discord_webhook", self._search(_DISCORD_WH, all_strs))

                # Discord bot token
                self._add_finding("discord_token", self._search(_DISCORD_TK, all_strs))

                # Email addresses + adjacent password heuristic (wide-char strings only)
                for mail in self._search(_EMAIL_RE, all_strs):
                    if mail not in fi["email"]:
                        fi["email"].append(mail)
                        try:
                            idx = wide_strs.index(mail)
                            candidate = wide_strs[idx + 1]
                            if candidate not in fi["email_password"] and "Format_BadBase64Char" not in candidate:
                                fi["email_password"].append(candidate)
                        except (ValueError, IndexError):
                            pass


                # Non-loopback, non-private, non-version-like IP addresses
                def _is_ioc_ip(ip):
                    if ip.startswith(("127.", "0.", "169.254.", "255.", "10.", "192.168.")):
                        return False
                    try:
                        parts = [int(o) for o in ip.split(".")]
                        if parts[0] == 172 and 16 <= parts[1] <= 31:
                            return False
                        # All octets small → version string (e.g. 1.2.3.4)
                        if max(parts) < 20:
                            return False
                        # Last octet 0 → network/subnet address (e.g. 145.0.0.0, 77.1.0.0)
                        if parts[3] == 0:
                            return False
                        # Second octet 0 → version string or subnet (e.g. 21.0.2.14)
                        if parts[1] == 0:
                            return False
                        # Last three octets identical → placeholder (e.g. 37.7.7.7)
                        if parts[1] == parts[2] == parts[3]:
                            return False
                        # Low first + low second octet → version string (e.g. 14.5.201.12)
                        if parts[0] < 20 and parts[1] < 10:
                            return False
                    except (ValueError, IndexError):
                        return False
                    return True
                self._add_finding("ip_addresses", [
                    ip for ip in self._search(_IP_RE, all_strs) if _is_ioc_ip(ip)
                ])

                # Registry keys
                self._add_finding("registry_keys", self._search(_REG_RE, all_strs))

                # PowerShell encoded commands
                self._add_finding("encoded_commands", self._search(_ENC_CMD, all_strs))

                # URLs
                seen_urls = set(self.report["extracted_urls"].get(tpu, []))
                tpu_urls  = list(seen_urls)
                for s in all_strs:
                    for url in _URL_RE.findall(s):
                        if url not in seen_urls and self._is_valid_url(url):
                            update_table(table_object, 13, url)
                            tpu_urls.append(url)
                            seen_urls.add(url)
                self.report["extracted_urls"][tpu] = tpu_urls

            await asyncio.sleep(2)

    def _monitor_handler(self, data_type, table_object, description):
        for item in self.report["interesting_findings"].get(data_type, []):
            if item not in self.logged_things:
                update_table(table_object, 12, description, str(item))
                self.logged_things.append(item)

    async def interesting_findings_monitor(self, table_object):
        _LABELS = {
            "telegram_bot_token": "Telegram Bot Token",
            "telegram_chat_id":   "Telegram Chat ID",
            "discord_webhook":    "Discord Webhook",
            "discord_token":      "Discord Bot Token",
            "email":              "E-Mail Address",
            "email_password":     "Possible E-Mail Password",
            "ip_addresses":       "Embedded IP",
            "registry_keys":      "Registry Key",
            "encoded_commands":   "Encoded PS Command",
        }
        while True:
            for key, label in _LABELS.items():
                self._monitor_handler(data_type=key, table_object=table_object, description=label)
            await asyncio.sleep(1)

    async def attach_process_with_hooker(self, on_api_call_cb):
        loop = asyncio.get_running_loop()

        def _threadsafe_cb(api_name, args_str):
            loop.call_soon_threadsafe(on_api_call_cb, api_name, args_str)

        hooker = WindowsAPIHooker(
            self.target_pid,
            [a for a in self.target_api_list if a.strip()],
            _threadsafe_cb,
        )
        try:
            # start() only allocates resources; DebugActiveProcess runs inside the thread
            await loop.run_in_executor(None, hooker.start)
        except Exception as exc:
            self.report["hook_info"] = {
                "hooked": [],
                "failed": [{"api": "attach", "reason": str(exc)}],
            }
            return

        self._hooker = hooker   # keep alive – hooks die with the object

        # Continuously sync hook status from the background debug thread.
        # Wait for the thread to actually start (attach_error might be set early).
        await asyncio.sleep(0.5)

        while self._hooker is hooker and self._hooker._running:
            self.report["hook_info"] = {
                "hooked": list(hooker.hooked),
                "failed": list(hooker.failed),
                "loop_error": hooker.loop_error or "",
            }
            await asyncio.sleep(2)

        # Final sync after debug loop exits
        self.report["hook_info"] = {
            "hooked": list(hooker.hooked),
            "failed": list(hooker.failed),
            "loop_error": hooker.loop_error or "",
        }

    async def get_open_files(self):
        loop = asyncio.get_running_loop()
        while True:
            for tprc in list(self.target_processes):
                try:
                    opfl  = psutil.Process(tprc)
                    files = await loop.run_in_executor(None, opfl.open_files)
                    if files:
                        self.report["open_files"][tprc] = [ff.path for ff in files]
                except Exception:
                    continue
            await asyncio.sleep(1.5)

    async def create_log_file(self):
        while True:
            with open(f"sc0pe_process-{self.target_pid}.json", "w") as rp_file:
                json.dump(self.report, rp_file, indent=4)
            await asyncio.sleep(1)


def main_app(target_pid):
    start_time     = datetime.now()
    wda            = WindowsDynamicAnalyzer(target_pid)
    program_layout = Layout(name="RootLayout")

    # Root: fixed header strip + main body
    program_layout.split_column(
        Layout(name="Header", size=3),
        Layout(name="Main"),
    )
    # Main body: left (ratio 3) + right (ratio 2)
    program_layout["Main"].split_row(
        Layout(name="Left",  ratio=3),
        Layout(name="Right", ratio=2),
    )
    # Left: network on top (ratio 2) + api/url row below (ratio 3)
    program_layout["Left"].split_column(
        Layout(name="network", ratio=2),
        Layout(name="api_row", ratio=3),
    )
    program_layout["api_row"].split_row(
        Layout(name="api"),
        Layout(name="urls"),
    )
    # Right: process/dump row (ratio 1) + findings (ratio 2)
    program_layout["Right"].split_column(
        Layout(name="proc_row", ratio=1),
        Layout(name="findings", ratio=2),
    )
    program_layout["proc_row"].split_row(
        Layout(name="processes"),
        Layout(name="dumps"),
    )

    # Network connections table
    conn_table = Table(show_header=True, header_style="bold green",
                       box=box.SIMPLE_HEAD, expand=True)
    conn_table.add_column("PID",        justify="right",  style="cyan",   no_wrap=True, width=7)
    conn_table.add_column("Process",    justify="left",   style="white",  no_wrap=True)
    conn_table.add_column("Connection", justify="left",   style="yellow", no_wrap=True)
    conn_table.add_column("Status",     justify="center", style="green",  no_wrap=True, width=14)

    # Process tree table
    proc_info_table = Table(show_header=True, header_style="bold yellow",
                            box=box.SIMPLE_HEAD, expand=True)
    proc_info_table.add_column("Process Name", justify="left",  style="white")
    proc_info_table.add_column("PID",          justify="right", style="cyan", no_wrap=True, width=7)

    # Windows API calls table
    win_api_ct = Table(show_header=True, header_style="bold red",
                       box=box.SIMPLE_HEAD, expand=True)
    win_api_ct.add_column("API / Function", justify="left", style="bold white", no_wrap=True)
    win_api_ct.add_column("Arguments",      justify="left", style="yellow")

    # Extracted URLs table
    ex_url_mem = Table(show_header=True, header_style="bold blue",
                       box=box.SIMPLE_HEAD, expand=True)
    ex_url_mem.add_column("Extracted URL", justify="left", style="bright_blue")

    # Memory dumps table
    mem_dumpy = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAD, expand=True)
    mem_dumpy.add_column("PID",       justify="right", style="cyan",    no_wrap=True, width=7)
    mem_dumpy.add_column("File Name", justify="left",  style="white",   no_wrap=True)
    mem_dumpy.add_column("Size (B)",  justify="right", style="magenta", no_wrap=True, width=10)

    # Interesting findings table
    ifds = Table(show_header=True, header_style="bold cyan",
                 box=box.SIMPLE_HEAD, expand=True)
    ifds.add_column("Type",  justify="left", style="bold cyan",   no_wrap=True)
    ifds.add_column("Value", justify="left", style="bold yellow")

    # Assign panels to layout nodes
    program_layout["Header"].update(Panel("", border_style="bold blue"))
    program_layout["network"].update(
        Panel(conn_table, border_style="bold green", title="Network Connection Tracer")
    )
    program_layout["api"].update(
        Panel(win_api_ct, border_style="bold red", title="Windows API Tracer")
    )
    program_layout["urls"].update(
        Panel(ex_url_mem, border_style="bold blue", title="Extracted URL Values")
    )
    program_layout["processes"].update(
        Panel(proc_info_table, border_style="bold yellow", title="Process Tree")
    )
    program_layout["dumps"].update(
        Panel(mem_dumpy, border_style="bold magenta", title="Memory Dumps")
    )
    program_layout["findings"].update(
        Panel(ifds, border_style="bold cyan", title="Interesting Findings")
    )

    # API hook callback — called from the hooker's background thread (via call_soon_threadsafe)
    def on_api_call(api_name, args_str):
        update_table(win_api_ct, 13, api_name, args_str)
        wda.report["api_calls"].append((api_name, args_str))

    # Status coroutine — live-updates the API Tracer panel title every 2 seconds
    async def update_hook_status():
        while True:
            await asyncio.sleep(2)
            fi         = wda.report.get("hook_info", {})
            hooked     = len(fi.get("hooked", []))
            failed     = fi.get("failed", [])
            loop_err   = fi.get("loop_error", "")

            # attach_error is either in hook_info["failed"] or directly on the hooker object
            attach_err = next(
                (f["reason"] for f in failed if f.get("api") == "attach"), None
            )
            if not attach_err and wda._hooker and wda._hooker.attach_error:
                attach_err = wda._hooker.attach_error
            write_fail = sum(1 for f in failed if "write_failed" in f.get("reason", ""))
            not_found  = sum(1 for f in failed if f.get("reason") == "export_not_found")

            if attach_err:
                title = f"[bold red]Windows API Tracer[/] [dim red]({attach_err[:70]})[/]"
            elif loop_err:
                title = f"[bold red]Windows API Tracer[/] [dim red](loop error: {loop_err[:60]})[/]"
            elif hooked:
                extra = ""
                if write_fail:
                    extra = f", {write_fail} ACG-blocked"
                if not_found:
                    extra += f", {not_found} not found"
                title = f"[bold red]Windows API Tracer[/] [dim green]({hooked} hooks active{extra})[/]"
            elif wda._hooker is not None:
                title = "[bold red]Windows API Tracer[/] [dim yellow](attaching...)[/]"
            else:
                title = "[bold red]Windows API Tracer[/] [dim](waiting for attach)[/]"

            program_layout["api"].update(
                Panel(win_api_ct, border_style="bold red", title=title)
            )

    # Header coroutine — updates PID, process name, status and uptime every second
    async def update_header():
        while True:
            elapsed = datetime.now() - start_time
            h, rem  = divmod(int(elapsed.total_seconds()), 3600)
            m, s    = divmod(rem, 60)
            try:
                proc    = psutil.Process(wda.target_pid)
                pname   = proc.name()
                pstatus = "[bold green]● RUNNING[/]"
            except psutil.NoSuchProcess:
                pname   = "N/A"
                pstatus = "[bold red]● TERMINATED[/]"
            g = Table.grid(expand=True)
            g.add_column(justify="left",   ratio=1)
            g.add_column(justify="center", ratio=1)
            g.add_column(justify="right",  ratio=1)
            g.add_row(
                f"  [bold cyan]PID[/]: [white]{wda.target_pid}[/]  "
                f"[bold cyan]Process[/]: [white]{pname}[/]  {pstatus}",
                "[bold red]Qu1cksc0pe[/] [bold white]Windows Dynamic Analyzer[/]",
                f"[bold cyan]Monitored[/]: [white]{len(wda.target_processes)}[/]  "
                f"[bold cyan]Uptime[/]: [white]{h:02d}:{m:02d}:{s:02d}[/]  ",
            )
            program_layout["Header"].update(Panel(g, border_style="bold blue"))
            await asyncio.sleep(1)

    # Event loop + tasks
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(wda.gather_processes(proc_info_table))
    loop.create_task(wda.check_alive_process())
    loop.create_task(wda.enumerate_network_connections(conn_table))
    loop.create_task(wda.memory_dumper(mem_dumpy))
    loop.create_task(wda.parse_cmdline_arguments())
    loop.create_task(wda.create_log_file())
    loop.create_task(wda.get_loaded_modules())
    loop.create_task(wda.extract_url_and_interesting_from_memory(ex_url_mem))
    loop.create_task(wda.interesting_findings_monitor(ifds))
    loop.create_task(wda.attach_process_with_hooker(on_api_call))
    loop.create_task(wda.get_open_files())
    loop.create_task(update_header())
    loop.create_task(update_hook_status())

    with Live(program_layout, refresh_per_second=1.8):
        loop.run_forever()


if __name__ == "__main__":
    try:
        target_pid_or_name = input(f"{infoC} Enter target PID or Process Name: ")

        if target_pid_or_name.isnumeric():
            target_pid = int(target_pid_or_name)
        else:
            # Strip path separators — only keep the filename
            if path_seperator in target_pid_or_name:
                target_pid_or_name = target_pid_or_name.split(path_seperator)[-1]

            print(f"\n{infoS} Target acquired! Now you need to [bold blink green]execute the target file![white]")
            target_pid = None
            while True:
                for pr in psutil.process_iter():
                    if target_pid_or_name in pr.name():
                        target_pid = int(pr.pid)
                        break
                if target_pid:
                    break

            # Walk up to parent only when the direct parent is NOT explorer.exe
            parent = psutil.Process(target_pid).parent()
            if parent and "explorer.exe" not in parent.name():
                target_pid = psutil.Process(target_pid).ppid()

        print(f"\n{infoS} Monitoring PID: [bold green]{target_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
        print(f"{infoS} For detailed information please check: [bold green]sc0pe_process-{target_pid}.json[white]")
        main_app(target_pid)
    except KeyboardInterrupt:
        err_exit(f"{errorS} Keyboard interrupt detected...")
    except Exception:
        err_exit(f"{errorS} Program terminated!")
