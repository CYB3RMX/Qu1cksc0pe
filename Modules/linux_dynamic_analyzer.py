import re
import os
import sys
import json
import shutil
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
    pt_prompt       = None
    _PATH_COMPLETER = None
    WordCompleter   = None

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
infoS  = f"[bold cyan][[bold red]*[bold cyan]][white]"

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

# ── Tracer filter strings ───────────────────────────────────────────────────

# Kernel syscalls for strace (comma-separated)
# read/write/sendmsg/recvmsg capture data I/O on already-running processes
# where the earlier connect/openat calls happened before strace attached.
_STRACE_FILTER = (
    "open,openat,creat,connect,bind,accept,"
    "sendto,recvfrom,sendmsg,send,recv,"
    "read,write,"
    "execve,execveat,mkdir,mkdirat,rmdir,rename,"
    "unlink,unlinkat,ptrace,prctl,kill,chmod,access"
)

# Library functions for ltrace (+-separated, used as fallback when strace unavailable)
_LTRACE_FILTER = (
    "fopen+fopen64+freopen+opendir+system+popen+dlopen+"
    "getenv+setenv+putenv+gethostbyname+getaddrinfo+"
    "inet_addr+inet_aton+remove+execvp+execlp+send+htonl+htons"
)

# ── Trace-line parsing ──────────────────────────────────────────────────────

# Matches:  [pid N]  call_name(raw_args...
_TRACE_CALL_RE = re.compile(
    r'^(?:\[pid\s+\d+\]\s+)?'
    r'(\w+)\((.{0,512})'
)
_STR_ARG_RE = re.compile(r'"((?:[^"\\]|\\.){0,256})"')
_INET_RE    = re.compile(r'inet_addr\("([^"]+)"\)')
_HTONS_RE   = re.compile(r'htons\((\d+)\)')

_NET_TRACE_CALLS  = {"connect", "bind", "accept", "sendto", "sendmsg"}
_DATA_TRACE_CALLS = {"send", "recv", "recvfrom", "read", "write"}
_NUM_TRACE_CALLS  = {"kill", "ptrace", "prctl", "htonl", "htons"}

# Minimum number of printable ASCII chars required in a data argument.
# Filters out binary IPC noise (e.g. Firefox pipe traffic: "\372", "\0\1\2...").
_ESC_SEQ_RE    = re.compile(r'\\(?:[0-7]{1,3}|x[0-9a-fA-F]{1,2}|.)')  # strace octal/hex/char escapes

# ── Interesting-findings routing ───────────────────────────────────────────

_EXEC_APIS = {"execve", "execveat", "execvp", "execlp", "system", "popen"}
_FILE_APIS = {
    "open", "openat", "creat", "fopen", "fopen64", "freopen",
    "access", "faccessat", "stat", "chmod", "fchmodat", "chown",
    "unlink", "unlinkat", "remove", "mkdir", "mkdirat", "rmdir",
    "rename", "renameat2", "opendir",
}
_LIB_APIS  = {"dlopen"}
_ENV_APIS  = {"getenv", "setenv", "putenv"}
_HOST_APIS = {"gethostbyname", "getaddrinfo", "inet_addr", "inet_aton"}
_NET_APIS  = {"connect", "bind", "accept", "sendto"}
_ANTI_APIS = {"ptrace", "prctl"}

_URL_RE = re.compile(r"https?://[a-zA-Z0-9./@?=_%:&#+\-\[\]~!$'()*,;]{8,}")
_IP_RE  = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_BTC_RE = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

_SKIP_ARGS = {"", "(null)", "0", "-1", "null"}

_FINDING_LABELS = {
    "executed_commands":    "Executed Command",
    "loaded_libraries":     "Loaded Library",
    "accessed_files":       "File Access",
    "environment_variables":"Env Variable",
    "resolved_hostnames":   "Hostname",
    "ip_addresses":         "IP Address",
    "urls":                 "URL",
    "bitcoin_addresses":    "Bitcoin Address",
    "ethereum_addresses":   "Ethereum Address",
    "anti_analysis":        "Anti-Analysis",
}


def _add_unique(lst, val):
    if val and val not in lst:
        lst.append(val)


def _route_finding(api_name, args_str, fi):
    """Categorise a Frida message into the interesting_findings dict."""
    if not args_str or args_str in _SKIP_ARGS:
        return

    if api_name in _EXEC_APIS:
        _add_unique(fi["executed_commands"], args_str)
    elif api_name in _FILE_APIS:
        _add_unique(fi["accessed_files"], args_str)
    elif api_name in _LIB_APIS:
        _add_unique(fi["loaded_libraries"], args_str)
    elif api_name in _ENV_APIS:
        _add_unique(fi["environment_variables"], args_str)
    elif api_name in _HOST_APIS:
        _add_unique(fi["resolved_hostnames"], args_str)
    elif api_name in _NET_APIS:
        _add_unique(fi["ip_addresses"], args_str)
    elif api_name in _ANTI_APIS:
        _add_unique(fi["anti_analysis"], f"{api_name}({args_str})")

    # Also scan the arg string itself for embedded indicators
    for url in _URL_RE.findall(args_str):
        _add_unique(fi["urls"], url)
    for ip in _IP_RE.findall(args_str):
        if not ip.startswith(("127.", "0.", "255.")):
            _add_unique(fi["ip_addresses"], ip)
    for btc in _BTC_RE.findall(args_str):
        _add_unique(fi["bitcoin_addresses"], btc)
    for eth in _ETH_RE.findall(args_str):
        _add_unique(fi["ethereum_addresses"], eth)


# ── Helpers ────────────────────────────────────────────────────────────────

def _input_path(prompt_text):
    return _input_text(prompt_text, completer=_PATH_COMPLETER)


def _input_text(prompt_text, completer=None):
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
        ignore_case=True, sentence=True,
    )


def _build_pid_name_completer():
    if WordCompleter is None:
        return None
    candidates = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            pid  = proc.info.get("pid")
            name = str(proc.info.get("name") or "").strip()
            if pid:
                candidates.add(str(pid))
            if name:
                candidates.add(name)
    except Exception:
        pass
    return WordCompleter(sorted(candidates)[:500], ignore_case=True, sentence=True)


# ── Analyser class ─────────────────────────────────────────────────────────

class LinuxDynamicAnalyzer:
    def __init__(self, target_pid):
        self.target_pid       = int(target_pid)
        self.target_processes = []
        self.strace_procs     = {}   # pid → asyncio.subprocess.Process
        self.ltrace_procs     = {}   # pid → asyncio.subprocess.Process

        self.proc_handler = psutil.Process(self.target_pid)
        self.target_processes.append(self.target_pid)

        self.report = {
            "network_connections": [],
            "syscalls":            {},
            "commandline_args":    {},
            "process_ids":         [],
            "open_files":          {},
            "tracer_info": {
                "tool":       None,
                "traced_pid": None,
            },
            "interesting_findings": {
                "executed_commands":    [],
                "loaded_libraries":     [],
                "accessed_files":       [],
                "environment_variables": [],
                "resolved_hostnames":   [],
                "ip_addresses":         [],
                "urls":                 [],
                "bitcoin_addresses":    [],
                "ethereum_addresses":   [],
                "anti_analysis":        [],
            },
        }

    # ── Async coroutines ───────────────────────────────────────────────────

    @staticmethod
    def _proc_row(proc):
        """Return (name, pid_str, user, status) for a psutil.Process."""
        try:
            name   = proc.name()
            pid    = str(proc.pid)
            user   = (proc.username() or "?")[:14]
            status = proc.status()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name, pid, user, status = "?", str(proc.pid), "?", "?"
        return name, pid, user, status

    async def gather_processes(self, table_object):
        _added_pids = set()
        while True:
            try:
                children = self.proc_handler.children()   # single call, no race
                targets  = children if children else [self.proc_handler]
                for proc in targets:
                    if proc.pid in _added_pids:
                        continue
                    name, pid_s, user, status = self._proc_row(proc)
                    if len(table_object.columns[0]._cells) < 6:
                        table_object.add_row(name, pid_s, user, status)
                    else:
                        idx = len(table_object.columns[0]._cells) - 1
                        table_object.columns[0]._cells[idx] = Text(name,   style="bold italic cyan")
                        table_object.columns[1]._cells[idx] = Text(pid_s,  style="bold italic cyan")
                        table_object.columns[2]._cells[idx] = Text(user,   style="bold italic cyan")
                        table_object.columns[3]._cells[idx] = Text(status, style="bold italic cyan")
                    _added_pids.add(proc.pid)
                    pid_entry = {"pid": proc.pid, "name": name}
                    if pid_entry not in self.report["process_ids"]:
                        self.report["process_ids"].append(pid_entry)
                    if proc.pid not in self.target_processes:
                        self.target_processes.append(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            await asyncio.sleep(1)

    async def enumerate_network_connections(self, table_object):
        while True:
            for pid_n in list(self.target_processes):
                try:
                    proc_net = psutil.Process(pid_n)
                    try:
                        conns = proc_net.net_connections()
                    except AttributeError:
                        conns = proc_net.connections()
                    for conn in conns:
                        if not conn.raddr:
                            continue
                        try:
                            raddr    = f"{conn.raddr.ip}:{conn.raddr.port}"
                            conn_str = (
                                f"{proc_net.pid}|{proc_net.name()}|"
                                f"{raddr}|{conn.status}"
                            )
                            if conn_str not in self.report["network_connections"]:
                                row = (str(proc_net.pid), proc_net.name(), raddr, conn.status)
                                if len(table_object.columns[0]._cells) < 14:
                                    table_object.add_row(*row)
                                else:
                                    idx = len(table_object.columns[0]._cells) - 1
                                    for i, val in enumerate(row):
                                        table_object.columns[i]._cells[idx] = Text(val, style="bold italic cyan")
                                self.report["network_connections"].append(conn_str)
                        except Exception:
                            continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(1)

    async def check_alive_process(self):
        """Remove dead PIDs, kill their tracers, stop the loop when none remain."""
        while True:
            for pid in list(self.target_processes):
                if not psutil.pid_exists(pid):
                    self.target_processes.remove(pid)
            if not self.target_processes:
                # Kill any lingering tracer subprocesses before stopping.
                for d in (self.strace_procs, self.ltrace_procs):
                    for p in list(d.values()):
                        try:
                            p.kill()
                        except Exception:
                            pass
                asyncio.get_running_loop().stop()
                return
            await asyncio.sleep(1)

    async def parse_cmdline_arguments(self):
        while True:
            for pid in list(self.target_processes):
                try:
                    if pid not in self.report["commandline_args"]:
                        proc    = psutil.Process(pid)
                        cmdline = proc.cmdline()
                        if len(cmdline) > 1:
                            self.report["commandline_args"][pid] = cmdline[1:]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(1)

    # ── strace / ltrace management ─────────────────────────────────────────

    def _parse_trace_line(self, line):
        """Parse one strace/ltrace output line.
        Returns (call_name, arg_str) or (None, None) if not a recognised call.
        """
        m = _TRACE_CALL_RE.match(line)
        if not m:
            return None, None
        call  = m.group(1)
        rargs = m.group(2)

        if call in _NET_TRACE_CALLS:
            ip_m   = _INET_RE.search(rargs)
            port_m = _HTONS_RE.search(rargs)
            if ip_m:
                port = port_m.group(1) if port_m else "?"
                return call, f"{ip_m.group(1)}:{port}"
            return None, None

        if call in _DATA_TRACE_CALLS:
            sm = _STR_ARG_RE.search(rargs)
            if not sm:
                return None, None
            val = sm.group(1)[:64]
            # Drop binary/IPC noise — strip strace escape sequences, require 3+ real chars left
            if len(_ESC_SEQ_RE.sub("", val)) < 3:
                return None, None
            return call, val

        if call in _NUM_TRACE_CALLS:
            nm = re.search(r'(\d+)', rargs)
            return (call, nm.group(1)) if nm else (None, None)

        sm = _STR_ARG_RE.search(rargs)
        return (call, sm.group(1)) if sm else (None, None)

    def _dispatch_trace_event(self, call, arg, syscall_table, findings_table, logged_findings):
        """Update the report, syscall UI table, and findings UI table."""
        if not call or not arg or arg in _SKIP_ARGS:
            return

        self.report["syscalls"].setdefault(call, [])
        if arg not in self.report["syscalls"][call]:
            self.report["syscalls"][call].append(arg)

        # Truncate for display only — full value is preserved in the report
        display_arg = arg if len(arg) <= 80 else arg[:77] + "..."

        _MAX_ROWS = 14
        if len(syscall_table.columns[0]._cells) < _MAX_ROWS:
            syscall_table.add_row(call, display_arg)
        else:
            for col in syscall_table.columns:
                col._cells[:-1] = col._cells[1:]
            syscall_table.columns[0]._cells[-1] = Text(call)
            syscall_table.columns[1]._cells[-1] = Text(display_arg)

        _route_finding(call, arg, self.report["interesting_findings"])

        fi = self.report["interesting_findings"]
        for key, label in _FINDING_LABELS.items():
            for item in fi.get(key, []):
                token = (key, item)
                if token not in logged_findings:
                    logged_findings.add(token)
                    _MAX_FINDINGS = 11
                    if len(findings_table.columns[0]._cells) < _MAX_FINDINGS:
                        findings_table.add_row(label, str(item))
                    else:
                        for col in findings_table.columns:
                            col._cells[:-1] = col._cells[1:]
                        findings_table.columns[0]._cells[-1] = Text(label)
                        findings_table.columns[1]._cells[-1] = Text(str(item))

    async def _run_strace(self, syscall_table, findings_table, logged_findings):
        """Run strace -f on target_pid, following all forked children."""
        cmd = [
            "strace", "-p", str(self.target_pid),
            "-f",        # follow forks/clones — covers child processes automatically
            "-q",        # suppress attach/detach messages
            "-e", f"trace={_STRACE_FILTER}",
            "-s", "256",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            print(f"{errorS} strace failed: {exc}")
            return
        self.strace_procs[self.target_pid] = proc
        self.report["tracer_info"] = {"tool": "strace", "traced_pid": self.target_pid}
        print(f"{infoS} strace attached to PID: [bold green]{self.target_pid}[white]")
        _got_output = False
        try:
            while True:
                raw = await proc.stderr.readline()
                if not raw:
                    if not _got_output:
                        print(f"{errorS} strace produced no output — check permissions or filter")
                    break
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                # Surface strace error messages (e.g. permission denied, invalid PID)
                if line.startswith("strace:"):
                    print(f"{errorS} strace: {line[7:].strip()}")
                    continue
                _got_output = True
                call, arg = self._parse_trace_line(line)
                if call:
                    self._dispatch_trace_event(
                        call, arg, syscall_table, findings_table, logged_findings
                    )
        except Exception:
            pass
        finally:
            self.strace_procs.pop(self.target_pid, None)
            try:
                proc.kill()
            except Exception:
                pass

    async def _run_ltrace(self, syscall_table, findings_table, logged_findings):
        """Run ltrace -f on target_pid (fallback when strace is unavailable)."""
        cmd = [
            "ltrace", "-p", str(self.target_pid),
            "-f",
            "-q",
            "-e", _LTRACE_FILTER,
            "-s", "256",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            print(f"{errorS} ltrace failed: {exc}")
            return
        self.ltrace_procs[self.target_pid] = proc
        self.report["tracer_info"] = {"tool": "ltrace", "traced_pid": self.target_pid}
        print(f"{infoS} ltrace attached to PID: [bold green]{self.target_pid}[white]")
        _got_output = False
        try:
            while True:
                raw = await proc.stderr.readline()
                if not raw:
                    if not _got_output:
                        print(f"{errorS} ltrace produced no output — check permissions or filter")
                    break
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                if line.startswith("ltrace:"):
                    print(f"{errorS} ltrace: {line[7:].strip()}")
                    continue
                _got_output = True
                call, arg = self._parse_trace_line(line)
                if call:
                    self._dispatch_trace_event(
                        call, arg, syscall_table, findings_table, logged_findings
                    )
        except Exception:
            pass
        finally:
            self.ltrace_procs.pop(self.target_pid, None)
            try:
                proc.kill()
            except Exception:
                pass

    async def start_process_tracers(self, syscall_table, findings_table):
        """Launch strace (or ltrace fallback) on the main target PID with -f."""
        logged_findings = set()
        loop = asyncio.get_running_loop()

        strace_ok = shutil.which("strace") is not None
        ltrace_ok = shutil.which("ltrace") is not None

        if not strace_ok:
            print(f"{errorS} [bold yellow]strace[white] not found — install: apt install strace")
        if not ltrace_ok:
            print(f"{errorS} [bold yellow]ltrace[white] not found — install: apt install ltrace")
        if not strace_ok and not ltrace_ok:
            return

        # strace has priority: it traces at kernel level and -f follows all forks.
        # ltrace is only used when strace is unavailable (both need exclusive ptrace).
        if strace_ok:
            loop.create_task(
                self._run_strace(syscall_table, findings_table, logged_findings)
            )
        else:
            loop.create_task(
                self._run_ltrace(syscall_table, findings_table, logged_findings)
            )

    async def get_open_files(self, table_object=None):
        _shown = set()
        while True:
            for pid in list(self.target_processes):
                files = []
                # Primary: psutil (handles /proc/pid/fd internally)
                try:
                    proc  = psutil.Process(pid)
                    files = [ff.path for ff in proc.open_files() if ff.path]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Fallback: read /proc/pid/fd directly — reliable as root even
                # when psutil.open_files() returns empty on some kernels/WSL2.
                if not files:
                    try:
                        fd_dir = f"/proc/{pid}/fd"
                        for fd_name in os.listdir(fd_dir):
                            try:
                                link = os.readlink(os.path.join(fd_dir, fd_name))
                                # Keep only regular filesystem paths; skip sockets/pipes
                                if link.startswith("/") and ":" not in link:
                                    files.append(link)
                            except OSError:
                                continue
                    except OSError:
                        pass

                if not files:
                    continue

                # Deduplicate while preserving order
                seen_paths: dict = {}
                for f in files:
                    seen_paths[f] = None
                files = list(seen_paths)
                self.report["open_files"][pid] = files

                if table_object is not None:
                    for fpath in files:
                        token = (pid, fpath)
                        if token not in _shown:
                            _shown.add(token)
                            if len(table_object.columns[0]._cells) < 14:
                                table_object.add_row(str(pid), fpath)
                            else:
                                idx = len(table_object.columns[0]._cells) - 1
                                table_object.columns[0]._cells[idx] = Text(str(pid), style="bold italic cyan")
                                table_object.columns[1]._cells[idx] = Text(fpath,    style="bold italic cyan")
            await asyncio.sleep(1.5)

    async def create_log_file(self):
        while True:
            with open(f"sc0pe_process-{self.target_pid}.json", "w") as fh:
                json.dump(self.report, fh, indent=4)
            await asyncio.sleep(1)


# ── Emulation helpers ──────────────────────────────────────────────────────

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


# ── PID resolution ─────────────────────────────────────────────────────────

def _parse_pid_input(raw):
    try:
        pid = int(str(raw).strip())
    except Exception:
        return None
    return pid if pid > 0 else None


def _normalize_process_name(raw_name):
    name = str(raw_name or "").strip().strip("\"'")
    if not name:
        return ""
    if path_seperator in name:
        name = name.split(path_seperator)[-1]
    return name.strip()


def _find_pid_by_process_name(target_name):
    name_l = str(target_name or "").strip().lower()
    if not name_l:
        return None

    exact, partial = [], []
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            pname = str(proc.info.get("name") or "")
            if not pname:
                continue
            pl = pname.lower()
            entry = (proc.info.get("create_time") or 0, int(proc.info["pid"]))
            if pl == name_l:
                exact.append(entry)
            elif name_l in pl:
                partial.append(entry)
        except Exception:
            continue

    if exact:
        exact.sort(reverse=True)
        return exact[0][1]
    if partial:
        partial.sort(reverse=True)
        return partial[0][1]
    return None


def _resolve_target_pid(value, wait_for_name=True, wait_seconds=45):
    pid = _parse_pid_input(value)
    if pid is not None:
        try:
            psutil.Process(pid)
            return pid
        except Exception:
            return None

    proc_name = _normalize_process_name(value)
    if not proc_name:
        return None

    found = _find_pid_by_process_name(proc_name)
    if found is not None:
        return found

    if not wait_for_name:
        return None

    print(f"{infoS} Target acquired! Now you need to [bold blink green]execute the target process[white].")
    import time
    for _ in range(max(1, int(wait_seconds))):
        found = _find_pid_by_process_name(proc_name)
        if found is not None:
            return found
        try:
            time.sleep(1)
        except Exception:
            break
    return None


# ── main_app ───────────────────────────────────────────────────────────────

def main_app(target_pid):
    # ── Layout tree ────────────────────────────────────────────────────────
    #
    #  ┌─────────────────────┬────────────────────────────────────────────┐
    #  │ Network (ratio=1)   │                                            │
    #  │                     │  Open Files (ratio=2, full height)         │
    #  ├─────────────────────┤                                            │
    #  │ Process Info        │                                            │
    #  │ (ratio=1)           │                                            │
    #  ├─────────────────────┴──────────────────────────────────────────-─┤
    #  │ Syscall / API Tracer (ratio=3)  │ Interesting Findings (ratio=2) │
    #  └─────────────────────────────────┴────────────────────────────────┘

    program_layout = Layout(name="Root")
    program_layout.split_column(
        Layout(name="Top",    ratio=3),
        Layout(name="Bottom", ratio=2),
    )
    program_layout["Top"].split_row(
        Layout(name="top_left",  ratio=1),
        Layout(name="top_right", ratio=2),
    )
    program_layout["top_left"].split_column(
        Layout(name="tl_net",  ratio=3),
        Layout(name="tl_proc", ratio=2),
    )
    program_layout["Bottom"].split_row(
        Layout(name="bot_syscall",   ratio=3),
        Layout(name="bot_findings",  ratio=2),
    )

    # ── Tables ─────────────────────────────────────────────────────────────

    conn_table = Table(show_edge=True)
    conn_table.add_column("[bold green]PID",         justify="center", max_width=7)
    conn_table.add_column("[bold green]Name",        justify="center", max_width=14)
    conn_table.add_column("[bold green]Remote Addr", justify="left")
    conn_table.add_column("[bold green]Status",      justify="center", max_width=12)

    proc_info_table = Table(show_edge=True)
    proc_info_table.add_column("[bold green]Name",   justify="center", max_width=16)
    proc_info_table.add_column("[bold green]PID",    justify="center", max_width=8)
    proc_info_table.add_column("[bold green]User",   justify="center", max_width=14)
    proc_info_table.add_column("[bold green]Status", justify="center", max_width=10)

    syscall_table = Table(show_edge=True)
    syscall_table.add_column("[bold green]API / Syscall", justify="center", max_width=18, no_wrap=True)
    syscall_table.add_column("[bold green]Arguments",     justify="left",   max_width=80, no_wrap=True)

    findings_table = Table(show_edge=True)
    findings_table.add_column("[bold green]Category", justify="center", max_width=18)
    findings_table.add_column("[bold green]Value",    justify="left")

    # no_wrap=True prevents long paths from folding into blank-PID rows
    open_files_table = Table(show_edge=True)
    open_files_table.add_column("[bold green]PID",  justify="center", max_width=7,  no_wrap=True)
    open_files_table.add_column("[bold green]Path", justify="left",   max_width=72, no_wrap=True)

    # ── Panel assembly ─────────────────────────────────────────────────────

    tl_net_grid = Table.grid()
    tl_net_grid.add_row(conn_table)

    program_layout["tl_net"].update(
        Panel(tl_net_grid, border_style="bold green",   title="Network Connections")
    )
    program_layout["tl_proc"].update(
        Panel(proc_info_table, border_style="bold yellow", title="Process Information")
    )
    program_layout["top_right"].update(
        Panel(open_files_table, border_style="bold magenta", title="Open Files")
    )

    program_layout["bot_syscall"].update(
        Panel(syscall_table, border_style="bold red", title="Syscall / API Tracer")
    )
    program_layout["bot_findings"].update(
        Panel(findings_table, border_style="bold cyan", title="Interesting Findings")
    )

    lda = LinuxDynamicAnalyzer(target_pid)

    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        event_loop.create_task(lda.gather_processes(proc_info_table))
        event_loop.create_task(lda.parse_cmdline_arguments())
        event_loop.create_task(lda.enumerate_network_connections(conn_table))
        event_loop.create_task(lda.check_alive_process())
        event_loop.create_task(lda.create_log_file())
        event_loop.create_task(lda.start_process_tracers(syscall_table, findings_table))
        event_loop.create_task(lda.get_open_files(open_files_table))
        with Live(program_layout, refresh_per_second=1.1):
            try:
                event_loop.run_forever()
            except KeyboardInterrupt:
                print(f"\n{infoS} Monitoring stopped by user.")
    finally:
        for d in (lda.strace_procs, lda.ltrace_procs):
            for p in list(d.values()):
                try:
                    p.kill()
                except Exception:
                    pass
        try:
            pending = asyncio.all_tasks(event_loop)
            for task in pending:
                task.cancel()
            if pending:
                event_loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
        except Exception:
            pass
        try:
            event_loop.close()
        except Exception:
            pass


# ── Menus ──────────────────────────────────────────────────────────────────

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
    print("[bold cyan][[bold red]2[bold cyan]][white] PID Monitoring")
    choice = _input_text(
        ">>> Select [1/2] [TAB for autocomplete]: ",
        completer=_build_menu_completer(),
    ).strip().lower()

    if choice in {"1", "binary", "emulation"}:
        run_binary_emulation_menu()
    elif choice in {"2", "pid", "monitor"}:
        run_pid_monitoring_menu()
    else:
        print(f"{errorS} Wrong option :(")


if __name__ == "__main__":
    try:
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
