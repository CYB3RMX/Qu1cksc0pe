"""
windows_api_hooker.py
---------------------
Frida-free Windows API interceptor using the Windows Debug API (x64 only).

Strategy:
  1. Enable SeDebugPrivilege so we can attach to any user-owned process.
  2. DebugActiveProcess(pid)   -- attach as a debugger
  3. On initial EXCEPTION_BREAKPOINT (attach break-in), install INT3 hooks
     for every API that can be resolved right now.
  4. On LOAD_DLL_DEBUG_EVENT, retry APIs whose DLL was not yet loaded.
  5. On subsequent EXCEPTION_BREAKPOINT (our hooks):
       - read argument registers (RCX/RDX/R8/R9 + stack)
       - fire the callback
       - restore the original byte, rewind RIP, set TRAP_FLAG
       - single-step -> EXCEPTION_SINGLE_STEP -> re-install INT3
  6. On EXIT_PROCESS, stop the loop and detach.

Public interface
~~~~~~~~~~~~~~~~
    hooker = WindowsAPIHooker(pid, api_list, callback)
    hooker.start()           # non-blocking; debug loop runs in a daemon thread
    hooker.stop()            # detach cleanly

    hooker.hooked       -> list[str]               successfully installed APIs
    hooker.failed       -> list[{"api", "reason"}] APIs that could not be hooked
    hooker.attach_error -> str | None              set if attach itself failed

Limitations
~~~~~~~~~~~
  * Python and target MUST both be 64-bit.
  * A process can have only one debugger at a time.
  * Processes protected by ACG (e.g. Chrome GPU/renderer) block WriteProcessMemory
    on code pages -- those hooks will appear in `failed` with reason "write_failed".
"""

import ctypes
import ctypes.wintypes as W
import struct
import threading

kernel32  = ctypes.WinDLL("kernel32",  use_last_error=True)
advapi32  = ctypes.WinDLL("advapi32",  use_last_error=True)

advapi32.OpenProcessToken.restype  = ctypes.c_bool
advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.HANDLE)]
advapi32.LookupPrivilegeValueW.restype  = ctypes.c_bool

# Fix restype AND argtypes — ctypes defaults to c_int (32-bit signed), which
# silently truncates 64-bit handles and pointers on x64 Windows.
_vp  = ctypes.c_void_p
_b   = ctypes.c_bool
_dw  = W.DWORD
_sz  = ctypes.c_size_t

kernel32.GetModuleHandleW.restype  = _vp
kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

kernel32.LoadLibraryW.restype  = _vp
kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]

kernel32.GetProcAddress.restype  = _vp
kernel32.GetProcAddress.argtypes = [_vp, ctypes.c_char_p]

kernel32.OpenProcess.restype  = _vp
kernel32.OpenProcess.argtypes = [_dw, _b, _dw]

kernel32.OpenThread.restype  = _vp
kernel32.OpenThread.argtypes = [_dw, _b, _dw]

kernel32.VirtualAlloc.restype  = _vp
kernel32.VirtualAlloc.argtypes = [_vp, _sz, _dw, _dw]

kernel32.VirtualFree.argtypes = [_vp, _sz, _dw]
kernel32.VirtualFree.restype  = _b

kernel32.GetCurrentProcess.restype  = _vp
kernel32.GetCurrentProcess.argtypes = []

kernel32.CloseHandle.restype  = _b
kernel32.CloseHandle.argtypes = [_vp]

kernel32.ReadProcessMemory.restype  = _b
kernel32.ReadProcessMemory.argtypes = [_vp, _vp, _vp, _sz, ctypes.POINTER(_sz)]

kernel32.WriteProcessMemory.restype  = _b
kernel32.WriteProcessMemory.argtypes = [_vp, _vp, _vp, _sz, ctypes.POINTER(_sz)]

kernel32.GetThreadContext.restype  = _b
kernel32.GetThreadContext.argtypes = [_vp, _vp]

kernel32.SetThreadContext.restype  = _b
kernel32.SetThreadContext.argtypes = [_vp, _vp]

# WaitForDebugEvent argtypes set after DEBUG_EVENT is defined (see below)
kernel32.WaitForDebugEvent.restype  = _b

kernel32.ContinueDebugEvent.restype  = _b
kernel32.ContinueDebugEvent.argtypes = [_dw, _dw, _dw]

kernel32.DebugActiveProcess.restype  = _b
kernel32.DebugActiveProcess.argtypes = [_dw]

kernel32.DebugActiveProcessStop.restype  = _b
kernel32.DebugActiveProcessStop.argtypes = [_dw]

kernel32.DebugSetProcessKillOnExit.restype  = _b
kernel32.DebugSetProcessKillOnExit.argtypes = [_b]

# ── Constants ──────────────────────────────────────────────────────────────────
EXCEPTION_DEBUG_EVENT      = 1
CREATE_THREAD_DEBUG_EVENT  = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT    = 4
EXIT_PROCESS_DEBUG_EVENT   = 5
LOAD_DLL_DEBUG_EVENT       = 6
UNLOAD_DLL_DEBUG_EVENT     = 7
OUTPUT_DEBUG_STRING_EVENT  = 8

EXCEPTION_BREAKPOINT  = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

DBG_CONTINUE              = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CONTEXT_AMD64    = 0x00100000
CONTEXT_CONTROL  = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER  = CONTEXT_AMD64 | 0x2
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x4
CONTEXT_FULL     = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS

THREAD_ALL_ACCESS    = 0x1FFFFF
PROCESS_VM_READ      = 0x0010
PROCESS_VM_WRITE     = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT    = 0x1000
MEM_RESERVE   = 0x2000
PAGE_READWRITE = 0x04
MEM_RELEASE   = 0x8000

TRAP_FLAG = 0x100   # EFlags bit 8

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY             = 0x0008
SE_PRIVILEGE_ENABLED    = 0x00000002

# ── Win32 structures ───────────────────────────────────────────────────────────

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", W.DWORD), ("HighPart", W.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", W.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", W.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class EXCEPTION_RECORD(ctypes.Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",        W.DWORD),
    ("ExceptionFlags",       W.DWORD),
    ("ExceptionRecord",      ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",     ctypes.c_void_p),
    ("NumberParameters",     W.DWORD),
    # ULONG_PTR is pointer-sized (8 bytes on x64); c_ulong is only 4 bytes — use c_size_t
    ("ExceptionInformation", ctypes.c_size_t * 15),
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance",   W.DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread",           W.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress",    ctypes.c_void_p),
    ]

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile",                 W.HANDLE),
        ("hProcess",              W.HANDLE),
        ("hThread",               W.HANDLE),
        ("lpBaseOfImage",         ctypes.c_void_p),
        ("dwDebugInfoFileOffset", W.DWORD),
        ("nDebugInfoSize",        W.DWORD),
        ("lpThreadLocalBase",     ctypes.c_void_p),
        ("lpStartAddress",        ctypes.c_void_p),
        ("lpImageName",           ctypes.c_void_p),
        ("fUnicode",              W.WORD),
    ]

class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", W.DWORD)]

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", W.DWORD)]

class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile",                 W.HANDLE),
        ("lpBaseOfDll",           ctypes.c_void_p),
        ("dwDebugInfoFileOffset", W.DWORD),
        ("nDebugInfoSize",        W.DWORD),
        ("lpImageName",           ctypes.c_void_p),
        ("fUnicode",              W.WORD),
    ]

class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]

class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData",  ctypes.c_void_p),
        ("fUnicode",           W.WORD),
        ("nDebugStringLength", W.WORD),
    ]

class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
    ]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", W.DWORD),
        ("dwProcessId",      W.DWORD),
        ("dwThreadId",       W.DWORD),
        ("u",                _DEBUG_EVENT_UNION),
    ]

# Now that DEBUG_EVENT is defined, set the argtypes for WaitForDebugEvent
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), W.DWORD]

# ── CONTEXT x64 ── must start at a 16-byte aligned address (use VirtualAlloc) ─

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]

class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord",    ctypes.c_uint16),
        ("StatusWord",     ctypes.c_uint16),
        ("TagWord",        ctypes.c_uint8),
        ("Reserved1",      ctypes.c_uint8),
        ("ErrorOpcode",    ctypes.c_uint16),
        ("ErrorOffset",    ctypes.c_uint32),
        ("ErrorSelector",  ctypes.c_uint16),
        ("Reserved2",      ctypes.c_uint16),
        ("DataOffset",     ctypes.c_uint32),
        ("DataSelector",   ctypes.c_uint16),
        ("Reserved3",      ctypes.c_uint16),
        ("MxCsr",          ctypes.c_uint32),
        ("MxCsr_Mask",     ctypes.c_uint32),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters",   M128A * 16),
        ("Reserved4",      ctypes.c_uint8 * 96),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr",        ctypes.c_uint32),
        ("SegCs",  ctypes.c_uint16), ("SegDs",  ctypes.c_uint16),
        ("SegEs",  ctypes.c_uint16), ("SegFs",  ctypes.c_uint16),
        ("SegGs",  ctypes.c_uint16), ("SegSs",  ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8",  ctypes.c_uint64), ("R9",  ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl",        ctypes.c_uint64),
        ("DebugControl",         ctypes.c_uint64),
        ("LastBranchToRip",      ctypes.c_uint64),
        ("LastBranchFromRip",    ctypes.c_uint64),
        ("LastExceptionToRip",   ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]

# ── SeDebugPrivilege helper ────────────────────────────────────────────────────

def _enable_sedebug() -> bool:
    """Enable SeDebugPrivilege for the current process token."""
    try:
        h_token = W.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token),
        ):
            return False

        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ok = advapi32.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp),
            ctypes.sizeof(tp), None, None,
        )
        kernel32.CloseHandle(h_token)
        return bool(ok)
    except Exception:
        return False

# ── API → DLL mapping ──────────────────────────────────────────────────────────
_API_TO_DLL = {
    # kernel32.dll
    "WriteFile":          "kernel32", "ReadFile":          "kernel32",
    "OpenFile":           "kernel32", "CreateFileW":       "kernel32",
    "CreateFileA":        "kernel32", "LoadLibrary":       "kernel32",
    "LoadLibraryA":       "kernel32", "LoadLibraryExW":    "kernel32",
    "IsDebuggerPresent":  "kernel32", "CreateProcess":     "kernel32",
    "CreateProcessA":     "kernel32", "CreateProcessW":    "kernel32",
    "CreateMutex":        "kernel32", "OutputDebugString": "kernel32",
    # ntdll.dll
    "NtOpenFile":         "ntdll",    "ZwCreateFile":      "ntdll",
    # advapi32.dll
    "CreateService":          "advapi32", "StartService":          "advapi32",
    "StartServiceA":          "advapi32", "RegOpenKeyExA":         "advapi32",
    "RegOpenKeyExW":          "advapi32", "RegOpenKeyTransactedA": "advapi32",
    "RegQueryValueEx":        "advapi32", "RegQueryInfoKeyW":      "advapi32",
    "RegQueryInfoKeyA":       "advapi32", "RegQueryValueExA":      "advapi32",
    "RegSetValue":            "advapi32", "RegGetValue":           "advapi32",
    "RegKeyOpen":             "advapi32",
    # shell32.dll
    "ShellExecute":       "shell32",  "ShellExecuteW":     "shell32",
    # user32.dll
    "GetKeyboardType":    "user32",   "SetWindowsHook":    "user32",
    "SetWindowsHookEx":   "user32",   "SetWindowsHookExA": "user32",
    "SetWindowsHookExW":  "user32",   "GetAsyncKeyState":  "user32",
    "GetForegroundWindow":"user32",
    # ws2_32.dll
    "connect":            "ws2_32",   "sendto":            "ws2_32",
    "WSAConnect":         "ws2_32",   "getaddrinfo":       "ws2_32",
    # wininet.dll
    "InternetOpen":       "wininet",  "InternetOpenA":     "wininet",
    "InternetReadFile":   "wininet",  "InternetRead":      "wininet",
}

# ── Lookup helpers ─────────────────────────────────────────────────────────────

_VK_NAMES = {
    0x08: "BACKSPACE", 0x09: "TAB",   0x0D: "ENTER",   0x10: "SHIFT",
    0x11: "CTRL",      0x12: "ALT",   0x14: "CAPSLOCK", 0x1B: "ESC",
    0x20: "SPACE",     0x21: "PGUP",  0x22: "PGDN",    0x23: "END",
    0x24: "HOME",      0x25: "LEFT",  0x26: "UP",      0x27: "RIGHT",
    0x28: "DOWN",      0x2C: "PRTSC", 0x2D: "INSERT",  0x2E: "DELETE",
    0x5B: "LWIN",      0x5C: "RWIN",  0x5D: "APPS",
    **{0x70 + i: f"F{i + 1}" for i in range(12)},
}

def _vk_name(code: int) -> str:
    if code in _VK_NAMES:
        return _VK_NAMES[code]
    if 0x30 <= code <= 0x39:
        return chr(code)
    if 0x41 <= code <= 0x5A:
        return chr(code)
    if 0x60 <= code <= 0x69:
        return f"NUM{code - 0x60}"
    return f"0x{code:X}"

_WH_NAMES = {
    0: "WH_MSGFILTER",  1: "WH_JOURNALRECORD",   2: "WH_JOURNALPLAYBACK",
    3: "WH_KEYBOARD",   4: "WH_GETMESSAGE",       5: "WH_CALLWNDPROC",
    6: "WH_CBT",        7: "WH_SYSMSGFILTER",     8: "WH_MOUSE",
    9: "WH_DEBUG",     10: "WH_SHELL",            11: "WH_FOREGROUNDIDLE",
   12: "WH_CALLWNDPROCRET", 13: "WH_KEYBOARD_LL", 14: "WH_MOUSE_LL",
}

def _wh_name(code: int) -> str:
    return _WH_NAMES.get(code, f"WH_UNKNOWN:{code}")

_HKEY_MAP = {
    0x80000000: "HKCR", 0x80000001: "HKCU",
    0x80000002: "HKLM", 0x80000003: "HKU",
    0x80000005: "HKCC",
}

def _hkey_name(val: int) -> str:
    return _HKEY_MAP.get(val & 0xFFFFFFFF, f"HKEY:0x{val:X}")


# ══════════════════════════════════════════════════════════════════════════════
class WindowsAPIHooker:
    """
    Attaches to a 64-bit Windows process and intercepts Windows API calls
    using INT3 software breakpoints via the Windows Debug API.
    """

    def __init__(self, pid: int, api_list: list, callback):
        self.pid      = pid
        self.api_list = [a for a in api_list if a.strip() and a in _API_TO_DLL]
        self.callback = callback

        # Public status (populated during run, thread-safe via GIL for list.append)
        self.hooked:       list = []
        self.failed:       list = []
        self.attach_error: str | None  = None   # set if DebugActiveProcess fails
        self.loop_error:   str | None  = None   # set if debug loop crashes
        self.ready:        bool        = False  # True once initial bp handled

        # Internal state
        self._bp:         dict = {}   # addr -> {api, orig}
        self._pending_ss: dict = {}   # tid  -> bp_addr
        self._deferred:   set  = set(self.api_list)
        self._ph:         int | None = None
        self._ctx_buf:    int | None = None
        self._running:    bool = False
        self._thread:     threading.Thread | None = None

    # ── Memory helpers ─────────────────────────────────────────────────────────

    def _read_mem(self, addr: int, size: int) -> bytes | None:
        if not addr or size <= 0:
            return None
        buf  = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok   = kernel32.ReadProcessMemory(
            self._ph, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)
        )
        return buf.raw[: read.value] if (ok and read.value) else None

    def _write_mem(self, addr: int, data: bytes) -> bool:
        buf     = ctypes.create_string_buffer(data)
        written = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(
            self._ph, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(written)
        ))

    def _read_str(self, addr: int, wide: bool = False, max_chars: int = 256) -> str:
        if not addr:
            return ""
        try:
            if wide:
                raw = self._read_mem(addr, max_chars * 2)
                if not raw:
                    return ""
                decoded = raw.decode("utf-16-le", errors="replace")
                end = decoded.find("\x00")
                return decoded[:end] if end >= 0 else decoded
            else:
                raw = self._read_mem(addr, max_chars)
                if not raw:
                    return ""
                end = raw.find(b"\x00")
                chunk = raw[:end] if end >= 0 else raw
                return chunk.decode("latin-1", errors="replace")
        except Exception:
            return ""

    def _read_sock_addr(self, ptr: int) -> str:
        if not ptr:
            return ""
        raw = self._read_mem(ptr, 16)
        if not raw or len(raw) < 8:
            return ""
        family = struct.unpack_from("<H", raw, 0)[0]
        if family == 2:
            port = struct.unpack_from(">H", raw, 2)[0]
            ip   = ".".join(str(b) for b in raw[4:8])
            return f"{ip}:{port}"
        if family == 23:
            port = struct.unpack_from(">H", raw, 2)[0]
            return f"[IPv6]:{port}"
        return f"family:{family}"

    # ── Breakpoint management ──────────────────────────────────────────────────

    def _install_bp(self, addr: int, api_name: str) -> bool:
        orig = self._read_mem(addr, 1)
        if orig is None:
            return False
        if not self._write_mem(addr, b"\xCC"):
            return False
        self._bp[addr] = {"api": api_name, "orig": orig}
        return True

    def _restore_bp(self, addr: int):
        info = self._bp.get(addr)
        if info:
            self._write_mem(addr, info["orig"])

    def _reinstall_bp(self, addr: int):
        if addr in self._bp:
            self._write_mem(addr, b"\xCC")

    # ── API address resolution ─────────────────────────────────────────────────

    def _resolve_in_local(self, api_name: str) -> int:
        """
        GetProcAddress in our own process.
        System DLLs share VAs across all processes in the same boot session,
        so this gives the correct address in the target process.
        Tries exact name, then +W, then +A suffixes.
        """
        dll_name = _API_TO_DLL.get(api_name)
        if not dll_name:
            return 0
        hmod = kernel32.GetModuleHandleW(dll_name + ".dll")
        if not hmod:
            hmod = kernel32.LoadLibraryW(dll_name + ".dll")
        if not hmod:
            return 0
        for candidate in (api_name, api_name + "W", api_name + "A"):
            addr = kernel32.GetProcAddress(hmod, candidate.encode())
            if addr:
                return addr
        return 0

    # ── CONTEXT management ─────────────────────────────────────────────────────

    def _get_context(self, thread_handle: int) -> CONTEXT | None:
        ctx = CONTEXT.from_address(self._ctx_buf)
        ctx.ContextFlags = CONTEXT_FULL
        if kernel32.GetThreadContext(thread_handle, ctypes.c_void_p(self._ctx_buf)):
            return ctx
        return None

    def _set_context(self, thread_handle: int):
        kernel32.SetThreadContext(thread_handle, ctypes.c_void_p(self._ctx_buf))

    # ── Argument extraction ────────────────────────────────────────────────────

    def _extract_args(self, api_name: str, ctx: CONTEXT) -> str:
        rcx, rdx, r8, r9 = ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9

        def stack_arg(n: int) -> int:
            raw = self._read_mem(ctx.Rsp + 0x20 + (n - 4) * 8, 8)
            return struct.unpack_from("<Q", raw)[0] if raw and len(raw) == 8 else 0

        def oa_name(oa_ptr: int) -> str:
            if not oa_ptr:
                return ""
            uni_raw = self._read_mem(oa_ptr + 16, 8)
            if not uni_raw:
                return ""
            uni_ptr = struct.unpack_from("<Q", uni_raw)[0]
            if not uni_ptr:
                return ""
            buf_raw = self._read_mem(uni_ptr + 8, 8)
            if not buf_raw:
                return ""
            buf_ptr = struct.unpack_from("<Q", buf_raw)[0]
            return self._read_str(buf_ptr, wide=True)

        a = api_name

        if a in ("connect", "WSAConnect"):
            return self._read_sock_addr(rdx)
        if a == "sendto":
            return self._read_sock_addr(stack_arg(5))
        if a == "getaddrinfo":
            return self._read_str(rcx)
        if a in ("InternetOpen", "InternetOpenA"):
            return self._read_str(rcx)
        if a in ("InternetRead", "InternetReadFile"):
            return f"handle:0x{rcx:X}"

        if a == "CreateFileW":
            return self._read_str(rcx, wide=True)
        if a == "CreateFileA":
            return self._read_str(rcx)
        if a == "OpenFile":
            return self._read_str(rcx)
        if a in ("ZwCreateFile", "NtOpenFile"):
            return oa_name(r8)
        if a in ("WriteFile", "ReadFile"):
            return f"handle:0x{rcx:X}"

        if a in ("LoadLibrary", "LoadLibraryA"):
            return self._read_str(rcx)
        if a == "LoadLibraryExW":
            return self._read_str(rcx, wide=True)

        if a in ("CreateProcess", "CreateProcessW"):
            app = self._read_str(rcx, wide=True)
            cmd = self._read_str(rdx, wide=True)
            return (app + " | " if app else "") + cmd
        if a == "CreateProcessA":
            app = self._read_str(rcx)
            cmd = self._read_str(rdx)
            return (app + " | " if app else "") + cmd

        if a == "ShellExecuteW":
            return f"{self._read_str(rdx, True)} | {self._read_str(r8, True)} | {self._read_str(r9, True)}"
        if a == "ShellExecute":
            return f"{self._read_str(rdx)} | {self._read_str(r8)} | {self._read_str(r9)}"

        if a in ("RegOpenKeyExA", "RegOpenKeyTransactedA"):
            return _hkey_name(rcx) + "\\" + self._read_str(rdx)
        if a in ("RegOpenKeyExW", "RegKeyOpen"):
            return _hkey_name(rcx) + "\\" + self._read_str(rdx, wide=True)
        if a == "RegQueryValueEx":
            return self._read_str(rdx, wide=True)
        if a == "RegQueryValueExA":
            return self._read_str(rdx)
        if a in ("RegQueryInfoKeyW", "RegQueryInfoKeyA"):
            return _hkey_name(rcx)
        if a in ("RegSetValue", "RegGetValue"):
            return _hkey_name(rcx) + "\\" + self._read_str(rdx, wide=True)

        if a == "CreateService":
            return f"{self._read_str(rdx, True)} | {self._read_str(r8, True)}"
        if a == "StartService":
            return f"handle:0x{rcx:X}"
        if a == "StartServiceA":
            return self._read_str(rcx)

        if a == "CreateMutex":
            return self._read_str(r8, wide=True)

        if a == "IsDebuggerPresent":
            return ""
        if a == "OutputDebugString":
            return self._read_str(rcx)

        if a == "GetAsyncKeyState":
            return f"vkey:{_vk_name(rcx & 0xFF)}"
        if a == "GetForegroundWindow":
            return ""
        if a == "GetKeyboardType":
            return f"nTypeFlag:{rcx}"
        if a in ("SetWindowsHook", "SetWindowsHookEx",
                 "SetWindowsHookExA", "SetWindowsHookExW"):
            return _wh_name(rcx & 0xFFFF)

        return f"rcx=0x{rcx:X}"

    # ── Hook installation ──────────────────────────────────────────────────────

    def _try_hook(self, api_name: str) -> tuple[bool, str]:
        """Returns (success, fail_reason)."""
        addr = self._resolve_in_local(api_name)
        if not addr:
            return False, "export_not_found"
        if not self._install_bp(addr, api_name):
            return False, f"write_failed (err={ctypes.get_last_error()})"
        return True, ""

    def _install_pending(self):
        """Try to install hooks for all APIs in `_deferred`."""
        for api in list(self._deferred):
            ok, reason = self._try_hook(api)
            if ok:
                self.hooked.append(api)
                self._deferred.discard(api)
            else:
                # Keep in deferred unless it's a write failure (permanent)
                if "write_failed" in reason:
                    self.failed.append({"api": api, "reason": reason})
                    self._deferred.discard(api)
                # export_not_found stays in _deferred for retry on next LOAD_DLL event

    def _finalize_failed(self):
        for api in self._deferred:
            self.failed.append({"api": api, "reason": "export_not_found"})
        self._deferred.clear()

    # ── Debug loop ─────────────────────────────────────────────────────────────

    def _debug_loop(self):
        """
        Entry point for the debug loop thread.
        CRITICAL: DebugActiveProcess AND WaitForDebugEvent must run in the SAME
        OS thread. We therefore call DebugActiveProcess here, not in start().
        """
        try:
            # Attach from inside this thread
            if not kernel32.DebugActiveProcess(self.pid):
                err = ctypes.get_last_error()
                self.attach_error = f"DebugActiveProcess failed (error {err})"
                return

            kernel32.DebugSetProcessKillOnExit(False)
            self._debug_loop_inner()

        except Exception as exc:
            self.loop_error = f"{type(exc).__name__}: {exc}"
        finally:
            self._running = False
            self._finalize_failed()
            try:
                kernel32.DebugActiveProcessStop(self.pid)
            except Exception:
                pass

    def _debug_loop_inner(self):
        de       = DEBUG_EVENT()
        first_bp = True

        while self._running:
            if not kernel32.WaitForDebugEvent(ctypes.byref(de), 200):
                # Timeout or spurious failure — check errno and loop
                err = ctypes.get_last_error()
                if err not in (0, 121):   # 121 = WAIT_TIMEOUT
                    self.loop_error = f"WaitForDebugEvent error {err}"
                    return
                continue

            cont = DBG_CONTINUE
            evt  = de.dwDebugEventCode
            tid  = de.dwThreadId
            pid  = de.dwProcessId

            if evt == EXCEPTION_DEBUG_EVENT:
                exc  = de.u.Exception.ExceptionRecord
                code = exc.ExceptionCode & 0xFFFFFFFF
                addr = exc.ExceptionAddress or 0

                if code == EXCEPTION_BREAKPOINT:
                    if first_bp:
                        # Synthetic attach break-in from ntdll!DbgBreakPoint
                        first_bp = False
                        self._install_pending()
                        self.ready = True
                    else:
                        bp_addr = addr   # ExceptionAddress IS the INT3 address
                        if bp_addr in self._bp:
                            th = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
                            if th:
                                self._restore_bp(bp_addr)   # always restore first; prevents crash loop if GetThreadContext fails
                                ctx = self._get_context(th)
                                if ctx:
                                    api_name = self._bp[bp_addr]["api"]
                                    args_str = self._extract_args(api_name, ctx)
                                    try:
                                        self.callback(api_name, args_str)
                                    except Exception:
                                        pass
                                    ctx.Rip    = bp_addr
                                    ctx.EFlags |= TRAP_FLAG
                                    self._set_context(th)
                                    self._pending_ss[tid] = bp_addr
                                kernel32.CloseHandle(th)
                        else:
                            cont = DBG_EXCEPTION_NOT_HANDLED

                elif code == EXCEPTION_SINGLE_STEP:
                    bp_addr = self._pending_ss.pop(tid, None)
                    if bp_addr is not None:
                        self._reinstall_bp(bp_addr)
                        th = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
                        if th:
                            ctx = self._get_context(th)
                            if ctx:
                                ctx.EFlags &= ~TRAP_FLAG
                                self._set_context(th)
                            kernel32.CloseHandle(th)
                    else:
                        cont = DBG_CONTINUE   # not our single-step; pass it through

                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED

            elif evt == LOAD_DLL_DEBUG_EVENT:
                info = de.u.LoadDll
                if info.hFile:
                    kernel32.CloseHandle(info.hFile)
                # Retry any APIs not yet hooked (DLL might just have been loaded)
                if self._deferred:
                    self._install_pending()

            elif evt == CREATE_PROCESS_DEBUG_EVENT:
                ci = de.u.CreateProcessInfo
                if ci.hFile:    kernel32.CloseHandle(ci.hFile)
                if ci.hProcess: kernel32.CloseHandle(ci.hProcess)
                if ci.hThread:  kernel32.CloseHandle(ci.hThread)

            elif evt == CREATE_THREAD_DEBUG_EVENT:
                if de.u.CreateThread.hThread:
                    kernel32.CloseHandle(de.u.CreateThread.hThread)

            elif evt == EXIT_PROCESS_DEBUG_EVENT:
                kernel32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)
                self._running = False
                return

            kernel32.ContinueDebugEvent(pid, tid, cont)

    # ── Public interface ───────────────────────────────────────────────────────

    def start(self):
        """
        Prepare resources and launch the debug loop in a background thread.
        DebugActiveProcess is called INSIDE the thread (same thread as WaitForDebugEvent).
        Windows requires both calls to originate from the same OS thread.
        """
        _enable_sedebug()   # best-effort; proceeds even if privilege elevation fails

        self._ph = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False, self.pid,
        )
        if not self._ph:
            err = ctypes.get_last_error()
            raise OSError(f"OpenProcess({self.pid}) failed (error {err})")

        # VirtualAlloc guarantees >= 4096-byte alignment, satisfying CONTEXT's
        # requirement that FltSave (XMM_SAVE_AREA32) lands on a 16-byte boundary.
        self._ctx_buf = kernel32.VirtualAlloc(
            None, ctypes.sizeof(CONTEXT),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        )
        if not self._ctx_buf:
            kernel32.CloseHandle(self._ph)
            raise OSError("VirtualAlloc for CONTEXT failed")

        self._running = True
        self._thread  = threading.Thread(target=self._debug_loop, daemon=True,
                                         name=f"api-hooker-{self.pid}")
        self._thread.start()

    def stop(self):
        """Signal the debug loop to stop and release resources."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self._ctx_buf:
            kernel32.VirtualFree(ctypes.c_void_p(self._ctx_buf), 0, MEM_RELEASE)
            self._ctx_buf = None
        if self._ph:
            kernel32.CloseHandle(self._ph)
            self._ph = None
