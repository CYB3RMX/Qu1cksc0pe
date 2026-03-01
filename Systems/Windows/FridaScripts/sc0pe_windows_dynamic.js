'use strict';

// ─── Low-level read helpers ───────────────────────────────────────────────────

var PTR_SIZE = Process.pointerSize; // 4 on x86, 8 on x64

function safeReadUtf16(p) {
    try { return p.isNull() ? '' : (p.readUtf16String() || ''); } catch (e) { return ''; }
}

function safeReadCStr(p) {
    try { return p.isNull() ? '' : (p.readCString() || ''); } catch (e) { return ''; }
}

function safeReadUtf8(p) {
    try { return p.isNull() ? '' : (p.readUtf8String() || ''); } catch (e) { return ''; }
}

function safeReadBytes(p, len) {
    try {
        if (p.isNull() || len <= 0) return '';
        var n   = Math.min(len, 512);
        var buf = p.readByteArray(n);
        if (!buf) return '';
        var u8  = new Uint8Array(buf);
        var hex = Array.from(u8, function(b) {
            return ('0' + b.toString(16)).slice(-2);
        }).join(' ');
        // Also try to get printable ASCII representation
        var ascii = Array.from(u8, function(b) {
            return (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.';
        }).join('');
        return 'hex[' + hex.slice(0, 96) + (hex.length > 96 ? '..' : '') + '] ascii[' + ascii.slice(0, 48) + ']';
    } catch (e) { return ''; }
}

// ─── sockaddr struct parser ───────────────────────────────────────────────────

function readSockAddr(p) {
    try {
        if (p.isNull()) return '';
        var family = p.readU16();
        if (family === 2) {                       // AF_INET
            var portBE = p.add(2).readU16();
            var port   = ((portBE & 0xFF) << 8) | ((portBE >> 8) & 0xFF);
            var ip     = [p.add(4).readU8(), p.add(5).readU8(),
                          p.add(6).readU8(), p.add(7).readU8()].join('.');
            return ip + ':' + port;
        }
        if (family === 23) {                      // AF_INET6
            var p6BE = p.add(2).readU16();
            var p6   = ((p6BE & 0xFF) << 8) | ((p6BE >> 8) & 0xFF);
            return '[IPv6]:' + p6;
        }
        return 'family:' + family;
    } catch (e) { return 'sockaddr_err:' + e.message; }
}

// ─── OBJECT_ATTRIBUTES filename extractor (NtOpenFile / ZwCreateFile) ────────

function readObjectAttrName(oa) {
    try {
        if (oa.isNull()) return '';
        // OBJECT_ATTRIBUTES layout (x64): Length(4)+pad(4)+RootDir(8)+ObjectName(8)+...
        // OBJECT_ATTRIBUTES layout (x86): Length(4)+RootDir(4)+ObjectName(4)+...
        var objectNameOffset = PTR_SIZE === 8 ? 16 : 8;
        var uniStrPtr = oa.add(objectNameOffset).readPointer();
        if (uniStrPtr.isNull()) return '';
        // UNICODE_STRING: Length(2)+MaxLength(2)+[pad(4) on x64]+Buffer(ptr)
        var bufOffset = PTR_SIZE === 8 ? 8 : 4;
        var bufPtr = uniStrPtr.add(bufOffset).readPointer();
        return safeReadUtf16(bufPtr);
    } catch (e) { return ''; }
}

// ─── Virtual key code → name ──────────────────────────────────────────────────

var VK_NAMES = {
    0x08:'BACKSPACE', 0x09:'TAB',       0x0D:'ENTER',   0x10:'SHIFT',
    0x11:'CTRL',      0x12:'ALT',       0x14:'CAPSLOCK', 0x1B:'ESC',
    0x20:'SPACE',     0x21:'PGUP',      0x22:'PGDN',    0x23:'END',
    0x24:'HOME',      0x25:'LEFT',      0x26:'UP',      0x27:'RIGHT',
    0x28:'DOWN',      0x2C:'PRTSC',     0x2D:'INSERT',  0x2E:'DELETE',
    0x5B:'LWIN',      0x5C:'RWIN',      0x5D:'APPS',
    0x70:'F1',  0x71:'F2',  0x72:'F3',  0x73:'F4',
    0x74:'F5',  0x75:'F6',  0x76:'F7',  0x77:'F8',
    0x78:'F9',  0x79:'F10', 0x7A:'F11', 0x7B:'F12',
};

function vkName(code) {
    if (VK_NAMES[code])            return VK_NAMES[code];
    if (code >= 0x30 && code <= 0x39) return String.fromCharCode(code);
    if (code >= 0x41 && code <= 0x5A) return String.fromCharCode(code);
    if (code >= 0x60 && code <= 0x69) return 'NUM' + (code - 0x60);
    if (code >= 0xA0 && code <= 0xA5) return ['LSHIFT','RSHIFT','LCTRL','RCTRL','LALT','RALT'][code-0xA0];
    return '0x' + code.toString(16).toUpperCase();
}

// ─── Windows hook type → name ─────────────────────────────────────────────────

var WH_NAMES = {
    0:'WH_MSGFILTER',  1:'WH_JOURNALRECORD', 2:'WH_JOURNALPLAYBACK',
    3:'WH_KEYBOARD',   4:'WH_GETMESSAGE',    5:'WH_CALLWNDPROC',
    6:'WH_CBT',        7:'WH_SYSMSGFILTER',  8:'WH_MOUSE',
    9:'WH_DEBUG',     10:'WH_SHELL',         11:'WH_FOREGROUNDIDLE',
    12:'WH_CALLWNDPROCRET', 13:'WH_KEYBOARD_LL', 14:'WH_MOUSE_LL',
};

function whName(code) {
    return WH_NAMES[code] || ('WH_UNKNOWN:' + code);
}

// ─── HKEY constant → name ────────────────────────────────────────────────────

function hkeyName(handle) {
    try {
        var v = handle.toUInt32();
        var map = {
            0x80000000:'HKCR', 0x80000001:'HKCU',
            0x80000002:'HKLM', 0x80000003:'HKU',
            0x80000005:'HKCC',
        };
        return map[v] || ('HKEY:0x' + v.toString(16));
    } catch (e) { return 'HKEY:?'; }
}

// ─── Safe send ────────────────────────────────────────────────────────────────

function safeSend(api, args, category) {
    try {
        send({ target_api: api, args: args, category: category || 'general' });
    } catch (e) {}
}

// ─── onEnter handlers per API ─────────────────────────────────────────────────

var ENTER_HANDLERS = {
    // ── Network / Socket ──────────────────────────────────────────────────────
    'connect':    function(a) { return { val: readSockAddr(a[1]),      cat: 'network' }; },
    'WSAConnect': function(a) { return { val: readSockAddr(a[1]),      cat: 'network' }; },
    'sendto':     function(a) { return { val: readSockAddr(a[4]),      cat: 'network' }; },
    'send': function(a) {
        return { val: safeReadBytes(a[1], a[2].toInt32()), cat: 'network' };
    },
    'getaddrinfo': function(a) { return { val: safeReadCStr(a[0]),     cat: 'network' }; },

    // ── WinINet ───────────────────────────────────────────────────────────────
    'InternetOpen':     function(a) { return { val: safeReadCStr(a[0]),   cat: 'network' }; },
    'InternetOpenA':    function(a) { return { val: safeReadCStr(a[0]),   cat: 'network' }; },
    'InternetRead':     function(a) { return { val: safeReadCStr(a[0]),   cat: 'network' }; },

    // ── File (Wide) ───────────────────────────────────────────────────────────
    'CreateFileW': function(a) { return { val: safeReadUtf16(a[0]), cat: 'filesystem' }; },
    'DeleteFileW': function(a) { return { val: safeReadUtf16(a[0]), cat: 'filesystem' }; },
    'MoveFileExW': function(a) {
        return { val: safeReadUtf16(a[0]) + ' -> ' + safeReadUtf16(a[1]), cat: 'filesystem' };
    },
    'CopyFileW': function(a) {
        return { val: safeReadUtf16(a[0]) + ' -> ' + safeReadUtf16(a[1]), cat: 'filesystem' };
    },
    'ZwCreateFile': function(a) { return { val: readObjectAttrName(a[2]), cat: 'filesystem' }; },
    'NtOpenFile':   function(a) { return { val: readObjectAttrName(a[2]), cat: 'filesystem' }; },

    // ── File (ANSI) ───────────────────────────────────────────────────────────
    'CreateFileA': function(a) { return { val: safeReadCStr(a[0]),  cat: 'filesystem' }; },
    'OpenFile':    function(a) { return { val: safeReadCStr(a[0]),  cat: 'filesystem' }; },

    // ── File I/O (handle-based) ───────────────────────────────────────────────
    'WriteFile': function(a) {
        return {
            val: 'handle:0x' + a[0].toString(16) + ' ' + safeReadBytes(a[1], a[2].toInt32()),
            cat: 'filesystem'
        };
    },

    // ── Library loading ───────────────────────────────────────────────────────
    'LoadLibrary':    function(a) { return { val: safeReadCStr(a[0]),   cat: 'library' }; },
    'LoadLibraryA':   function(a) { return { val: safeReadCStr(a[0]),   cat: 'library' }; },
    'LoadLibraryExW': function(a) { return { val: safeReadUtf16(a[0]),  cat: 'library' }; },

    // ── Process creation ──────────────────────────────────────────────────────
    'CreateProcess': function(a) {
        var app = safeReadUtf16(a[0]), cmd = safeReadUtf16(a[1]);
        return { val: (app ? app + ' | ' : '') + cmd, cat: 'process' };
    },
    'CreateProcessA': function(a) {
        var app = safeReadCStr(a[0]), cmd = safeReadCStr(a[1]);
        return { val: (app ? app + ' | ' : '') + cmd, cat: 'process' };
    },
    'CreateProcessW': function(a) {
        var app = safeReadUtf16(a[0]), cmd = safeReadUtf16(a[1]);
        return { val: (app ? app + ' | ' : '') + cmd, cat: 'process' };
    },

    // ── Shell execution ───────────────────────────────────────────────────────
    'ShellExecute': function(a) {
        // ANSI: hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShow
        return {
            val: safeReadCStr(a[1]) + ' | ' + safeReadCStr(a[2]) + ' | ' + safeReadCStr(a[3]),
            cat: 'process'
        };
    },
    'ShellExecuteW': function(a) {
        return {
            val: safeReadUtf16(a[1]) + ' | ' + safeReadUtf16(a[2]) + ' | ' + safeReadUtf16(a[3]),
            cat: 'process'
        };
    },

    // ── Registry ──────────────────────────────────────────────────────────────
    'RegOpenKeyExA':         function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadCStr(a[1]),   cat: 'registry' }; },
    'RegOpenKeyExW':         function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadUtf16(a[1]), cat: 'registry' }; },
    'RegOpenKeyTransactedA': function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadCStr(a[1]),   cat: 'registry' }; },
    'RegKeyOpen':            function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadUtf16(a[1]), cat: 'registry' }; },
    'RegQueryValueEx':       function(a) { return { val: safeReadUtf16(a[1]),                          cat: 'registry' }; },
    'RegQueryValueExA':      function(a) { return { val: safeReadCStr(a[1]),                           cat: 'registry' }; },
    'RegQueryInfoKeyW':      function(a) { return { val: hkeyName(a[0]),                               cat: 'registry' }; },
    'RegQueryInfoKeyA':      function(a) { return { val: hkeyName(a[0]),                               cat: 'registry' }; },
    'RegSetValue':           function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadUtf16(a[1]), cat: 'registry' }; },
    'RegGetValue':           function(a) { return { val: hkeyName(a[0]) + '\\' + safeReadUtf16(a[1]), cat: 'registry' }; },

    // ── Service control ───────────────────────────────────────────────────────
    'CreateService': function(a) {
        return { val: safeReadUtf16(a[1]) + ' | ' + safeReadUtf16(a[2]), cat: 'service' };
    },
    'StartService':  function(a) { return { val: 'handle:0x' + a[0].toString(16), cat: 'service' }; },
    'StartServiceA': function(a) { return { val: safeReadCStr(a[0]),               cat: 'service' }; },

    // ── Mutex ─────────────────────────────────────────────────────────────────
    'CreateMutex': function(a) { return { val: safeReadUtf16(a[2]), cat: 'sync' }; },

    // ── Anti-analysis (output captured in onLeave) ────────────────────────────
    'IsDebuggerPresent': function(a) { return null; },  // onLeave
    'OutputDebugString': function(a) { return { val: safeReadCStr(a[0]), cat: 'debug' }; },

    // ── Keylogger indicators ──────────────────────────────────────────────────
    'GetAsyncKeyState':    function(a) { return { val: 'vkey:' + vkName(a[0].toInt32()),   cat: 'keylog' }; },
    'GetForegroundWindow': function(a) { return { val: '',                                  cat: 'keylog' }; },
    'GetKeyboardType':     function(a) { return { val: 'nTypeFlag:' + a[0].toInt32(),       cat: 'keylog' }; },

    // ── Hook installation ─────────────────────────────────────────────────────
    'SetWindowsHookEx':  function(a) { return { val: whName(a[0].toInt32()), cat: 'hook' }; },
    'SetWindowsHookExA': function(a) { return { val: whName(a[0].toInt32()), cat: 'hook' }; },
    'SetWindowsHookExW': function(a) { return { val: whName(a[0].toInt32()), cat: 'hook' }; },
};

// ─── onLeave handlers (need return value or output buffer) ────────────────────

var LEAVE_HANDLERS = {
    'IsDebuggerPresent': function(retval, ctx) {
        safeSend('IsDebuggerPresent',
            retval.toInt32() !== 0 ? 'DEBUGGER DETECTED' : 'not_detected',
            'anti_analysis');
    },
    'ReadFile': function(retval, ctx) {
        if (retval.toInt32() !== 0 && ctx.buf && ctx.len) {
            safeSend('ReadFile',
                'handle:0x' + ctx.handle.toString(16) + ' ' + safeReadBytes(ctx.buf, ctx.len.toInt32()),
                'filesystem');
        }
    },
    'InternetReadFile': function(retval, ctx) {
        if (retval.toInt32() !== 0 && ctx.buf && ctx.len) {
            safeSend('InternetReadFile', safeReadBytes(ctx.buf, ctx.len.toInt32()), 'network');
        }
    },
};

// ─── Context savers for onLeave ───────────────────────────────────────────────

var CONTEXT_SAVERS = {
    'ReadFile': function(args, ctx) {
        ctx.handle = args[0];
        ctx.buf    = args[1];
        ctx.len    = args[2];
    },
    'InternetReadFile': function(args, ctx) {
        ctx.buf = args[1];
        ctx.len = args[2];
    },
};

// ─── RPC exports ──────────────────────────────────────────────────────────────

rpc.exports = {
    readBytes: function(address, size) {
        return Memory.readByteArray(ptr(address), size);
    },

    enumerateRanges: function(prot) {
        return Process.enumerateRangesSync({ protection: prot, coalesce: true });
    },

    // Hook a batch of APIs in a single RPC round-trip.
    // Returns { ok: [api, ...], failed: [{api, reason}, ...] }
    hookWindowsApiBatch: function(apiList) {
        var results = { ok: [], failed: [] };

        apiList.forEach(function(api) {
            if (!api || !api.trim()) return;
            try {
                var exportPtr = Module.findExportByName(null, api);
                if (!exportPtr) {
                    results.failed.push({ api: api, reason: 'export_not_found' });
                    return;
                }

                var enterHandler = ENTER_HANDLERS[api];
                var leaveHandler = LEAVE_HANDLERS[api];
                var ctxSaver     = CONTEXT_SAVERS[api];

                Interceptor.attach(exportPtr, {
                    onEnter: function(args) {
                        this._ctx = {};
                        if (ctxSaver) {
                            try { ctxSaver(args, this._ctx); } catch (e) {}
                        }
                        if (enterHandler) {
                            try {
                                var result = enterHandler(args);
                                if (result) safeSend(api, result.val, result.cat);
                            } catch (e) {
                                safeSend(api + '_enter_error', e.message, 'error');
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (leaveHandler) {
                            try { leaveHandler(retval, this._ctx); } catch (e) {}
                        }
                    }
                });

                results.ok.push(api);
            } catch (e) {
                results.failed.push({ api: api, reason: e.message });
            }
        });

        return results;
    },

    // Single-API hook kept for backwards compatibility
    hookWindowsApi: function(api) {
        return this.hookWindowsApiBatch([api]);
    },
};
