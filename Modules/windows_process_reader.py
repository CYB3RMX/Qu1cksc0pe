import ctypes
from ctypes import wintypes, byref

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEMORY_BASIC_INFORMATION = 0x28

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class WindowsProcessReader:
    def __init__(self, target_pid):
        self.target_pid = target_pid

    def get_process_handle(self):
        # Get a handle to the process
        return ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.target_pid)

    def read_memory(self, process_handle, address, size):
        # Read memory from the process
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        result = ctypes.windll.kernel32.ReadProcessMemory(process_handle, address, buffer, size, byref(bytes_read))
        if result == 0:
            return None
        return buffer.raw

    def query_memory(self, process_handle, address):
        # Query memory information of the process
        mbi = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
        if ctypes.windll.kernel32.VirtualQueryEx(process_handle, address, byref(mbi), size) == 0:
            return None
        return mbi

    def dump_memory(self):
        # Dump readable memory regions of the process
        process_handle = self.get_process_handle()
        if not process_handle:
            return False
        try:
            address = 0
            memory_dump = {}

            while True:
                mbi = self.query_memory(process_handle, ctypes.c_void_p(address))
                if not mbi:
                    break

                if (mbi.Protect & 0x04 or mbi.Protect & 0x02) and mbi.State == 0x1000:  # PAGE_READWRITE or PAGE_READONLY
                    data = self.read_memory(process_handle, ctypes.c_void_p(address), mbi.RegionSize)
                    if data:
                        memory_dump[hex(address)] = data

                address += mbi.RegionSize

            # Save memory dump to file
            with open(f"qu1cksc0pe_memory_dump_{self.target_pid}.bin", "wb") as dump_file:
                for region in memory_dump.values():
                    dump_file.write(region)
            return True
        finally:
            ctypes.windll.kernel32.CloseHandle(process_handle)