import tkinter as tk
import tkinter.simpledialog as simpledialog
import time
import psutil
import threading
import ctypes
import struct
import json
import os
from ctypes import wintypes

from pymem import Pymem
from pymem.process import module_from_name

# =========================
# Logger
# =========================

class Logger:
    def __init__(self, capacity=500):
        self.capacity = capacity
        self.lines = []
        self._lock = threading.Lock()
        self.ui_widget = None

    def set_widget(self, widget):
        self.ui_widget = widget

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        with self._lock:
            self.lines.append(line)
            if len(self.lines) > self.capacity:
                self.lines.pop(0)
        print(line)
        if self.ui_widget:
            try:
                self.ui_widget.configure(state="normal")
                self.ui_widget.insert(tk.END, line + "\n")
                self.ui_widget.see(tk.END)
                self.ui_widget.configure(state="disabled")
            except Exception:
                pass

    def export(self, path="trainer_log.txt"):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.lines))
            self.log(f"[Log] Exported to {path}")
        except Exception as e:
            self.log(f"[Log] Export failed: {e}")

LOG = Logger()

# =========================
# Config and signatures
# =========================

class TrainerConfig:
    def __init__(self):
        self._mode = "standard"
        self._labels = {
            "hp": "Set HP",
            "run_speed": "Set Run Speed",
            "attack_speed": "Set Attack Speed",
            "dodge": "Set Dodge (Dex)",
            "damage_patch_on": "Enable Damage Patch",
            "damage_patch_off": "Disable Damage Patch",
            "scan": "Scan Offsets",
        }
        self._titles = {"standard": "System Control Panel"}
        self.rescan_interval_secs = 60

    def mode(self):
        return self._mode

    def labels(self):
        return self._labels

    def window_title(self):
        return self._titles[self._mode]

DEFAULT_SIGNATURES = {
    "player_health_sig": "A1 ?? ?? ?? ?? 89 45 ?? 8B 45 ??",
    "run_speed_data_sig": "?? ?? ?? ?? ?? ?? ?? ??",
    "attack_speed_sig":   "?? ?? ?? ?? ?? ?? ?? ??",
    "dex_data_sig":       "?? ?? ?? ?? ?? ?? ?? ??",
    "damage_calc_sig":    "55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ??",
}

def load_signatures():
    fname = "signatures.json"
    sigs = dict(DEFAULT_SIGNATURES)
    if os.path.exists(fname):
        try:
            with open(fname, "r", encoding="utf-8") as f:
                external = json.load(f)
            for k, v in external.items():
                if isinstance(v, str) and v.strip():
                    sigs[k] = v
            LOG.log("[Core] Loaded signatures.json overrides")
        except Exception as e:
            LOG.log(f"[Core] signatures.json load failed: {e}")
    return sigs

# =========================
# Enable debug privilege
# =========================

def enable_debug_privilege():
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        SE_DEBUG_NAME = "SeDebugPrivilege"
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x8
        SE_PRIVILEGE_ENABLED = 0x2

        hProcess = kernel32.GetCurrentProcess()
        hToken = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
            LOG.log("[Core] OpenProcessToken failed")
            return False

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            LOG.log("[Core] LookupPrivilegeValueW failed")
            kernel32.CloseHandle(hToken)
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None):
            LOG.log("[Core] AdjustTokenPrivileges failed")
            kernel32.CloseHandle(hToken)
            return False

        kernel32.CloseHandle(hToken)
        LOG.log("[Core] SeDebugPrivilege enabled")
        return True
    except Exception as e:
        LOG.log(f"[Core] Debug privilege error: {e}")
        return False

# =========================
# Memory helpers
# =========================

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000

class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def iter_committed_regions(pm):
    kernel32 = ctypes.windll.kernel32
    mbi = MEMORY_BASIC_INFORMATION32()
    addr = 0
    max_addr = 0x7FFF0000
    while addr < max_addr:
        res = kernel32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not res:
            addr += 0x1000
            continue
        if mbi.State == MEM_COMMIT and mbi.RegionSize and (mbi.Protect in (PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)):
            yield int(mbi.BaseAddress), int(mbi.RegionSize)
        next_addr = int(mbi.BaseAddress) + int(mbi.RegionSize)
        addr = next_addr if next_addr > addr else addr + 0x1000

def find_pe_base_via_scan(pm):
    for base, size in iter_committed_regions(pm):
        try:
            if pm.read_bytes(base, 2) != b'MZ':
                continue
            e_lfanew = struct.unpack("<I", pm.read_bytes(base + 0x3C, 4))[0]
            if 0 < e_lfanew < 0x1000:
                if pm.read_bytes(base + e_lfanew, 4) == b'PE\x00\x00':
                    return base
        except Exception:
            pass
    return None
# =========================
# Patch manager
# =========================

class PatchManager:
    def __init__(self, memory_editor):
        self.me = memory_editor
        self.backups = {}

    def backup(self, addr, size):
        try:
            original = self.me.pm.read_bytes(addr, size)
            self.backups[addr] = original
            LOG.log(f"[Patch] Backed up {size} bytes at {hex(addr)}")
            return original
        except Exception as e:
            LOG.log(f"[Patch] Backup failed at {hex(addr)}: {e}")
            return None

    def apply(self, addr, patch_bytes):
        size = len(patch_bytes)
        if addr not in self.backups:
            self.backup(addr, size)
        try:
            self.me.pm.write_bytes(addr, patch_bytes, size)
            LOG.log(f"[Patch] Applied {size} bytes at {hex(addr)}")
            return True
        except Exception as e:
            LOG.log(f"[Patch] Apply failed at {hex(addr)}: {e}")
            return False

    def restore(self, addr):
        original = self.backups.get(addr)
        if not original:
            LOG.log(f"[Patch] No backup for {hex(addr)}")
            return False
        try:
            self.me.pm.write_bytes(addr, original, len(original))
            LOG.log(f"[Patch] Restored original {len(original)} bytes at {hex(addr)}")
            return True
        except Exception as e:
            LOG.log(f"[Patch] Restore failed at {hex(addr)}: {e}")
            return False

    def stealth_apply(self, addr, patch_bytes, work_fn, restore_delay_ms=30):
        size = len(patch_bytes)
        original = self.backups.get(addr) or self.backup(addr, size)
        if original is None:
            return False
        try:
            self.me.pm.write_bytes(addr, patch_bytes, size)
            try:
                work_fn()
            finally:
                time.sleep(restore_delay_ms / 1000.0)
                self.me.pm.write_bytes(addr, original, len(original))
            LOG.log(f"[Patch] Stealth patch cycle completed at {hex(addr)}")
            return True
        except Exception as e:
            LOG.log(f"[Patch] Stealth apply failed at {hex(addr)}: {e}")
            try:
                self.me.pm.write_bytes(addr, original, len(original))
            except Exception:
                pass
            return False

# =========================
# Memory Editor
# =========================

class MemoryEditor:
    def __init__(self):
        self.pm = None
        self.base = None
        self.pid = None
        self._stop_loop = False
        self._name_loop_stop = False

    def attach_by_pid(self, pid, retries=8, interval=0.8):
        try:
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
                pexe = proc.exe() or ""
                LOG.log(f"[Core] Target PID {pid}, name={pname}, exe={pexe}")
            except Exception as e:
                LOG.log(f"[Core] Process info unavailable: {e}")
                pname, pexe = None, ""

            enable_debug_privilege()

            pm = Pymem()
            pm.open_process_from_id(pid)
            self.pm = pm
            self.pid = pid

            mods = []
            for _ in range(retries):
                try:
                    mods = list(pm.list_modules())
                except Exception:
                    mods = []
                if mods:
                    break
                time.sleep(interval)

            if mods:
                self.base = mods[0].lpBaseOfDll
                LOG.log(f"[Core] Attached at {hex(self.base)}")
                return True

            if pname:
                try:
                    module = module_from_name(pm.process_handle, pname)
                    if module:
                        self.base = module.lpBaseOfDll
                        LOG.log(f"[Core] Attached via fallback at {hex(self.base)}")
                        return True
                except Exception:
                    pass

            base_addr = find_pe_base_via_scan(pm)
            if base_addr:
                self.base = base_addr
                LOG.log(f"[Core] Attached via PE-scan fallback at {hex(self.base)}")
                return True

            LOG.log("[Core] No modules found after retries and fallbacks.")
            return False

        except Exception as e:
            LOG.log(f"[Core] Attach error: {e}")
            return False

    def is_alive(self):
        try:
            return bool(self.pid) and psutil.Process(self.pid).is_running()
        except Exception:
            return False

    def start_auto_attach(self, pid, interval=2.0):
        self.pid = pid
        self._stop_loop = False
        def loop():
            while not self._stop_loop:
                if not self.pm or not self.base or not self.is_alive():
                    if self.attach_by_pid(self.pid, retries=5, interval=0.5):
                        LOG.log("[Core] Auto-attach successful")
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()

    def stop_auto_attach(self):
        self._stop_loop = True

    def start_name_tracker(self, process_name, poll_interval=1.5, attach_retries=6):
        self._name_loop_stop = False
        def find_pid_by_name(name):
            name_lower = name.lower()
            for p in psutil.process_iter(['pid', 'name']):
                n = (p.info.get('name') or '').lower()
                if n == name_lower:
                    return p.info['pid']
            return None
        def loop():
            last_pid = None
            while not self._name_loop_stop:
                pid = find_pid_by_name(process_name)
                if pid and pid != last_pid:
                    LOG.log(f"[Core] Found {process_name} at PID {pid}, attaching...")
                    if self.attach_by_pid(pid, retries=attach_retries, interval=0.5):
                        LOG.log("[Core] Name-tracker attach successful")
                        last_pid = pid
                elif not pid:
                    last_pid = None
                time.sleep(poll_interval)
        threading.Thread(target=loop, daemon=True).start()

    def stop_name_tracker(self):
        self._name_loop_stop = True

    def attach_by_window_title(self, title_substring, retries=20, interval=0.5):
        target = title_substring.lower()
        @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        def enum_proc(hwnd, lParam):
            if not ctypes.windll.user32.IsWindowVisible(hwnd):
                return True
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
            if target in title.lower():
                pid = wintypes.DWORD()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                lParam.append(pid.value)
                return False
            return True
        for _ in range(retries):
            pids = []
            ctypes.windll.user32.EnumWindows(enum_proc, pids)
            if pids:
                LOG.log(f"[Core] Found window '{title_substring}' -> PID {pids[0]}")
                return self.attach_by_pid(pids[0], retries=8, interval=interval)
            time.sleep(interval)
        LOG.log(f"[Core] Window '{title_substring}' not found")
        return False

    def wait_for_module_and_attach(self, process_name, module_substring, poll_interval=0.7, attach_retries=6):
        module_sub = module_substring.lower()
        def find_pid_by_name(name):
            name_lower = name.lower()
            for p in psutil.process_iter(['pid', 'name']):
                n = (p.info.get('name') or '').lower()
                if n == name_lower:
                    return p.info['pid']
            return None
        while True:
            pid = find_pid_by_name(process_name)
            if pid:
                LOG.log(f"[Core] Found {process_name} PID {pid}, attaching...")
                if not self.attach_by_pid(pid, retries=attach_retries, interval=0.5):
                    LOG.log("[Core] Attach failed; retrying...")
                    time.sleep(poll_interval)
                    continue
                for _ in range(30):
                    try:
                        mods = list(self.pm.list_modules())
                        if any(module_sub in (m.name or "").lower() for m in mods):
                            LOG.log(f"[Core] Module '{module_substring}' present — ready.")
                            return True
                    except Exception:
                        pass
                    time.sleep(poll_interval)
                LOG.log(f"[Core] Module '{module_substring}' not loaded yet; retrying...")
            time.sleep(poll_interval)
# =========================
# Signature store
# =========================

class SignatureStore:
    def __init__(self, path="signatures.json"):
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                LOG.log(f"[SigStore] Loaded {len(self.data)} entries from {self.path}")
            except Exception as e:
                LOG.log(f"[SigStore] Load failed: {e}")
                self.data = {}
        else:
            self.data = {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            LOG.log(f"[SigStore] Saved {len(self.data)} entries to {self.path}")
        except Exception as e:
            LOG.log(f"[SigStore] Save failed: {e}")

    def update_sig(self, key, value):
        self.data[key] = value
        self.save()

    def update_chain(self, name, base_sig, offsets, ptr_size=4):
        if "_chains" not in self.data:
            self.data["_chains"] = {}
        self.data["_chains"][name] = {
            "base_sig": base_sig,
            "offsets": offsets,
            "ptr_size": ptr_size
        }
        self.save()

# =========================
# Offset scanner (wildcard‑friendly)
# =========================

class OffsetScanner:
    def __init__(self, memory_editor, signatures=None, rescan_interval_secs=60, sig_store=None):
        self.me = memory_editor
        self.sigs = signatures or {}
        self.results = {}
        self.last_scan = 0
        self.rescan_interval = rescan_interval_secs
        self.staleness_threshold = 300
        self.sig_store = sig_store

    def refresh_bindings(self, me):
        self.me = me

    # Helper: convert "A1 ?? ??" → b"\xA1.." for regex scan
    def sig_to_regex_bytes(self, sig_str):
        tokens = sig_str.strip().split()
        regex_bytes = b""
        for tok in tokens:
            if tok == "??":
                regex_bytes += b"."  # wildcard for any byte
            else:
                regex_bytes += bytes.fromhex(tok)
        return regex_bytes

    def module_scan(self, pattern, max_hits=1):
        if not self.me or not self.me.pm or not self.me.base:
            LOG.log("[Scanner] Not attached")
            return []
        try:
            if isinstance(pattern, str):
                pattern = self.sig_to_regex_bytes(pattern)
            hits = self.me.pm.pattern_scan_all(pattern, return_multiple=True)
            if hits and max_hits:
                return hits[:max_hits]
            return hits
        except Exception as e:
            LOG.log(f"[Scanner] Scan failed: {e}")
            return []

    def scan_offsets(self):
        if not self.me or not self.me.pm or not self.me.base:
            LOG.log("[Scanner] Not attached")
            return
        LOG.log("[Scanner] Scanning offsets...")
        self.results.clear()

        # Scan normal signatures
        for key, sig in self.sigs.items():
            if key == "_chains":
                continue
            if not isinstance(sig, str) or not sig.strip():
                continue
            try:
                pattern_bytes = self.sig_to_regex_bytes(sig)
                hits = self.me.pm.pattern_scan_all(pattern_bytes, return_multiple=True)
                if hits:
                    self.results[key] = hits[0]
                    LOG.log(f"[Scanner] {key} -> {hex(hits[0])}")
                    if self.sig_store:
                        self.sig_store.update_sig(key, sig)
                else:
                    LOG.log(f"[Scanner] {key} not found")
            except Exception as e:
                LOG.log(f"[Scanner] {key} scan failed: {e}")

        # Scan pointer chains
        if "_chains" in self.sigs:
            for name, cfg in self.sigs["_chains"].items():
                base_sig = cfg.get("base_sig")
                offsets = cfg.get("offsets", [])
                ptr_size = cfg.get("ptr_size", 4)
                if not base_sig or base_sig not in self.results:
                    continue
                addr = self.results[base_sig]
                try:
                    for off in offsets:
                        if ptr_size == 4:
                            addr = self.me.pm.read_int(addr) + off
                        elif ptr_size == 8:
                            addr = self.me.pm.read_longlong(addr) + off
                        else:
                            raise ValueError(f"Unsupported ptr_size: {ptr_size}")
                    self.results[name] = addr
                    LOG.log(f"[Scanner] Chain {name} -> {hex(addr)}")
                    if self.sig_store:
                        self.sig_store.update_chain(name, base_sig, offsets, ptr_size)
                except Exception as e:
                    LOG.log(f"[Scanner] Chain {name} failed: {e}")

        self.last_scan = time.time()

    def ensure_fresh(self):
        self.refresh_bindings(self.me)
        if not self.me or not self.me.pm or not self.me.base:
            return False
        now = time.time()
        if (now - self.last_scan) > min(self.rescan_interval, self.staleness_threshold):
            LOG.log("[Scanner] Refresh due to staleness — rescanning offsets")
            self.scan_offsets()
        return True
# =========================
# Feature helpers
# =========================

def ensure_attached_and_scanned(me, scanner, attach_retries=5):
    if not me or not me.pm or not me.base or not me.is_alive():
        LOG.log("[Core] Handle invalid — reattaching...")
        if not me.pid:
            LOG.log("[Core] No PID set. Use Attach or Name Tracker.")
            return False
        if not me.attach_by_pid(me.pid, retries=attach_retries, interval=0.5):
            LOG.log("[Core] Reattach failed.")
            return False
        scanner.refresh_bindings(me)
        scanner.scan_offsets()
        return True
    scanner.ensure_fresh()
    return True

# =========================
# Feature classes
# =========================

class FeatureHP:
    def __init__(self, me, scanner, value=500):
        self.me = me
        self.scanner = scanner
        self.value = value
    def set_value(self, v): self.value = v
    def activate(self):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        ptr = self.scanner.results.get("player_health_ptr")
        if not ptr:
            LOG.log("[Module] HP pointer not found. Run scanOffsets().")
            return
        try:
            self.me.pm.write_int(ptr, int(self.value))
            LOG.log(f"[Module] Set HP to {self.value} at {hex(ptr)}")
        except Exception as e:
            LOG.log(f"[Module] HP write failed: {e}")

class FeatureRunSpeed:
    def __init__(self, me, scanner, value=2.5, offset=0):
        self.me = me
        self.scanner = scanner
        self.value = value
        self.offset = offset
    def set_value(self, v): self.value = v
    def activate(self):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        ptr = self.scanner.results.get("player_run_speed_ptr")
        if not ptr:
            LOG.log("[Module] Run speed pointer not found. Run scanOffsets().")
            return
        addr = ptr + self.offset
        try:
            self.me.pm.write_float(addr, float(self.value))
            LOG.log(f"[Module] Set run speed to {self.value} at {hex(addr)}")
        except Exception as e:
            LOG.log(f"[Module] Run speed write failed: {e}")

class FeatureAttackSpeed:
    def __init__(self, me, scanner, value=2.0, offset=0):
        self.me = me
        self.scanner = scanner
        self.value = value
        self.offset = offset
    def set_value(self, v): self.value = v
    def activate(self):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        ptr = self.scanner.results.get("player_attack_speed_ptr")
        if not ptr:
            LOG.log("[Module] Attack speed pointer not found. Run scanOffsets().")
            return
        addr = ptr + self.offset
        try:
            self.me.pm.write_float(addr, float(self.value))
            LOG.log(f"[Module] Set attack speed to {self.value} at {hex(addr)}")
        except Exception as e:
            LOG.log(f"[Module] Attack speed write failed: {e}")

class FeatureDodgeDex:
    def __init__(self, me, scanner, value=50.0, as_int=False):
        self.me = me
        self.scanner = scanner
        self.value = value
        self.as_int = as_int
    def set_value(self, v): self.value = v
    def activate(self):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        ptr = self.scanner.results.get("player_dex_ptr")
        if not ptr:
            LOG.log("[Module] Dex pointer not found. Run scanOffsets().")
            return
        try:
            if self.as_int:
                self.me.pm.write_int(ptr, int(self.value))
            else:
                self.me.pm.write_float(ptr, float(self.value))
            LOG.log(f"[Module] Set dex/dodge driver to {self.value} at {hex(ptr)}")
        except Exception as e:
            LOG.log(f"[Module] Dex write failed: {e}")

class FeatureDamagePatch:
    def __init__(self, me, scanner, patch_len=6):
        self.me = me
        self.scanner = scanner
        self.patch_len = patch_len
        self.patch_mgr = PatchManager(me)
        self.active_addr = None

    def enable(self):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        addr = self.scanner.results.get("damage_calc_addr")
        if not addr:
            LOG.log("[Module] Damage routine not found. Run scanOffsets().")
            return
        patch = b"\x90" * self.patch_len
        if self.patch_mgr.apply(addr, patch):
            self.active_addr = addr
            LOG.log(f"[Module] Damage patch enabled at {hex(addr)}")

    def disable(self):
        if self.active_addr is None:
            LOG.log("[Module] Damage patch not active")
            return
        if self.patch_mgr.restore(self.active_addr):
            LOG.log(f"[Module] Damage patch disabled at {hex(self.active_addr)}")
            self.active_addr = None

    def stealth_once(self, action=lambda: None):
        if not ensure_attached_and_scanned(self.me, self.scanner):
            return
        addr = self.scanner.results.get("damage_calc_addr")
        if not addr:
            LOG.log("[Module] Damage routine not found. Run scanOffsets().")
            return
        patch = b"\x90" * self.patch_len
        self.patch_mgr.stealth_apply(addr, patch, action, restore_delay_ms=30)

# =========================
# Buff tracker scaffold
# =========================

class BuffTracker:
    def __init__(self, me, scanner):
        self.me = me
        self.scanner = scanner
        self.buff_addrs = {}

    def register(self, name, sig_key, offset=0):
        sig = self.scanner.sigs.get(sig_key)
        if not sig or not sig.strip("? ").strip():
            LOG.log(f"[Buff] Signature empty for {name}")
            return
        hits = self.scanner.module_scan(sig, max_hits=1)
        if hits:
            addr = hits[0] + offset
            self.buff_addrs[name] = addr
            LOG.log(f"[Buff] {name} at {hex(addr)}")
        else:
            LOG.log(f"[Buff] {name} not found")

    def write_float(self, name, value):
        addr = self.buff_addrs.get(name)
        if not addr:
            LOG.log(f"[Buff] Address not registered for {name}")
            return
        try:
            self.me.pm.write_float(addr, float(value))
            LOG.log(f"[Buff] Wrote {value} to {name} at {hex(addr)}")
        except Exception as e:
            LOG.log(f"[Buff] Write failed for {name}: {e}")
# =========================
# Interpreter
# =========================

class WickedInterpreter:
    def __init__(self, modules, scanner, memory_editor):
        self.modules = modules
        self.scanner = scanner
        self.me = memory_editor

    def execute(self, command):
        cmd = command.strip()
        if cmd == "scanOffsets()":
            self.scanner.refresh_bindings(self.me)
            self.scanner.scan_offsets()
            return
        if cmd.startswith("activate("):
            try:
                name = cmd.split('"')[1]
            except Exception:
                LOG.log("[Interpreter] Invalid activate() syntax")
                return
            mod = self.modules.get(name)
            if mod:
                mod.activate()
            else:
                LOG.log(f"[Interpreter] Feature not found: {name}")
            return
        if cmd.startswith("set("):
            try:
                inside = cmd[4:-1]
                key, val = [x.strip() for x in inside.split(",", 1)]
                key = key.strip('"').strip("'")
                val = float(val) if "." in val else int(val)
            except Exception:
                LOG.log("[Interpreter] Invalid set() syntax")
                return
            mod = self.modules.get(key)
            if hasattr(mod, "set_value"):
                mod.set_value(val)
                LOG.log(f"[Interpreter] Set {key} target to {val}")
            else:
                LOG.log(f"[Interpreter] Unknown feature for set(): {key}")
            return
        if cmd:
            LOG.log(f"[Interpreter] Unknown command: {cmd}")

# =========================
# Tkinter dashboard UI (Part 1)
# =========================

def launch_dashboard(config, interpreter, memory_editor, scanner, modules):
    root = tk.Tk()
    root.title(config.window_title())
    root.geometry("900x820")
    root.configure(bg="#121212")

    status_var = tk.StringVar(value="Status: Idle")

    # Log view
    log_frame = tk.Frame(root, bg="#121212")
    log_frame.pack(fill="both", expand=False, pady=6)
    tk.Label(log_frame, text="Log", fg="white", bg="#121212", font=("Consolas", 12)).pack(anchor="w")
    log_text = tk.Text(log_frame, height=10, width=110, state="disabled", bg="#0E0E0E", fg="#C7F0D8")
    log_text.pack(fill="x", padx=6)
    LOG.set_widget(log_text)

    def export_log():
        LOG.export("trainer_log.txt")

    tk.Button(log_frame, text="Export Log", command=export_log).pack(anchor="e", padx=6, pady=4)

    # Attach controls
    attach_frame = tk.Frame(root, bg="#121212")
    attach_frame.pack(pady=6, fill="x")

    def attach_prompt():
        pid_str = simpledialog.askstring("Attach", "Enter PID:")
        if not pid_str or not pid_str.isdigit():
            return
        pid = int(pid_str)
        status_var.set(f"Status: Attaching to PID {pid}...")
        root.update_idletasks()
        ok = memory_editor.attach_by_pid(pid, retries=8, interval=0.6)
        if ok:
            scanner.refresh_bindings(memory_editor)
            status_var.set(f"Status: Attached at {hex(memory_editor.base)}")
            interpreter.execute("scanOffsets()")
        else:
            status_var.set("Status: Attach failed")

    def start_name_track():
        pname = simpledialog.askstring("Track by name", "Enter process name (e.g., Game.exe):")
        if not pname:
            return
        memory_editor.start_name_tracker(pname, poll_interval=1.2, attach_retries=6)
        status_var.set(f"Status: Tracking {pname}...")

    def stop_name_track():
        memory_editor.stop_name_tracker()
        status_var.set("Status: Name tracking stopped")

    def attach_by_title():
        title = simpledialog.askstring("Attach by Window Title", "Enter window title substring:")
        if not title:
            return
        ok = memory_editor.attach_by_window_title(title, retries=30, interval=0.5)
        if ok:
            scanner.refresh_bindings(memory_editor)
            status_var.set(f"Status: Attached at {hex(memory_editor.base)}")
            interpreter.execute("scanOffsets()")
        else:
            status_var.set("Status: Attach by title failed")

    def wait_module_attach():
        pname = simpledialog.askstring("Wait for Module", "Process name (e.g., Game.exe):")
        msub = simpledialog.askstring("Wait for Module", "Module substring (e.g., game.dll):")
        if not pname or not msub:
            return
        threading.Thread(target=lambda: (
            memory_editor.wait_for_module_and_attach(pname, msub) and interpreter.execute("scanOffsets()")
        ), daemon=True).start()
        status_var.set(f"Status: Waiting for {pname} + module '{msub}'...")

    def reload_sigs():
        new_sigs = load_signatures()
        scanner.sigs = new_sigs
        LOG.log("[UI] signatures.json reloaded")
        interpreter.execute("scanOffsets()")

    def save_current_sigs():
        if not hasattr(scanner, "sig_store") or not scanner.sig_store:
            LOG.log("[UI] No SignatureStore attached")
            return
        for key, val in scanner.sigs.items():
            if isinstance(val, str) and val.strip():
                scanner.sig_store.update_sig(key, val)
        if "_chains" in scanner.sigs:
            for name, cfg in scanner.sigs["_chains"].items():
                scanner.sig_store.update_chain(
                    name,
                    cfg.get("base_sig", ""),
                    cfg.get("offsets", []),
                    cfg.get("ptr_size", 4)
                )
        LOG.log("[UI] Current signatures saved to JSON")

    tk.Button(attach_frame, text="Attach by PID", width=18, command=attach_prompt).grid(row=0, column=0, padx=6, pady=4)
    tk.Button(attach_frame, text="Track by Name", width=18, command=start_name_track).grid(row=0, column=1, padx=6, pady=4)
    tk.Button(attach_frame, text="Stop Tracking", width=18, command=stop_name_track).grid(row=0, column=2, padx=6, pady=4)
    tk.Button(attach_frame, text=config.labels()["scan"], width=18, command=lambda: interpreter.execute("scanOffsets()")).grid(row=0, column=3, padx=6, pady=4)
    tk.Button(attach_frame, text="Attach by Title", width=18, command=attach_by_title).grid(row=1, column=0, padx=6, pady=4)
    tk.Button(attach_frame, text="Wait for Module", width=18, command=wait_module_attach).grid(row=1, column=1, padx=6, pady=4)
    tk.Button(attach_frame, text="Reload Signatures", width=18, command=reload_sigs).grid(row=1, column=2, padx=6, pady=4)
    tk.Button(attach_frame, text="Save Current Sigs", width=18, command=save_current_sigs).grid(row=1, column=3, padx=6, pady=4)
    # Periodic rescan control
    def adjust_rescan():
        secs_str = simpledialog.askstring("Periodic Rescan", "Rescan interval (seconds):", initialvalue=str(config.rescan_interval_secs))
        if not secs_str:
            return
        try:
            secs = int(secs_str)
            config.rescan_interval_secs = max(5, secs)
            scanner.rescan_interval = config.rescan_interval_secs
            LOG.log(f"[UI] Rescan interval set to {scanner.rescan_interval}s")
        except Exception:
            LOG.log("[UI] Invalid interval")

    tk.Button(attach_frame, text="Rescan Interval", width=18, command=adjust_rescan).grid(row=2, column=0, padx=6, pady=4)

    # Status label
    tk.Label(root, textvariable=status_var, fg="#9EE37D", bg="#121212", font=("Consolas", 11)).pack(pady=6)

    # Value controls
    controls = tk.Frame(root, bg="#121212")
    controls.pack(pady=8)

    def add_value_row(label, default, setter):
        row = tk.Frame(controls, bg="#121212")
        row.pack(pady=4)
        tk.Label(row, text=label, fg="#CCCCCC", bg="#121212", width=18, anchor="w").pack(side="left")
        var = tk.StringVar(value=str(default))
        entry = tk.Entry(row, textvariable=var, width=10)
        entry.pack(side="left", padx=6)
        def apply():
            try:
                vtxt = var.get().strip()
                val = float(vtxt) if "." in vtxt else int(vtxt)
                setter(val)
                LOG.log(f"[UI] {label} set to {val}")
            except Exception:
                LOG.log(f"[UI] Invalid value for {label}")
        tk.Button(row, text="Apply", width=10, command=apply).pack(side="left", padx=6)

    add_value_row("HP", modules["hp"].value, modules["hp"].set_value)
    add_value_row("Run Speed", modules["run_speed"].value, modules["run_speed"].set_value)
    add_value_row("Attack Speed", modules["attack_speed"].value, modules["attack_speed"].set_value)
    add_value_row("Dex (Dodge)", modules["dodge"].value, modules["dodge"].set_value)

    # Feature buttons
    btns = tk.Frame(root, bg="#121212")
    btns.pack(pady=10)
    labels = config.labels()
    tk.Button(btns, text=labels["hp"], width=22, command=lambda: interpreter.execute('activate("hp")')).grid(row=0, column=0, padx=6, pady=6)
    tk.Button(btns, text=labels["run_speed"], width=22, command=lambda: interpreter.execute('activate("run_speed")')).grid(row=0, column=1, padx=6, pady=6)
    tk.Button(btns, text=labels["attack_speed"], width=22, command=lambda: interpreter.execute('activate("attack_speed")')).grid(row=1, column=0, padx=6, pady=6)
    tk.Button(btns, text=labels["dodge"], width=22, command=lambda: interpreter.execute('activate("dodge")')).grid(row=1, column=1, padx=6, pady=6)

    # Damage patch toggles
    patch_frame = tk.Frame(root, bg="#121212")
    patch_frame.pack(pady=10)
    tk.Label(patch_frame, text="Damage Patch", fg="#CCCCCC", bg="#121212").grid(row=0, column=0, padx=6)
    tk.Button(patch_frame, text=labels["damage_patch_on"], width=22, command=modules["damage_patch"].enable).grid(row=0, column=1, padx=6)
    tk.Button(patch_frame, text=labels["damage_patch_off"], width=22, command=modules["damage_patch"].disable).grid(row=0, column=2, padx=6)
    tk.Button(patch_frame, text="Stealth Damage Once", width=22, command=modules["damage_patch"].stealth_once).grid(row=0, column=3, padx=6)

    # Hotkeys
    def bind_hotkeys():
        root.bind_all("<F5>", lambda e: interpreter.execute('activate("hp")'))
        root.bind_all("<F6>", lambda e: interpreter.execute('activate("run_speed")'))
        root.bind_all("<F7>", lambda e: interpreter.execute('activate("attack_speed")'))
        root.bind_all("<F8>", lambda e: interpreter.execute('activate("dodge")'))
        LOG.log("[UI] Hotkeys bound: F5=HP, F6=Run, F7=Atk, F8=Dodge")
    bind_hotkeys()

    # Profiles
    def save_profile():
        data = {
            "hp": modules["hp"].value,
            "run_speed": modules["run_speed"].value,
            "attack_speed": modules["attack_speed"].value,
            "dodge": modules["dodge"].value,
            "rescan_interval": scanner.rescan_interval,
        }
        try:
            with open("profile.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            LOG.log("[Profile] Saved profile.json")
        except Exception as e:
            LOG.log(f"[Profile] Save failed: {e}")

    def load_profile():
        try:
            with open("profile.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            modules["hp"].set_value(data.get("hp", modules["hp"].value))
            modules["run_speed"].set_value(data.get("run_speed", modules["run_speed"].value))
            modules["attack_speed"].set_value(data.get("attack_speed", modules["attack_speed"].value))
            modules["dodge"].set_value(data.get("dodge", modules["dodge"].value))
            scanner.rescan_interval = data.get("rescan_interval", scanner.rescan_interval)
            LOG.log("[Profile] Loaded profile.json")
        except Exception as e:
            LOG.log(f"[Profile] Load failed: {e}")

    tk.Button(attach_frame, text="Save Profile", width=18, command=save_profile).grid(row=2, column=1, padx=6, pady=4)
    tk.Button(attach_frame, text="Load Profile", width=18, command=load_profile).grid(row=2, column=2, padx=6, pady=4)

    # Buff tracker section
    buff_frame = tk.Frame(root, bg="#121212")
    buff_frame.pack(pady=8)
    tk.Label(buff_frame, text="Buff Tracker (stub)", fg="#CCCCCC", bg="#121212").grid(row=0, column=0, padx=6)
    tk.Button(buff_frame, text="Reload Sigs & Scan Buffs", command=reload_sigs).grid(row=0, column=1, padx=6)

    # Script console
    tk.Label(root, text="Console", fg="white", bg="#121212", font=("Consolas", 12)).pack(pady=6)
    script_entry = tk.Text(root, height=8, width=110, bg="#0E0E0E", fg="#DCDCDC")
    script_entry.pack(pady=6)

    def run_script():
        interpreter.execute(script_entry.get("1.0", tk.END))

    tk.Button(root, text="Run", width=20, command=run_script).pack(pady=6)

    root.mainloop()

# =========================
# Main entry point
# =========================

if __name__ == "__main__":
    config = TrainerConfig()
    sig_store = SignatureStore()
    sigs = load_signatures()
    me = MemoryEditor()
    scanner = OffsetScanner(me, signatures=sigs, rescan_interval_secs=config.rescan_interval_secs, sig_store=sig_store)

    mods = {
        "hp": FeatureHP(me, scanner, value=500),
        "run_speed": FeatureRunSpeed(me, scanner, value=2.5),
        "attack_speed": FeatureAttackSpeed(me, scanner, value=2.0),
        "dodge": FeatureDodgeDex(me, scanner, value=50.0, as_int=False),
        "damage_patch": FeatureDamagePatch(me, scanner, patch_len=6),
    }

    buffs = BuffTracker(me, scanner)
    interp = WickedInterpreter(mods, scanner, me)
    LOG.log("[Main] Launching dashboard...")
    launch_dashboard(config, interp, me, scanner, mods)
