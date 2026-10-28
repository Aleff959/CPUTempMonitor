import os
import sys
import time
import struct
import ctypes
from ctypes import wintypes
import winreg
import threading
import subprocess
import shutil
import logging
from collections import deque
import psutil

# Win32 / HID Constants & Structures
setupapi = ctypes.windll.setupapi
hid = ctypes.windll.hid
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.c_size_t),
    ]

setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
hid.HidD_SetFeature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG]
hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

kernel32.OpenFileMappingW.restype = ctypes.c_void_p
kernel32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.MapViewOfFile.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]

shell32.ShellExecuteW.restype = ctypes.c_void_p
shell32.ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
shell32.IsUserAnAdmin.restype = wintypes.BOOL

FILE_MAP_READ = 0x0004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class RTSSReader:
    """Reads real-time instantaneous framerate directly from RivaTuner Statistics Server shared memory."""
    def __init__(self):
        self.last_check_launch = 0.0
        self.rtss_path = r"C:\Program Files (x86)\RivaTuner Statistics Server\RTSS.exe"
        self.has_rtss_installed = os.path.exists(self.rtss_path)
        self.auto_launch_rtss = False  # Does not open RTSS hidden without user consent
        self.last_times = {}

    def try_launch_rtss(self):
        if not self.auto_launch_rtss or not self.has_rtss_installed:
            return
        now = time.time()
        if now - self.last_check_launch < 15.0:
            return
        self.last_check_launch = now
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() == "rtss.exe":
                    return
            except Exception:
                pass
        try:
            shell32.ShellExecuteW(None, "open", self.rtss_path, None, os.path.dirname(self.rtss_path), 0)
        except Exception:
            try:
                shell32.ShellExecuteW(None, "runas", self.rtss_path, None, os.path.dirname(self.rtss_path), 0)
            except Exception:
                pass

    def read_fps(self):
        h_map = kernel32.OpenFileMappingW(FILE_MAP_READ, False, "RTSSSharedMemoryV2")
        if not h_map:
            self.try_launch_rtss()
            return 0.0
        try:
            # Map up to 128KB safely
            p_mem = kernel32.MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 131072)
            if not p_mem:
                return 0.0
            try:
                raw_header = ctypes.string_at(p_mem, 64)
                dw_sig, dw_ver, dw_app_entry_size, dw_app_arr_offset, dw_app_arr_size = struct.unpack_from("<5I", raw_header, 0)
                if dw_sig not in (0x53535452, 0x52545353) or dw_ver < 0x00020000:
                    return 0.0

                now = time.time()
                best_fps = 0.0

                # Prevent unbounded dictionary growth
                if len(self.last_times) > 64:
                    self.last_times = {pid: v for pid, v in self.last_times.items() if now - v[2] < 30.0}

                # Validate offset and boundary against mapped size
                if dw_app_arr_offset >= 131072 or dw_app_entry_size < 284:
                    return 0.0

                max_entries = min(dw_app_arr_size, 32)
                for i in range(max_entries):
                    entry_off = dw_app_arr_offset + i * dw_app_entry_size
                    if entry_off + 284 > 131072:
                        break

                    entry_raw = ctypes.string_at(p_mem + entry_off, min(dw_app_entry_size, 512))
                    pid = struct.unpack_from("<I", entry_raw, 0)[0]
                    if pid == 0:
                        continue

                    name_bytes = entry_raw[4:264].split(b'\x00')[0]
                    app_name = name_bytes.decode('latin1', errors='ignore').lower()
                    if "fulgor" in app_name or "openhardware" in app_name:
                        continue

                    flags, t0, t1, frames, frametime = struct.unpack_from("<5I", entry_raw, 264)

                    prev = self.last_times.get(pid)
                    if prev:
                        prev_t1, prev_frames, prev_update = prev
                        if t1 != prev_t1 or frames != prev_frames:
                            self.last_times[pid] = (t1, frames, now)
                        else:
                            if now - prev_update > 2.0:
                                continue
                    else:
                        self.last_times[pid] = (t1, frames, now)

                    fps = 0.0
                    if t1 > t0:
                        fps = 1000.0 * frames / (t1 - t0)
                    elif frametime > 0:
                        fps = 1000000.0 / frametime

                    if fps > 0:
                        best_fps = max(best_fps, fps)

                return round(best_fps, 0)
            finally:
                kernel32.UnmapViewOfFile(p_mem)
        finally:
            kernel32.CloseHandle(h_map)


class PresentMonReader:
    """Fallback ETW-based framerate reader utilizing PresentMon."""
    def __init__(self):
        self.proc = None
        self.thread = None
        self.running = False
        self.failed = False
        self.lock = threading.Lock()
        self.recent_presents = deque(maxlen=500)
        self.last_start_time = 0.0
        self.exe_path = self._find_presentmon()

    def _find_presentmon(self):
        cands = [
            r"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins\Client\PresentMonDataProvider\PresentMon-2.3.1-x64-DLSS4.exe",
            r"C:\Program Files (x86)\RivaTuner Statistics Server\Plugins\Client\PresentMonDataProvider\PresentMon-2.3.1-x64.exe",
            r"C:\Program Files\NVIDIA Corporation\FrameViewSDK\bin\PresentMon_x64.exe",
        ]
        for c in cands:
            if os.path.exists(c):
                return c
        return None

    def start(self):
        now = time.time()
        if not self.exe_path or self.running or self.failed or (now - self.last_start_time < 30.0):
            return
        self.last_start_time = now
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            try:
                subprocess.run(
                    ["logman", "stop", "FulgorPCista_ETW", "-ets"],
                    capture_output=True,
                    timeout=1.0,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception:
                pass

            cmd = [
                self.exe_path,
                "--session_name", "FulgorPCista_ETW",
                "--stop_existing_session",
                "--output_stdout",
                "--exclude", "dwm.exe",
                "--exclude", "explorer.exe",
                "--exclude", "FulgorPCista.exe",
                "--exclude", "OpenHardwareMonitorServer.exe",
                "--exclude", "svchost.exe",
            ]

            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in iter(self.proc.stdout.readline, ''):
                if not self.running:
                    break
                line = line.strip()
                if not line or "," not in line or line.startswith("Application,") or line.startswith("PresentMon") or line.startswith("warning") or line.startswith("error"):
                    continue
                parts = line.split(",")
                if len(parts) < 5:
                    continue
                app_name = parts[0].strip().lower()
                if any(ex in app_name for ex in ["dwm", "explorer", "fulgor", "openhardware", "svchost"]):
                    continue
                now = time.time()
                with self.lock:
                    self.recent_presents.append(now)
                    cutoff = now - 1.2
                    while self.recent_presents and self.recent_presents[0] < cutoff:
                        self.recent_presents.popleft()
        except Exception:
            self.failed = True
        finally:
            self.running = False
            if self.proc:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
                self.proc = None
            try:
                subprocess.run(
                    ["logman", "stop", "FulgorPCista_ETW", "-ets"],
                    capture_output=True,
                    timeout=1.0,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception:
                pass

    def get_fps(self):
        now = time.time()
        with self.lock:
            cutoff = now - 1.2
            while self.recent_presents and self.recent_presents[0] < cutoff:
                self.recent_presents.popleft()
            count = len(self.recent_presents)
            if count == 0 or (now - self.recent_presents[-1] > 1.2):
                return 0.0
            return round(count / 1.2, 0)

    def stop(self):
        self.running = False
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.proc = None
        try:
            subprocess.run(
                ["logman", "stop", "FulgorPCista_ETW", "-ets"],
                capture_output=True,
                timeout=1.0,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass


KNOWN_GAME_EXES = {
    "cyberpunk2077.exe", "witcher3.exe", "gta5.exe", "gtav.exe", "gta_sa.exe",
    "cod.exe", "cod22.exe", "modernwarfare.exe", "warzone.exe", "r5apex.exe",
    "valorant.exe", "fortniteclient-win64-shipping.exe", "overwatch.exe",
    "cs2.exe", "csgo.exe", "dota2.exe", "rdr2.exe", "starfield.exe",
    "eldenring.exe", "bg3.exe", "bg3_dx11.exe", "forzahorizon5.exe",
    "forzahorizon4.exe", "league of legends.exe", "rocketleague.exe", "pubg.exe"
}


class MonitorCore:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()

        # State
        self.stats = {
            "cpu_temp": 0.0,
            "cpu_load": 0.0,
            "cpu_power": 0.0,
            "gpu_temp": 0.0,         # Effective Hot Spot temperature for display & cooler
            "gpu_core_temp": 0.0,    # GPU Core temperature
            "gpu_hotspot": 0.0,      # Explicit Hot Spot temperature
            "gpu_load": 0.0,
            "gpu_power": 0.0,
            "gpu_vram_load": 0.0,    # VRAM usage percentage
            "gpu_vram_used": 0.0,    # VRAM used in MB
            "gpu_vram_total": 0.0,   # VRAM total in MB
            "fps": 0,                # Real-time frames per second
            "mb_temp": 0.0,
            "mb_model": "Placa-Mãe",
            "active_device": "CPU",  # "CPU", "GPU", or "FPS"
            "active_unit": "°C",     # "°C" for CPU, "°F" for GPU / FPS
            "led_switch": 1,
            "cooler_connected": False,
            "auto_switch_fps": 1,    # Auto-switch to FPS mode when entering game
            "in_game": False,        # True when game actively presenting frames
        }

        self.last_user_device = "CPU"
        self.auto_switched = False
        self.game_active_samples = 0
        self.game_idle_samples = 0
        self._last_proc_scan = 0.0
        self._last_game_proc_detected = False

        self.server_proc = None
        self.hid_handle = None
        self.server_dir = self._find_server_dir()
        self.lhm_gpu = None
        self.lhm_comp = None
        self.rtss_reader = RTSSReader()
        self.pmon_reader = PresentMonReader()
        # Note: Do not auto-start PresentMon in __init__ to prevent unnecessary ETW sessions
        self.has_nvidia_smi = (shutil.which("nvidia-smi") is not None)
        self.last_nvidia_check = 0.0
        self.last_lhm_attempt = 0.0

        self._detect_motherboard_model()
        self._init_lhm_gpu()

        # Load persisted preference from registry
        self._load_registry_preferences()

        # Initialize CPU percent baseline
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        # Start background worker (starts server, reads sensors, drives USB HID cooler)
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()

    def _init_lhm_gpu(self):
        """Direct NVAPI GPU initialization via LibreHardwareMonitorLib for Hot Spot telemetry."""
        try:
            candidates = [
                os.path.join(self.server_dir, "LibreHardwareMonitorLib.dll"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "LibreHardwareMonitorLib.dll"),
            ]
            lib_path = None
            for c in candidates:
                if os.path.exists(c):
                    lib_path = c
                    break

            if not lib_path:
                return

            import pythonnet
            try:
                pythonnet.load()
            except Exception:
                pass
            import clr
            clr.AddReference(os.path.abspath(lib_path))
            import LibreHardwareMonitor.Hardware as LHM

            comp = LHM.Computer()
            comp.IsGpuEnabled = True
            comp.Open()

            for hw in comp.Hardware:
                if "gpu" in str(hw.HardwareType).lower():
                    self.lhm_gpu = hw
                    self.lhm_comp = comp
                    break
        except Exception:
            self.lhm_gpu = None
            self.lhm_comp = None

    def _find_server_dir(self):
        candidates = []
        if getattr(sys, "frozen", False):
            exe_dir = os.path.dirname(sys.executable)
            candidates.append(exe_dir)
            candidates.append(os.path.join(exe_dir, "_internal"))
        if hasattr(sys, "_MEIPASS"):
            candidates.append(sys._MEIPASS)
        candidates.append(os.path.dirname(os.path.abspath(__file__)))

        for d in candidates:
            if os.path.exists(os.path.join(d, "OpenHardwareMonitorServer.exe")):
                return d
        return os.path.dirname(os.path.abspath(__file__))

    def _patch_server_binary(self, server_exe):
        """Ensure FindXYCoolerWindow (offset 1849) returns true (0x17) without needing XYWindow."""
        try:
            with open(server_exe, "rb") as f:
                data = bytearray(f.read())
            if len(data) > 1850 and data[1849] == 0x16:
                data[1849] = 0x17
                with open(server_exe, "wb") as f:
                    f.write(data)
        except Exception:
            pass

    def _ensure_internal_server(self):
        # Check if xinyao_hardware_mapfile is already active with valid CPU temperature
        b = self._read_shared_memory()
        if b and len(b) >= 160:
            try:
                cpu_t = struct.unpack_from("<f", b, 152)[0]
                if cpu_t > 0:
                    return
            except Exception:
                pass

        # Stop any leftover non-admin fallback process so the elevated server can take over
        for p in psutil.process_iter(["name"]):
            try:
                pname = (p.info["name"] or "").lower()
                if "openhardwaremonitorserver_user" in pname:
                    p.kill()
                elif "openhardwaremonitorserver" in pname:
                    return
            except Exception:
                pass

        server_exe = os.path.join(self.server_dir, "OpenHardwareMonitorServer.exe")
        if not os.path.exists(server_exe):
            return

        self._patch_server_binary(server_exe)

        # Try direct Popen first (succeeds when running as Administrator)
        try:
            self.server_proc = subprocess.Popen(
                [server_exe],
                cwd=self.server_dir,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return
        except OSError as e:
            # WinError 740: requires elevation
            if getattr(e, "winerror", 0) == 740 and not os.environ.get("CPUTEMP_NO_UAC"):
                try:
                    # Request elevation via ShellExecuteW
                    ret = shell32.ShellExecuteW(None, "runas", server_exe, None, self.server_dir, 0)
                    if ret and int(ret) > 32:
                        return
                except Exception:
                    pass

        # Fallback: create a non-elevated copy (asInvoker) so GPU & CPU load still work via LHM
        try:
            user_exe = os.path.join(os.environ.get("LOCALAPPDATA", self.server_dir), "Temp", "OpenHardwareMonitorServer_user.exe")
            lib_src = os.path.join(self.server_dir, "LibreHardwareMonitorLib.dll")
            lib_dst = os.path.join(os.path.dirname(user_exe), "LibreHardwareMonitorLib.dll")
            if os.path.exists(lib_src):
                if not os.path.exists(lib_dst) or os.path.getsize(lib_src) != os.path.getsize(lib_dst) or os.path.getmtime(lib_src) > os.path.getmtime(lib_dst):
                    shutil.copy2(lib_src, lib_dst)
            with open(server_exe, "rb") as f:
                raw = f.read()
            q = b'"'
            old_s = b"level=" + q + b"requireAdministrator" + q
            new_s = b"level=" + q + b"asInvoker" + q + b"           "
            raw_user = raw.replace(old_s, new_s)
            with open(user_exe, "wb") as f:
                f.write(raw_user)
            self.server_proc = subprocess.Popen(
                [user_exe],
                cwd=os.path.dirname(user_exe),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    def _read_shared_memory(self):
        """Read 1024-byte SYSTEM_INFO from xinyao_hardware_mapfile using OpenFileMappingW."""
        h_map = kernel32.OpenFileMappingW(FILE_MAP_READ, False, "xinyao_hardware_mapfile")
        if not h_map:
            return None
        try:
            ptr = kernel32.MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 1024)
            if not ptr:
                return None
            try:
                data = ctypes.string_at(ptr, 1024)
                return data
            finally:
                kernel32.UnmapViewOfFile(ptr)
        finally:
            kernel32.CloseHandle(h_map)

    def _read_nvidia_fallback(self):
        """Fast fallback for NVIDIA GPU metrics and VRAM while server initializes."""
        if not getattr(self, "has_nvidia_smi", False):
            return None
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,power.draw,memory.used,memory.total", "--format=csv,noheader,nounits"],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=1.5,
                text=True,
            ).strip()
            if out:
                parts = [p.strip() for p in out.splitlines()[0].split(",")]
                if len(parts) >= 3:
                    temp = float(parts[0])
                    load = float(parts[1])
                    pwr = float(parts[2])
                    used_mb = float(parts[3]) if len(parts) >= 4 else 0.0
                    total_mb = float(parts[4]) if len(parts) >= 5 else 0.0
                    vram_load = round((used_mb / total_mb) * 100.0, 1) if total_mb > 0 else 0.0
                    return temp, load, pwr, vram_load, used_mb, total_mb
        except Exception:
            pass
        return None

    def _is_display_collection(self, path):
        """True if the HID collection is the vendor-defined display one (UsagePage 0xFF01, Feature=64)."""
        h = kernel32.CreateFileW(path, 0xC0000000, 3, None, 3, 0, None)
        if not h or h == INVALID_HANDLE_VALUE:
            return False
        try:
            pp = ctypes.c_void_p()
            if not hid.HidD_GetPreparsedData(ctypes.c_void_p(h), ctypes.byref(pp)):
                return False
            try:
                caps = (ctypes.c_ushort * 32)()
                hid.HidP_GetCaps(pp, caps)
                # caps[0]=Usage, caps[1]=UsagePage, caps[4]=FeatureReportByteLength
                return caps[1] == 0xFF01 and caps[4] == 64
            finally:
                hid.HidD_FreePreparsedData(pp)
        finally:
            kernel32.CloseHandle(h)

    def _find_cooler_hid_path(self):
        """Find the cooler display HID collection (VID_1A2C & PID_4984, vendor page 0xFF01, 64-byte feature report)."""
        hid_guid = GUID()
        hid.HidD_GetHidGuid(ctypes.byref(hid_guid))
        hDevInfo = setupapi.SetupDiGetClassDevsW(ctypes.byref(hid_guid), None, None, 0x12)
        if not hDevInfo or hDevInfo == INVALID_HANDLE_VALUE:
            return None

        found_path = None
        try:
            idx = 0
            while True:
                ifData = SP_DEVICE_INTERFACE_DATA()
                ifData.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
                if not setupapi.SetupDiEnumDeviceInterfaces(hDevInfo, None, ctypes.byref(hid_guid), idx, ctypes.byref(ifData)):
                    break
                idx += 1

                req = wintypes.DWORD(0)
                setupapi.SetupDiGetDeviceInterfaceDetailW(hDevInfo, ctypes.byref(ifData), None, 0, ctypes.byref(req), None)
                if req.value == 0:
                    continue

                buf = ctypes.create_string_buffer(req.value)
                ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0] = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 5
                if setupapi.SetupDiGetDeviceInterfaceDetailW(hDevInfo, ctypes.byref(ifData), buf, req, None, None):
                    path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
                    if "vid_1a2c&pid_4984" in path.lower() and self._is_display_collection(path):
                        found_path = path
                        break
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(hDevInfo)
        return found_path

    def _send_cooler_packet(self, temp_celsius: float, sec_val: float, mode_code: int, led_on: bool):
        """Send 64-byte HID Feature Report (Report ID 0x07) directly to cooler."""
        if not self.hid_handle:
            path = self._find_cooler_hid_path()
            if path:
                h = kernel32.CreateFileW(path, 0xC0000000, 3, None, 3, 0, None)
                if h and h != INVALID_HANDLE_VALUE:
                    self.hid_handle = h

        if not self.hid_handle:
            return False

        pkt = bytearray(64)
        pkt[0] = 0x07  # Report ID (Feature Report, 64 bytes)

        if led_on:
            t_int = max(0, min(999, int(round(temp_celsius))))
            pkt[1] = (t_int // 100) % 10
            pkt[2] = (t_int // 10) % 10
            pkt[3] = t_int % 10

            # Mode flag in byte 4:
            # 0x10 = Main °C, Secondary % (CPU mode or VRAM % mode)
            # 0x01 = Main °F, Secondary W (GPU power mode)
            pkt[4] = mode_code

            # Secondary 3-digit display (CPU load % or GPU power Watts or VRAM %)
            # pkt[5] = hundreds, pkt[6] = tens, pkt[7] = units
            s_int = max(0, min(999, int(round(sec_val))))
            pkt[5] = (s_int // 100) % 10  # Hundreds digit
            pkt[6] = (s_int // 10) % 10   # Tens digit
            pkt[7] = s_int % 10           # Units digit
        else:
            # Blank display digits when LED switch is off
            for i in range(1, 8):
                pkt[i] = 0xFF

        written = wintypes.DWORD(0)
        buf = (ctypes.c_char * 64).from_buffer(pkt)
        ok = hid.HidD_SetFeature(ctypes.c_void_p(self.hid_handle), buf, 64)
        if not ok:
            kernel32.CloseHandle(self.hid_handle)
            self.hid_handle = None
            return False
        return True

    def _detect_motherboard_model(self):
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_BaseBoard).Product"],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2.0,
                text=True,
            ).strip()
            if out:
                self.stats["mb_model"] = out
                return out
        except Exception:
            pass
        return self.stats.get("mb_model", "Placa-Mãe")

    def _load_registry_preferences(self):
        try:
            key = None
            for sub in [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub)
                    break
                except OSError:
                    continue
            if key:
                try:
                    auto_sw, _ = winreg.QueryValueEx(key, "auto_switch_fps")
                    self.stats["auto_switch_fps"] = 1 if str(auto_sw) != "0" else 0
                except OSError:
                    self.stats["auto_switch_fps"] = 1

                winreg.CloseKey(key)

            # Regra: CPU (°C e carga %) é sempre o padrão primário de inicialização do app e do PC.
            # O modo FPS / VRAM só se ativa de forma automática ao entrar em um jogo.
            self.stats["active_device"] = "CPU"
            self.stats["active_unit"] = "°C"
            self.last_user_device = "CPU"
            self.auto_switched = False
            self.save_registry_device(1, 0)
        except Exception:
            self.stats["active_device"] = "CPU"
            self.stats["active_unit"] = "°C"
            self.last_user_device = "CPU"
            self.auto_switched = False

    def save_registry_device(self, dev_type, temp_type):
        for sub in [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]:
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
                winreg.SetValueEx(key, "device_type", 0, winreg.REG_SZ, str(dev_type))
                winreg.SetValueEx(key, "tempe_type", 0, winreg.REG_SZ, str(temp_type))
                winreg.CloseKey(key)
            except Exception:
                pass

    def set_auto_switch(self, enabled: bool):
        val = 1 if enabled else 0
        with self.lock:
            self.stats["auto_switch_fps"] = val
        for sub in [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]:
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
                winreg.SetValueEx(key, "auto_switch_fps", 0, winreg.REG_SZ, str(val))
                winreg.CloseKey(key)
            except Exception:
                pass
        return True

    def set_led(self, state: int):
        return True

    def set_device(self, device: str):
        dev = str(device).upper()
        if "FPS" in dev or "VRAM" in dev:
            dev_upper = "FPS"
            dev_unit = "%"
            dev_val = 2
            temp_val = 2
        elif "GPU" in dev:
            dev_upper = "GPU"
            dev_unit = "°F"
            dev_val = 0
            temp_val = 1
        else:
            dev_upper = "CPU"
            dev_unit = "°C"
            dev_val = 1
            temp_val = 0

        with self.lock:
            self.stats["active_device"] = dev_upper
            self.stats["active_unit"] = dev_unit
            if dev_upper in ["CPU", "GPU"]:
                self.last_user_device = dev_upper
            self.auto_switched = False

        self.save_registry_device(dev_val, temp_val)
        return True

    def set_mode(self, mode: str, interval: float = 5.0):
        return self.set_device(mode)

    def _worker_loop(self):
        self._ensure_internal_server()
        while self.running:
            try:
                self._tick()
            except Exception:
                logging.exception("worker tick error")
            time.sleep(0.8)

    def _tick(self):
        now = time.time()

        # Attempt LHM GPU init if not active yet
        if not self.lhm_gpu and (now - self.last_lhm_attempt >= 5.0):
            self.last_lhm_attempt = now
            self._init_lhm_gpu()

        # 1. Read shared memory if available
        b = self._read_shared_memory()
        cpu_temp = cpu_load = cpu_pwr = 0.0
        gpu_temp = gpu_load = gpu_pwr = 0.0
        mb_temp = 0.0

        if b and len(b) >= 760:
            try:
                cpu_volt, cpu_pwr, cpu_pwr_c, cpu_pwr_m, cpu_bus, cpu_clk, cpu_temp, cpu_load = struct.unpack_from("<8f", b, 128)
                gpu_pwr, gpu_clk, gpu_temp, gpu_load, gpu_volt = struct.unpack_from("<5f", b, 288)
                raw_mb = struct.unpack_from("<f", b, 724)[0]
                if raw_mb > 0.0:
                    mb_temp = raw_mb
            except Exception:
                pass

        # 2. Direct NVAPI Hot Spot, GPU & VRAM telemetry from LibreHardwareMonitor
        lhm_hotspot = 0.0
        lhm_core = 0.0
        lhm_pwr = 0.0
        lhm_load = 0.0
        lhm_vram_load = 0.0
        lhm_vram_used = 0.0
        lhm_vram_total = 0.0

        if self.lhm_gpu:
            try:
                self.lhm_gpu.Update()
                for s in self.lhm_gpu.Sensors:
                    stype = str(s.SensorType).lower()
                    sname = str(s.Name).lower()
                    val = float(s.Value) if s.Value is not None else 0.0
                    if "temperature" in stype:
                        if sname in ("gpu hot spot", "gpu hotspot"):
                            lhm_hotspot = val
                        elif sname in ("gpu core", "gpu temperature"):
                            if lhm_core == 0.0:
                                lhm_core = val
                    elif "power" in stype and sname in ("gpu package", "gpu core", "gpu power"):
                        if val > lhm_pwr:
                            lhm_pwr = val
                    elif "load" in stype:
                        if sname in ("gpu memory", "gpu memory used"):
                            if lhm_vram_load == 0.0:
                                lhm_vram_load = val
                        elif sname == "gpu core":
                            if val > lhm_load:
                                lhm_load = val
                    elif "smalldata" in stype:
                        if sname == "memory used" and "dedicated" not in sname:
                            lhm_vram_used = val
                        elif sname == "memory total":
                            lhm_vram_total = val
            except Exception:
                pass

        if lhm_vram_used > 0 and lhm_vram_total > 0:
            lhm_vram_load = round((lhm_vram_used / lhm_vram_total) * 100.0, 1)

        # Fallbacks if shared memory is still warming up or missing sensors
        if cpu_load <= 0.0:
            try:
                cpu_load = psutil.cpu_percent(interval=None)
            except Exception:
                pass

        nv_vram_load = nv_vram_used = nv_vram_total = 0.0
        if self.has_nvidia_smi and ((gpu_temp <= 0.0 and lhm_core <= 0.0) or lhm_vram_load <= 0.0) and (now - self.last_nvidia_check >= 2.0):
            self.last_nvidia_check = now
            nv = self._read_nvidia_fallback()
            if nv:
                gpu_temp, gpu_load, gpu_pwr, nv_vram_load, nv_vram_used, nv_vram_total = nv

        # Prefer direct NVAPI metrics when available
        core_temp = lhm_core if lhm_core > 0 else gpu_temp
        hotspot_temp = lhm_hotspot
        effective_gpu_temp = hotspot_temp if hotspot_temp > 0 else core_temp
        if lhm_pwr > 0:
            gpu_pwr = lhm_pwr
        if lhm_load > 0:
            gpu_load = lhm_load

        final_vram_load = lhm_vram_load if lhm_vram_load > 0 else nv_vram_load
        final_vram_used = lhm_vram_used if lhm_vram_used > 0 else nv_vram_used
        final_vram_total = lhm_vram_total if lhm_vram_total > 0 else nv_vram_total

        # Read FPS from RTSS or PresentMon
        cur_fps = self.rtss_reader.read_fps()
        if cur_fps <= 0.0 and not self.rtss_reader.has_rtss_installed:
            if not self.pmon_reader.running and not self.pmon_reader.failed:
                self.pmon_reader.start()
            cur_fps = self.pmon_reader.get_fps()

        # Automatic Game Detection & Mode Switching with exact executable names
        is_rendering_fps = (cur_fps > 5.0)
        is_game_proc = False
        if now - self._last_proc_scan > 3.0:
            self._last_proc_scan = now
            try:
                for p in psutil.process_iter(["name"]):
                    pname = (p.info["name"] or "").lower()
                    if pname in KNOWN_GAME_EXES:
                        is_game_proc = True
                        break
                self._last_game_proc_detected = is_game_proc
            except Exception:
                pass
        else:
            is_game_proc = self._last_game_proc_detected

        is_in_game = is_rendering_fps or (is_game_proc and cur_fps > 0.0)

        # 3. Update state quickly under lock
        with self.lock:
            auto_on = (self.stats.get("auto_switch_fps", 1) == 1)

            if is_in_game:
                self.game_active_samples += 1
                self.game_idle_samples = 0
                if self.game_active_samples >= 2:
                    self.stats["in_game"] = True
                    if auto_on and self.stats["active_device"] != "FPS":
                        if self.stats["active_device"] in ["CPU", "GPU"]:
                            self.last_user_device = self.stats["active_device"]
                        self.stats["active_device"] = "FPS"
                        self.stats["active_unit"] = "%"
                        self.auto_switched = True
            else:
                self.game_idle_samples += 1
                self.game_active_samples = 0
                if self.game_idle_samples >= 4:
                    self.stats["in_game"] = False
                    if auto_on and self.auto_switched:
                        restore_target = self.last_user_device if self.last_user_device in ["CPU", "GPU"] else "CPU"
                        self.stats["active_device"] = restore_target
                        self.stats["active_unit"] = "°C" if restore_target == "CPU" else "°F"
                        self.auto_switched = False

            if cpu_temp > 0:
                self.stats["cpu_temp"] = round(cpu_temp, 1)
            if cpu_load > 0 or self.stats["cpu_load"] == 0:
                self.stats["cpu_load"] = round(cpu_load, 1)
            if cpu_pwr > 0:
                self.stats["cpu_power"] = round(cpu_pwr, 1)

            if effective_gpu_temp > 0:
                self.stats["gpu_temp"] = round(effective_gpu_temp, 1)
            if core_temp > 0:
                self.stats["gpu_core_temp"] = round(core_temp, 1)
            if hotspot_temp > 0:
                self.stats["gpu_hotspot"] = round(hotspot_temp, 1)
            if gpu_load >= 0 and (b is not None or effective_gpu_temp > 0):
                self.stats["gpu_load"] = round(gpu_load, 1)
            if gpu_pwr > 0:
                self.stats["gpu_power"] = round(gpu_pwr, 1)

            if final_vram_load > 0:
                self.stats["gpu_vram_load"] = round(final_vram_load, 1)
            if final_vram_used > 0:
                self.stats["gpu_vram_used"] = round(final_vram_used, 0)
            if final_vram_total > 0:
                self.stats["gpu_vram_total"] = round(final_vram_total, 0)

            self.stats["fps"] = int(round(cur_fps))

            # Only report motherboard temperature if a real sensor measurement was provided (no invented formulas)
            self.stats["mb_temp"] = round(mb_temp, 1) if mb_temp > 0.0 else 0.0

            active_dev = self.stats["active_device"]
            led_on = True

            if active_dev == "FPS":
                # Main display: FPS
                # Secondary display: VRAM % with 0-100 and % glyph (0x10)
                disp_temp = float(self.stats["fps"])
                disp_sec = float(self.stats["gpu_vram_load"])
                mode_code = 0x10  # 0x10 forces % glyph on the secondary display!
            elif active_dev == "GPU":
                disp_temp = float(self.stats["gpu_temp"])
                disp_sec = float(self.stats["gpu_power"] if self.stats["gpu_power"] > 0 else self.stats["gpu_load"])
                mode_code = 0x01  # 0x01 forces W glyph on the secondary display
            else:  # CPU
                disp_temp = float(self.stats["cpu_temp"])
                disp_sec = float(self.stats["cpu_load"])
                mode_code = 0x10  # 0x10 forces % glyph on the secondary display

        # 4. Send packet directly to USB HID Cooler outside lock
        connected = self._send_cooler_packet(disp_temp, disp_sec, mode_code, True)
        with self.lock:
            self.stats["cooler_connected"] = connected

    def get_data(self):
        with self.lock:
            return dict(self.stats)

    def close(self):
        self.running = False
        self.pmon_reader.stop()
        if self.server_proc:
            try:
                self.server_proc.terminate()
                self.server_proc.wait(timeout=1.5)
            except Exception:
                try:
                    self.server_proc.kill()
                except Exception:
                    pass
            self.server_proc = None
        if self.hid_handle:
            try:
                kernel32.CloseHandle(self.hid_handle)
            except Exception:
                pass
            self.hid_handle = None
        if self.lhm_comp:
            try:
                self.lhm_comp.Close()
            except Exception:
                pass
            self.lhm_comp = None
