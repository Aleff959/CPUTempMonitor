import os
import sys
import time
import struct
import ctypes
from ctypes import wintypes
import winreg
import threading
import subprocess
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


class MonitorCore:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()

        # State
        self.stats = {
            "cpu_temp": 0.0,
            "cpu_load": 0.0,
            "cpu_power": 0.0,
            "gpu_temp": 0.0,
            "gpu_load": 0.0,
            "gpu_power": 0.0,
            "mb_temp": 0.0,
            "active_device": "CPU",  # "CPU" or "GPU"
            "active_unit": "°C",     # "°C" for CPU, "°F" for GPU (as visual indicator)
            "led_switch": 1,
            "cooler_connected": False,
        }

        self.server_proc = None
        self.hid_handle = None
        self.server_dir = self._find_server_dir()

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
            if os.path.exists(lib_src) and not os.path.exists(lib_dst):
                import shutil
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
        """Fast fallback for NVIDIA GPU metrics while server initializes."""
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,power.draw", "--format=csv,noheader,nounits"],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=1.5,
                text=True,
            ).strip()
            if out:
                parts = [p.strip() for p in out.splitlines()[0].split(",")]
                if len(parts) >= 3:
                    return float(parts[0]), float(parts[1]), float(parts[2])
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

    def _send_cooler_packet(self, temp_celsius: float, sec_val: float, is_cpu: bool, led_on: bool):
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

            # Mode flag: 0x10 for CPU (°C), 0x01 for GPU (°F marker)
            pkt[4] = 0x10 if is_cpu else 0x01

            # Secondary 3-digit display (CPU load % or GPU power Watts / load %)
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

    def _load_registry_preferences(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\CPU TEMP Monitor")
            try:
                dev, _ = winreg.QueryValueEx(key, "device_type")
                if str(dev) == "0":
                    self.stats["active_device"] = "GPU"
                    self.stats["active_unit"] = "°F"
                else:
                    self.stats["active_device"] = "CPU"
                    self.stats["active_unit"] = "°C"
            except OSError:
                pass
            try:
                led, _ = winreg.QueryValueEx(key, "led_switch")
                self.stats["led_switch"] = 1 if str(led) != "0" else 0
            except OSError:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

    def save_registry_device(self, dev_type, temp_type):
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\CPU TEMP Monitor")
            winreg.SetValueEx(key, "device_type", 0, winreg.REG_SZ, str(dev_type))
            winreg.SetValueEx(key, "tempe_type", 0, winreg.REG_SZ, str(temp_type))
            winreg.CloseKey(key)
        except Exception:
            pass

    def set_led(self, state: int):
        led_val = 1 if state else 0
        with self.lock:
            self.stats["led_switch"] = led_val
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\CPU TEMP Monitor")
            winreg.SetValueEx(key, "led_switch", 0, winreg.REG_SZ, str(led_val))
            winreg.CloseKey(key)
        except Exception:
            pass

    def set_device(self, device: str):
        dev_upper = "GPU" if "gpu" in str(device).lower() else "CPU"
        with self.lock:
            self.stats["active_device"] = dev_upper
            self.stats["active_unit"] = "°C" if dev_upper == "CPU" else "°F"
            dev_val = 1 if dev_upper == "CPU" else 0
            temp_val = 0 if dev_upper == "CPU" else 1

        self.save_registry_device(dev_val, temp_val)
        return True

    def set_mode(self, mode: str, interval: float = 5.0):
        return self.set_device(mode)

    def _worker_loop(self):
        self._ensure_internal_server()
        last_nvidia_check = 0.0

        while self.running:
            now = time.time()

            # 1. Read shared memory if available
            b = self._read_shared_memory()
            cpu_temp = cpu_load = cpu_pwr = 0.0
            gpu_temp = gpu_load = gpu_pwr = 0.0
            mb_temp = 0.0

            if b and len(b) >= 760:
                try:
                    cpu_volt, cpu_pwr, cpu_pwr_c, cpu_pwr_m, cpu_bus, cpu_clk, cpu_temp, cpu_load = struct.unpack_from("<8f", b, 128)
                    gpu_pwr, gpu_clk, gpu_temp, gpu_load, gpu_volt = struct.unpack_from("<5f", b, 288)
                    mb_temp = struct.unpack_from("<f", b, 724)[0]
                except Exception:
                    pass

            # 2. Fallbacks if shared memory is still warming up or missing sensors
            if cpu_load <= 0.0:
                try:
                    cpu_load = psutil.cpu_percent(interval=None)
                except Exception:
                    pass

            if gpu_temp <= 0.0 and (now - last_nvidia_check >= 2.0):
                last_nvidia_check = now
                nv = self._read_nvidia_fallback()
                if nv:
                    gpu_temp, gpu_load, gpu_pwr = nv

            # 3. Update state quickly under lock
            with self.lock:
                if cpu_temp > 0:
                    self.stats["cpu_temp"] = round(cpu_temp, 1)
                if cpu_load > 0 or self.stats["cpu_load"] == 0:
                    self.stats["cpu_load"] = round(cpu_load, 1)
                if cpu_pwr > 0:
                    self.stats["cpu_power"] = round(cpu_pwr, 1)
                if gpu_temp > 0:
                    self.stats["gpu_temp"] = round(gpu_temp, 1)
                if gpu_load >= 0 and (b is not None or gpu_temp > 0):
                    self.stats["gpu_load"] = round(gpu_load, 1)
                if gpu_pwr > 0:
                    self.stats["gpu_power"] = round(gpu_pwr, 1)
                if mb_temp > 0:
                    self.stats["mb_temp"] = round(mb_temp, 1)

                active_dev = self.stats["active_device"]
                led_on = self.stats["led_switch"] == 1
                is_cpu = (active_dev == "CPU")

                if is_cpu:
                    disp_temp = self.stats["cpu_temp"]
                    disp_sec = self.stats["cpu_load"]
                else:
                    disp_temp = self.stats["gpu_temp"]
                    disp_sec = self.stats["gpu_power"] if self.stats["gpu_power"] > 0 else self.stats["gpu_load"]

            # 4. Send packet directly to USB HID Cooler outside lock
            connected = self._send_cooler_packet(disp_temp, disp_sec, is_cpu, led_on)
            with self.lock:
                self.stats["cooler_connected"] = connected

            time.sleep(0.8)

    def get_data(self):
        with self.lock:
            return dict(self.stats)

    def close(self):
        self.running = False
        if self.hid_handle:
            try:
                kernel32.CloseHandle(self.hid_handle)
            except Exception:
                pass
            self.hid_handle = None
