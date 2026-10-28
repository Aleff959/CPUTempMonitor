import os
import sys
import time
import json
import socket
import ctypes
import subprocess
import threading
import logging

IPC_HOST = "127.0.0.1"
IPC_PORT = 49841

SERVICE_NAME = "FulgorPCistaService"
BOOT_TASK_NAME = "FulgorPCista_BootService"
LOGON_TASK_NAME = "FulgorPCista_AutoStart"
SERVICE_DISPLAY_NAME = "Fulgor PCista - Motor de Telemetria USB HID"
SERVICE_DESCRIPTION = (
    "Servico de sistema de inicializacao instantanea (Pre-Logon) do Fulgor PCista. "
    "Controla o visor digital do cooler via USB HID e monitora sensores termicos de CPU/GPU "
    "ja na primeira tela de boot e bloqueio do Windows."
)


def install_boot_service(exe_path: str = None) -> dict:
    """
    Configure both Pre-Logon SYSTEM Boot Service Task (BootTrigger) and Instant Logon UI Task.
    Uses PowerShell Start-Process -Verb RunAs if not already running as Administrator.
    """
    if not exe_path:
        local_app = os.environ.get("LOCALAPPDATA", r"C:\Users\Alpha\AppData\Local")
        cand = os.path.join(local_app, "Programs", "FulgorPCista", "FulgorPCista.exe")
        if os.path.exists(cand):
            exe_path = cand
        elif getattr(sys, "frozen", False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(sys.argv[0])

    ps_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configurar_autostart.ps1")
    if getattr(sys, "frozen", False):
        for cand_dir in [os.path.dirname(sys.executable), getattr(sys, "_MEIPASS", "")]:
            p = os.path.join(cand_dir, "configurar_autostart.ps1")
            if os.path.exists(p):
                ps_script = p
                break

    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    try:
        if os.path.exists(ps_script):
            if is_admin:
                subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps_script, "-Silent"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=15,
                )
            else:
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    "powershell.exe",
                    f'-NoProfile -ExecutionPolicy Bypass -File "{ps_script}" -Silent',
                    os.path.dirname(ps_script),
                    0,
                )
                time.sleep(2.5)
        return {"success": True, "message": "Serviço de Boot Pré-Logon (Nível 2) configurado e ativado com sucesso!"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_boot_service_status() -> dict:
    """Return whether the Pre-Logon Boot Service is active and registered."""
    client = TelemetryIPCClient(timeout=0.25)
    ipc_active = client.is_alive()
    task_registered = False
    try:
        res = subprocess.run(
            ["schtasks", "/query", "/tn", BOOT_TASK_NAME],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=2.0,
        )
        task_registered = (res.returncode == 0)
    except Exception:
        pass
    return {
        "service_running": ipc_active,
        "boot_registered": task_registered,
    }


class TelemetryIPCServer:
    """Lightweight localhost TCP server running inside the System Service / Boot Daemon."""

    def __init__(self, core, port: int = IPC_PORT):
        self.core = core
        self.port = port
        self.running = True
        self.sock = None
        self.thread = threading.Thread(target=self._serve_loop, daemon=True)
        self.thread.start()

    def _serve_loop(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((IPC_HOST, self.port))
            self.sock.listen(8)
            self.sock.settimeout(1.0)
            logging.info(f"TelemetryIPCServer listening on {IPC_HOST}:{self.port}")
        except Exception as e:
            logging.error(f"TelemetryIPCServer failed to bind port {self.port}: {e}")
            return

        while self.running:
            try:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break
                time.sleep(0.1)

    def _handle_client(self, conn: socket.socket):
        with conn:
            conn.settimeout(2.0)
            try:
                raw = conn.recv(4096)
                if not raw:
                    return
                req = json.loads(raw.decode("utf-8", errors="ignore").strip())
                cmd = req.get("cmd", "")

                if cmd == "get_stats":
                    data = self.core.get_data()
                    data["service_active"] = True
                    resp = {"ok": True, "data": data}
                elif cmd == "set_mode":
                    mode = req.get("mode", "CPU")
                    interval = float(req.get("interval", 5.0))
                    self.core.set_mode(mode, interval)
                    resp = {"ok": True}
                elif cmd == "set_auto_switch":
                    enabled = bool(req.get("enabled", True))
                    self.core.set_auto_switch(enabled)
                    resp = {"ok": True}
                elif cmd == "set_led":
                    state = int(req.get("state", 1))
                    self.core.set_led(state)
                    resp = {"ok": True}
                elif cmd == "update_session_metrics":
                    fps = float(req.get("fps", 0.0))
                    in_game = bool(req.get("in_game", False))
                    if hasattr(self.core, "update_external_session_metrics"):
                        self.core.update_external_session_metrics(fps, in_game)
                    resp = {"ok": True}
                elif cmd == "ping":
                    resp = {"ok": True, "service": SERVICE_NAME}
                elif cmd == "shutdown":
                    resp = {"ok": True}
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                    self.stop()
                    self.core.close()
                    os._exit(0)
                    return
                else:
                    resp = {"ok": False, "error": f"Unknown command: {cmd}"}

                conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except Exception as e:
                logging.debug(f"IPC client handling error: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class TelemetryIPCClient:
    """Client proxy used by the Desktop UI when the Boot Service / Daemon is active."""

    def __init__(self, timeout: float = 0.35, port: int = IPC_PORT):
        self.timeout = timeout
        self.port = port

    def _request(self, payload: dict):
        try:
            with socket.create_connection((IPC_HOST, self.port), timeout=self.timeout) as s:
                s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf:
                        break
                if not buf:
                    return None
                return json.loads(buf.decode("utf-8", errors="ignore").strip())
        except Exception:
            return None

    def is_alive(self) -> bool:
        res = self._request({"cmd": "ping"})
        return bool(res and res.get("ok"))

    def get_data(self):
        res = self._request({"cmd": "get_stats"})
        if res and res.get("ok") and isinstance(res.get("data"), dict):
            return res["data"]
        return None

    def set_mode(self, mode: str, interval: float = 5.0):
        res = self._request({"cmd": "set_mode", "mode": mode, "interval": interval})
        return bool(res and res.get("ok"))

    def set_auto_switch(self, enabled: bool):
        res = self._request({"cmd": "set_auto_switch", "enabled": bool(enabled)})
        return bool(res and res.get("ok"))

    def set_led(self, state: int):
        res = self._request({"cmd": "set_led", "state": int(state)})
        return bool(res and res.get("ok"))

    def send_session_metrics(self, fps: float, in_game: bool):
        res = self._request({"cmd": "update_session_metrics", "fps": fps, "in_game": in_game})
        return bool(res and res.get("ok"))

    def request_shutdown(self):
        res = self._request({"cmd": "shutdown"})
        return bool(res and res.get("ok"))


class HybridCoreProxy:
    """
    Transparent proxy for the Desktop UI.
    If the Boot Service / Daemon (Session 0) is running, delegates telemetry & USB HID control
    to the service via IPC while feeding local user-session RTSS/game FPS into the service.
    If the service is stopped or not installed, seamlessly falls back to an in-process MonitorCore.
    """

    def __init__(self):
        self.client = TelemetryIPCClient()
        self.local_core = None
        self._rtss = None
        self._last_proc_scan = 0.0
        self._last_game_proc = False

        if self.client.is_alive():
            logging.info("HybridCoreProxy: Connected to active Pre-Logon Boot Service via IPC.")
            from monitor_core import RTSSReader
            self._rtss = RTSSReader()
        else:
            # If running elevated (e.g. from HighestAvailable AutoStart task) and BootService is not yet running,
            # auto-provision or start the Pre-Logon Boot Service silently.
            try:
                if bool(ctypes.windll.shell32.IsUserAnAdmin()):
                    st = get_boot_service_status()
                    if not st.get("boot_registered"):
                        logging.info("HybridCoreProxy: Auto-registering Pre-Logon Boot Service with admin privileges...")
                        install_boot_service()
                        time.sleep(1.0)
                    elif not st.get("service_running"):
                        logging.info("HybridCoreProxy: Starting existing Pre-Logon Boot Service task...")
                        subprocess.run(
                            ["schtasks", "/run", "/tn", BOOT_TASK_NAME],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=5.0,
                        )
                        time.sleep(1.2)
            except Exception as e:
                logging.debug(f"Auto-provision boot service skipped: {e}")

            if self.client.is_alive():
                logging.info("HybridCoreProxy: Connected to newly started Pre-Logon Boot Service via IPC.")
                from monitor_core import RTSSReader
                self._rtss = RTSSReader()
            else:
                logging.info("HybridCoreProxy: Boot Service not detected, starting in-process MonitorCore.")
                from monitor_core import MonitorCore
                self.local_core = MonitorCore()

    def _ensure_fallback(self):
        if not self.local_core:
            from monitor_core import MonitorCore
            self.local_core = MonitorCore()

    def _sync_user_session_fps(self):
        if not self._rtss:
            from monitor_core import RTSSReader
            self._rtss = RTSSReader()
        fps = self._rtss.read_fps()
        now = time.time()
        if now - self._last_proc_scan > 3.0:
            self._last_proc_scan = now
            try:
                import psutil
                from monitor_core import KNOWN_GAME_EXES
                found = False
                for p in psutil.process_iter(["name"]):
                    pname = (p.info["name"] or "").lower()
                    if pname in KNOWN_GAME_EXES:
                        found = True
                        break
                self._last_game_proc = found
            except Exception:
                pass
        in_game = (fps > 5.0) or (self._last_game_proc and fps > 0.0)
        self.client.send_session_metrics(fps, in_game)

    def get_data(self):
        if self.local_core is None:
            self._sync_user_session_fps()
            data = self.client.get_data()
            if data is not None:
                return data
            self._ensure_fallback()
        return self.local_core.get_data()

    def set_mode(self, mode: str, interval: float = 5.0):
        if self.local_core is None:
            if self.client.set_mode(mode, interval):
                return True
            self._ensure_fallback()
        return self.local_core.set_mode(mode, interval)

    def set_device(self, device: str):
        return self.set_mode(device)

    def set_auto_switch(self, enabled: bool):
        if self.local_core is None:
            if self.client.set_auto_switch(enabled):
                return True
            self._ensure_fallback()
        return self.local_core.set_auto_switch(enabled)

    def set_led(self, state: int):
        if self.local_core is None:
            if self.client.set_led(state):
                return True
            self._ensure_fallback()
        return self.local_core.set_led(state)

    def close(self):
        if self.local_core is not None:
            self.local_core.close()
            self.local_core = None


def run_headless_daemon():
    """Run MonitorCore + IPC Server in headless mode (Boot Task or Service fallback)."""
    from monitor_core import MonitorCore

    # Boost process priority to HIGH_PRIORITY_CLASS (0x00000080) for instant USB display response at boot
    try:
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00000080)
    except Exception:
        pass

    logging.info("Starting headless Fulgor PCista Boot Daemon...")
    core = MonitorCore()
    ipc = TelemetryIPCServer(core)
    try:
        while core.running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        ipc.stop()
        core.close()


def run_windows_service():
    """Run as a native Windows Service under NT AUTHORITY\\SYSTEM (SCM)."""
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager

        class FulgorPCistaWinService(win32serviceutil.ServiceFramework):
            _svc_name_ = SERVICE_NAME
            _svc_display_name_ = SERVICE_DISPLAY_NAME
            _svc_description_ = SERVICE_DESCRIPTION

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                self.core = None
                self.ipc = None

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.hWaitStop)
                if self.ipc:
                    self.ipc.stop()
                if self.core:
                    self.core.close()

            def SvcDoRun(self):
                try:
                    ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00000080)
                except Exception:
                    pass
                from monitor_core import MonitorCore
                self.core = MonitorCore()
                self.ipc = TelemetryIPCServer(self.core)
                win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FulgorPCistaWinService)
        servicemanager.StartServiceCtrlDispatcher()
    except Exception as e:
        logging.warning(f"SCM dispatcher fallback to headless daemon: {e}")
        run_headless_daemon()
