import os
import sys
import ctypes
import threading
import time
import logging
import webview
from monitor_core import MonitorCore
from updater import AppUpdater

log_path = os.path.expandvars(r"%TEMP%\cputemp_debug.log")
logging.basicConfig(filename=log_path, filemode="w", level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

def _log_ex(args):
    logging.error(f"Thread exception: {args.exc_type} {args.exc_value}", exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

threading.excepthook = _log_ex

def _sys_ex(tp, val, tb):
    logging.error(f"System exception: {tp} {val}", exc_info=(tp, val, tb))

sys.excepthook = _sys_ex

APP_NAME = "Fulgor PCista"
APP_VERSION = "1.7.0"
APP_COMP = 26
APP_CODENAME = "Zeus"
WINDOW_TITLE = f"{APP_NAME} ({APP_VERSION} | Comp. {APP_COMP} - {APP_CODENAME})"


class Api:
    def __init__(self, core):
        self._core = core
        self._updater = AppUpdater(current_version=APP_VERSION, current_comp=APP_COMP)

    def get_stats(self):
        return self._core.get_data()

    def set_mode(self, mode, interval=5.0):
        self._core.set_mode(mode, interval)
        return True

    def set_led(self, state):
        self._core.set_led(state)
        return True

    def set_auto_switch(self, enabled):
        self._core.set_auto_switch(enabled)
        return True

    def get_service_status(self):
        from service_bridge import get_boot_service_status
        return get_boot_service_status()

    def enable_boot_service(self):
        from service_bridge import install_boot_service
        return install_boot_service()

    def open_url(self, url):
        import webbrowser
        try:
            webbrowser.open(url)
            return True
        except Exception as e:
            logging.error(f"Failed to open url {url}: {e}")
            return False

    def check_updates(self):
        return self._updater.check_for_updates()

    def apply_update(self, download_url=None, expected_hash=None):
        return self._updater.apply_update(download_url, expected_hash)


def apply_dark_titlebar():
    """Apply Windows 11 dark immersive titlebar matching Material You #111418 surface."""
    try:
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if hwnd:
            dark_mode = ctypes.c_int(1)
            dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark_mode), ctypes.sizeof(dark_mode))
            caption_color = ctypes.c_int(0x00181411)
            dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption_color), ctypes.sizeof(caption_color))
    except Exception:
        pass


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if hasattr(sys, "_MEIPASS"):
        p = os.path.join(sys._MEIPASS, relative_path)
        if os.path.exists(p):
            return p
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        for cand in [os.path.join(exe_dir, relative_path), os.path.join(exe_dir, "_internal", relative_path)]:
            if os.path.exists(cand):
                return cand
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


class WinFormsTrayManager:
    def __init__(self, window, start_hidden: bool):
        self.window = window
        self.start_hidden = start_hidden
        self.is_quitting = False
        self.notify = None
        self.form = None
        self.web_loaded = False

    def on_closing(self):
        """When user clicks X on window, hide window to tray instead of quitting."""
        if self.is_quitting:
            return True   # Allow close
        self.hide_window()
        return False  # In pywebview, returning False cancels closing/destruction!

    def show_window(self):
        if self.form:
            import System
            import System.Windows.Forms as WinForms
            import System.Drawing as Drawing
            def _show():
                # If window was created off-screen (-32000), re-center it on primary screen
                if self.form.Location.X < -1000 or self.form.Location.Y < -1000:
                    try:
                        self.form.CenterToScreen()
                    except Exception:
                        scr = WinForms.Screen.FromControl(self.form).WorkingArea
                        self.form.Location = Drawing.Point(
                            max(0, (scr.Width - self.form.Width) // 2),
                            max(0, (scr.Height - self.form.Height) // 2)
                        )

                self.form.Visible = True
                self.form.ShowInTaskbar = True
                self.form.WindowState = WinForms.FormWindowState.Normal
                if hasattr(self.form, "browser") and hasattr(self.form.browser, "webview"):
                    try:
                        self.form.browser.webview.Visible = True
                        self.form.browser.webview.Dock = WinForms.DockStyle.Fill
                        self.form.browser.webview.BringToFront()
                        self.form.browser.webview.Focus()
                    except Exception:
                        pass
                self.form.BringToFront()
                self.form.Activate()
                self.form.Invalidate(True)
                self.form.Update()

            try:
                self.form.Invoke(System.Action(_show))
                apply_dark_titlebar()
            except Exception as e:
                logging.error(f"show_window error: {e}")

    def hide_window(self):
        if self.form:
            import System
            def _hide():
                self.form.Visible = False
                self.form.ShowInTaskbar = False
            try:
                self.form.Invoke(System.Action(_hide))
            except Exception as e:
                logging.error(f"hide_window error: {e}")

    def quit_app(self):
        self.is_quitting = True
        if self.notify:
            try:
                self.notify.Visible = False
                self.notify.Dispose()
            except Exception:
                pass
        if self.form:
            import System
            try:
                self.form.Invoke(System.Action(self.form.Close))
            except Exception:
                pass

    def on_loaded(self):
        """Fires when WebView2 DOM and JS API are fully initialized and ready."""
        logging.info("on_loaded: WebView2 DOM and JS API fully initialized.")
        self.web_loaded = True
        if self.start_hidden:
            self.hide_window()

    def setup_tray(self):
        from webview.platforms.winforms import BrowserView
        import clr
        clr.AddReference("System.Windows.Forms")
        clr.AddReference("System.Drawing")
        import System
        import System.Windows.Forms as WinForms
        import System.Drawing as Drawing

        logging.info("setup_tray: waiting for form and handle...")
        # Wait until the form exists AND its window handle is created
        for i in range(100):
            self.form = BrowserView.instances.get(self.window.uid)
            if self.form and getattr(self.form, "IsHandleCreated", False):
                logging.info(f"setup_tray: form handle ready at iteration {i}")
                break
            time.sleep(0.1)

        if not self.form:
            logging.error("setup_tray: timed out waiting for form handle!")
            return

        def _init():
            try:
                logging.info("_init: creating NotifyIcon...")
                self.notify = WinForms.NotifyIcon()
                self.notify.Text = f"{APP_NAME} (v{APP_VERSION} - {APP_CODENAME})"[:63]

                # Infallible multi-tiered icon discovery
                ico = None
                ico_path = get_resource_path("app.ico")
                if os.path.exists(ico_path):
                    try:
                        ico = Drawing.Icon(ico_path)
                    except Exception as e:
                        logging.warning(f"Failed to load app.ico: {e}")
                if not ico and getattr(sys, "frozen", False):
                    try:
                        ico = Drawing.Icon.ExtractAssociatedIcon(sys.executable)
                    except Exception:
                        pass
                if not ico:
                    try:
                        ico = Drawing.Icon.ExtractAssociatedIcon(sys.executable)
                    except Exception:
                        pass
                if not ico:
                    try:
                        ico = Drawing.SystemIcons.Application
                    except Exception:
                        pass

                self.notify.Icon = ico
                logging.info(f"_init: icon assigned: {ico}")

                context_menu = WinForms.ContextMenuStrip()
                item_open = context_menu.Items.Add(f"Abrir {APP_NAME}")
                item_hide = context_menu.Items.Add("Minimizar para a Bandeja")
                context_menu.Items.Add("-")
                item_exit = context_menu.Items.Add(f"Encerrar {APP_NAME}")

                item_open.Click += lambda sender, args: self.show_window()
                item_hide.Click += lambda sender, args: self.hide_window()
                item_exit.Click += lambda sender, args: self.quit_app()

                self.notify.ContextMenuStrip = context_menu

                # Left click or double click on tray icon restores window
                def _on_mouse_click(sender, args):
                    if str(args.Button) == "Left":
                        self.show_window()
                self.notify.MouseClick += _on_mouse_click
                self.notify.DoubleClick += lambda sender, args: self.show_window()

                # Handle minimize: hide to tray
                def _on_resize(sender, args):
                    if self.form.WindowState == WinForms.FormWindowState.Minimized:
                        self.form.Visible = False
                        self.form.ShowInTaskbar = False
                self.form.Resize += _on_resize

                self.notify.Visible = True
                logging.info("_init: NotifyIcon is now Visible=True")

                if self.start_hidden:
                    self.form.ShowInTaskbar = False
                    if self.web_loaded:
                        self.form.Visible = False
            except Exception as e:
                logging.error(f"_init error: {e}", exc_info=True)

        try:
            logging.info("setup_tray: invoking _init on UI thread...")
            self.form.Invoke(System.Action(_init))
            logging.info("setup_tray: _init invocation complete.")
        except Exception as e:
            logging.error(f"setup_tray: invoke failed: {e}", exc_info=True)
            try:
                _init()
            except Exception:
                pass

    def on_shown(self):
        apply_dark_titlebar()

    def listen_show_event(self):
        """Listen for activation signal from subsequent process launches to properly restore and focus UI."""
        kernel32 = ctypes.windll.kernel32
        event_name = "Local\\FulgorPCista_ShowUI_Event"
        ev = kernel32.CreateEventW(None, False, False, event_name)
        while not self.is_quitting:
            res = kernel32.WaitForSingleObject(ev, 800)
            if res == 0:  # WAIT_OBJECT_0
                logging.info("listen_show_event: received show signal from another instance.")
                self.show_window()
        if ev:
            kernel32.CloseHandle(ev)


_single_instance_mutex = None


def _cleanup_legacy_and_stale_processes():
    """Terminate any legacy/stale UI instances (e.g. from older compilations without single-instance mutex) and purge .old files."""
    try:
        import psutil
        my_pid = os.getpid()
        parent_pid = os.getppid()
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = p.info["pid"]
                if pid in (my_pid, parent_pid):
                    continue
                pname = (p.info["name"] or "").lower()
                if "fulgorpcista" in pname or "cputempmonitor" in pname:
                    cmdline = [str(c).lower() for c in (p.info.get("cmdline") or [])]
                    if "-daemon" in cmdline or "--daemon" in cmdline or "-service" in cmdline or "--service" in cmdline:
                        continue
                    p.kill()
            except Exception:
                pass
    except Exception:
        pass

    try:
        if getattr(sys, "frozen", False):
            exe_dir = os.path.dirname(sys.executable)
            for fname in os.listdir(exe_dir):
                if ".old" in fname.lower() or ".del_" in fname.lower():
                    try:
                        os.remove(os.path.join(exe_dir, fname))
                    except Exception:
                        pass
    except Exception:
        pass


def ensure_single_ui_instance():
    """Ensure only 1 UI/Tray instance runs per user session. If already running, signal existing instance to show and exit."""
    global _single_instance_mutex
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    mutex_name = "Local\\FulgorPCista_UI_SingleInstance_Mutex"
    _single_instance_mutex = kernel32.CreateMutexW(None, False, mutex_name)
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        logging.info("Another UI instance of Fulgor PCista is already running. Signaling existing window to restore and exiting.")
        event_name = "Local\\FulgorPCista_ShowUI_Event"
        ev = kernel32.OpenEventW(0x0002, False, event_name)  # EVENT_MODIFY_STATE
        if ev:
            kernel32.SetEvent(ev)
            kernel32.CloseHandle(ev)
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if hwnd:
            user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            user32.SetForegroundWindow(hwnd)
        return False
    _cleanup_legacy_and_stale_processes()
    return True


def main():
    args_lower = [a.lower() for a in sys.argv[1:]]
    if "-service" in args_lower or "--service" in args_lower:
        from service_bridge import run_windows_service
        run_windows_service()
        return

    if "-daemon" in args_lower or "--daemon" in args_lower:
        from service_bridge import run_headless_daemon
        run_headless_daemon()
        return

    if not ensure_single_ui_instance():
        return

    start_hidden = "-hide" in args_lower or "--hide" in args_lower

    from service_bridge import HybridCoreProxy
    core = HybridCoreProxy()
    api = Api(core)

    html_path = get_resource_path(os.path.join("ui", "index.html"))

    init_x = -32000 if start_hidden else None
    init_y = -32000 if start_hidden else None

    window = webview.create_window(
        title=WINDOW_TITLE,
        url=f"file:///{html_path.replace(os.sep, '/')}",
        js_api=api,
        width=550,
        height=695,
        x=init_x,
        y=init_y,
        resizable=False,
        frameless=False,
        hidden=False,
        background_color="#111418",
    )

    tray = WinFormsTrayManager(window, start_hidden)
    window.events.closing += tray.on_closing
    window.events.shown += tray.on_shown
    window.events.loaded += tray.on_loaded

    threading.Thread(target=tray.setup_tray, daemon=True).start()
    threading.Thread(target=tray.listen_show_event, daemon=True).start()

    logging.info(f"main: start_hidden={start_hidden}, launching webview.start()...")
    try:
        webview.start(debug=False)
        logging.info("main: webview.start() completed normally.")
    except Exception as e:
        logging.error(f"main: webview.start() crashed with error: {e}", exc_info=True)
    finally:
        logging.info("main: closing core...")
        core.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        with open(os.path.expandvars(r"%TEMP%\cputemp_error.log"), "w") as f:
            f.write(traceback.format_exc())
