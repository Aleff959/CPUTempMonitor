"""
Automated Verification Test Suite: Milestone 6 / Milestone 4 (R4)
Security Hardening, Themes Persistence, Local Fonts, IPC Exclusivity & Autostart Integrity
Component: Fulgor PCista (v1.9.0 | Comp. 28 - Black Lightning)
Target: cpu-temp-material-you
"""

import os
import sys
import glob
import re
import json
import socket
import tempfile
import threading
import time
import uuid
import unittest
from unittest import mock

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import main
from main import Api
from service_bridge import (
    TelemetryIPCServer,
    TelemetryIPCClient,
    get_secure_executable_path,
    _get_token_path,
    _write_secure_token,
    SERVICE_NAME,
)


class DummyTelemetryCore:
    """Mock telemetry core for headless IPC testing."""

    def __init__(self):
        self.mode = "CPU"
        self.interval = 5.0
        self.auto_sw = 1
        self.led = 1
        self.fps = 0.0
        self.in_game = False
        self.closed = False

    def get_data(self):
        return {
            "cpu_temp": 42.0,
            "active_device": self.mode,
            "auto_switch_fps": self.auto_sw,
            "fps": int(self.fps),
            "in_game": self.in_game,
        }

    def set_mode(self, mode, interval=5.0):
        self.mode = mode
        self.interval = interval
        return True

    def set_auto_switch(self, enabled):
        self.auto_sw = 1 if enabled else 0
        return True

    def set_led(self, state):
        self.led = state
        return True

    def update_external_session_metrics(self, fps, in_game):
        self.fps = fps
        self.in_game = in_game
        return True

    def close(self):
        self.closed = True


class TestThemePersistenceAndLocalFonts(unittest.TestCase):
    """
    R1: Validate theme persistence in dual Windows Registry keys, fallback behavior,
    anti-flash script execution order in <head>, local offline .woff2 fonts,
    CSS consolidation (zero @import / zero !important), and JS redundancy removal.
    """

    REG_SUBKEYS = [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]
    VALID_THEMES = ["ambar", "terracota", "terminal", "synthwave", "default"]

    @classmethod
    def setUpClass(cls):
        import winreg
        cls._saved_values = {}
        for sub in cls.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                    val, typ = winreg.QueryValueEx(key, "selected_theme")
                    cls._saved_values[sub] = (val, typ)
            except OSError:
                cls._saved_values[sub] = None

    @classmethod
    def tearDownClass(cls):
        import winreg
        for sub, saved in cls._saved_values.items():
            try:
                if saved is not None:
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub) as key:
                        winreg.SetValueEx(key, "selected_theme", 0, saved[1], saved[0])
                else:
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_SET_VALUE) as key:
                            winreg.DeleteValue(key, "selected_theme")
                    except OSError:
                        pass
            except Exception as e:
                print(f"[Warning] Failed to restore registry key {sub}: {e}")

    def setUp(self):
        self.mock_core = mock.MagicMock()
        self.api = Api(self.mock_core)

    def test_theme_persistence_roundtrip(self):
        """
        Validate Api.set_theme / Api.get_theme roundtrip across all 5 themes,
        confirm dual registry persistence in HKCU\\Software\\Fulgor PCista and
        HKCU\\Software\\CPU TEMP Monitor, and verify graceful fallback to 'ambar'.
        """
        import winreg

        # 1. Roundtrip test for all 5 valid themes
        for theme in self.VALID_THEMES:
            with self.subTest(theme=theme):
                success = self.api.set_theme(theme)
                self.assertTrue(success, f"Api.set_theme failed for theme '{theme}'")

                # Verify primary registry key
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
                    val, typ = winreg.QueryValueEx(key, "selected_theme")
                    self.assertEqual(typ, winreg.REG_SZ)
                    self.assertEqual(val, theme, f"Primary registry mismatch for '{theme}'")

                # Verify secondary registry key
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\CPU TEMP Monitor") as key:
                    val, typ = winreg.QueryValueEx(key, "selected_theme")
                    self.assertEqual(typ, winreg.REG_SZ)
                    self.assertEqual(val, theme, f"Secondary registry mismatch for '{theme}'")

                # Verify Api.get_theme() retrieves it
                retrieved = self.api.get_theme()
                self.assertEqual(retrieved, theme, f"Api.get_theme returned '{retrieved}', expected '{theme}'")

        # 2. Test fallback to 'ambar' when registry contains empty string
        for sub in self.REG_SUBKEYS:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub) as key:
                winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_SZ, "")
        fallback_val = self.api.get_theme()
        self.assertEqual(fallback_val, "ambar", f"Expected fallback to 'ambar' on empty string, got '{fallback_val}'")

        # 3. Test fallback to 'ambar' when selected_theme value is deleted from both keys
        for sub in self.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "selected_theme")
            except OSError:
                pass
        fallback_deleted = self.api.get_theme()
        self.assertEqual(fallback_deleted, "ambar", f"Expected fallback to 'ambar' when deleted, got '{fallback_deleted}'")

    def test_antiflash_script_present_in_head(self):
        """
        In ui/index.html, verify that the synchronous anti-flash script is positioned
        strictly in <head> after <link id="themeStylesheet"> and before </head>.
        """
        index_path = os.path.join(PROJECT_ROOT, "ui", "index.html")
        self.assertTrue(os.path.exists(index_path), f"ui/index.html not found at {index_path}")

        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()

        head_open = content.find("<head>")
        head_close = content.find("</head>")
        self.assertNotEqual(head_open, -1, "<head> tag not found in ui/index.html")
        self.assertNotEqual(head_close, -1, "</head> tag not found in ui/index.html")
        self.assertLess(head_open, head_close, "<head> must appear before </head>")

        link_tag = '<link id="themeStylesheet" rel="stylesheet" href="">'
        link_pos = content.find(link_tag)
        self.assertNotEqual(link_pos, -1, f"Link tag {link_tag} not found in ui/index.html")
        self.assertGreater(link_pos, head_open, "themeStylesheet link must be inside <head>")
        self.assertLess(link_pos, head_close, "themeStylesheet link must be before </head>")

        # The synchronous anti-flash script must be located between link_pos and head_close
        head_segment = content[link_pos:head_close]
        self.assertIn("<script>", head_segment, "Synchronous <script> tag missing after themeStylesheet link in <head>")
        self.assertIn("localStorage.getItem('fulgor_theme')", head_segment, "Anti-flash script must read localStorage 'fulgor_theme'")
        self.assertIn("document.getElementById('themeStylesheet')", head_segment, "Anti-flash script must access themeStylesheet")
        self.assertIn("'ambar': 'themes/tema-ambar.css'", head_segment, "Anti-flash script must map 'ambar'")
        self.assertIn("'terracota': 'themes/tema-manrope-terracota.css'", head_segment, "Anti-flash script must map 'terracota'")
        self.assertIn("'terminal': 'themes/tema-terminal-matrix.css'", head_segment, "Anti-flash script must map 'terminal'")
        self.assertIn("'synthwave': 'themes/tema-synthwave-neon.css'", head_segment, "Anti-flash script must map 'synthwave'")

    def test_all_woff2_fonts_present_and_valid(self):
        """
        Verify that all 6 .woff2 font files exist in ui/fonts/ and start with
        the authentic b'wOF2' magic header.
        """
        fonts_dir = os.path.join(PROJECT_ROOT, "ui", "fonts")
        self.assertTrue(os.path.isdir(fonts_dir), f"ui/fonts directory not found at {fonts_dir}")

        expected_fonts = [
            "ibm-plex-sans.woff2",
            "ibm-plex-mono-400.woff2",
            "ibm-plex-mono-600.woff2",
            "manrope.woff2",
            "outfit.woff2",
            "jetbrains-mono.woff2",
        ]

        for font_name in expected_fonts:
            with self.subTest(font=font_name):
                font_path = os.path.join(fonts_dir, font_name)
                self.assertTrue(os.path.isfile(font_path), f"Font file missing: {font_path}")
                size = os.path.getsize(font_path)
                self.assertGreater(size, 1000, f"Font file {font_name} is abnormally small ({size} bytes)")

                with open(font_path, "rb") as f:
                    magic = f.read(4)
                    self.assertEqual(magic, b"wOF2", f"Font {font_name} header is not 'wOF2' (got {magic!r})")

    def test_css_themes_zero_import_zero_important(self):
        """
        Verify that all 4 theme CSS files in ui/themes/*.css contain 0 @import
        directives and 0 !important declarations, ensuring 100% offline purity
        and clean CSS variable overriding.
        """
        themes_dir = os.path.join(PROJECT_ROOT, "ui", "themes")
        self.assertTrue(os.path.isdir(themes_dir), f"ui/themes directory not found at {themes_dir}")

        theme_files = glob.glob(os.path.join(themes_dir, "*.css"))
        self.assertEqual(len(theme_files), 4, f"Expected exactly 4 theme CSS files, found {len(theme_files)}")

        expected_basenames = {
            "tema-ambar.css",
            "tema-manrope-terracota.css",
            "tema-synthwave-neon.css",
            "tema-terminal-matrix.css",
        }
        found_basenames = {os.path.basename(p) for p in theme_files}
        self.assertEqual(found_basenames, expected_basenames, f"Theme files mismatch: {found_basenames}")

        for theme_path in theme_files:
            bname = os.path.basename(theme_path)
            with self.subTest(theme=bname):
                with open(theme_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Rule: Zero external or local @import directives
                import_count = len(re.findall(r"@import\b", content, re.IGNORECASE))
                self.assertEqual(import_count, 0, f"Found {import_count} @import directive(s) in {bname}")

                # Rule: Zero !important declarations
                important_count = len(re.findall(r"!important\b", content, re.IGNORECASE))
                self.assertEqual(important_count, 0, f"Found {important_count} !important declaration(s) in {bname}")

                # Verify each theme declares local @font-face and :root variables
                self.assertIn("@font-face", content, f"Missing @font-face definition in {bname}")
                self.assertIn(":root", content, f"Missing :root variable block in {bname}")
                self.assertIn("../fonts/", content, f"Font src does not reference relative ../fonts/ in {bname}")

    def test_js_redundancy_removed(self):
        """
        Verify that ui/index.html does not contain redundant
        `currentThemeKey === 'default'` inline style mutations in updateUi().
        """
        index_path = os.path.join(PROJECT_ROOT, "ui", "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check absence of redundant JS conditional branching
        self.assertNotIn(
            "currentThemeKey === 'default'",
            content,
            "Redundant 'currentThemeKey === \\'default\\'' found in ui/index.html",
        )
        self.assertNotIn(
            'currentThemeKey === "default"',
            content,
            "Redundant 'currentThemeKey === \"default\"' found in ui/index.html",
        )


class TestIPCSocketAndTokenSecurity(unittest.TestCase):
    """
    R2: Validate localhost TCP socket exclusivity (SO_EXCLUSIVEADDRUSE),
    cryptographic token authorization, rejection of unauthenticated requests (HTTP 401),
    and standard user token read permissions.
    """

    def setUp(self):
        self.core = DummyTelemetryCore()

    def test_ipc_so_exclusiveaddruse_blocks_rebinding(self):
        """
        Spin up a TelemetryIPCServer and assert that attempting a secondary socket
        bind on the same port with SO_REUSEADDR raises PermissionError or WinError 10013.
        """
        test_port = 49891
        srv = TelemetryIPCServer(self.core, port=test_port)
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                with self.assertRaises((PermissionError, OSError)) as cm:
                    s2.bind(("127.0.0.1", test_port))
                err_str = str(cm.exception)
                # On Windows, SO_EXCLUSIVEADDRUSE collisions raise WinError 10013 (WSAEACCES)
                self.assertTrue(
                    "10013" in err_str or isinstance(cm.exception, PermissionError),
                    f"Expected WinError 10013 or PermissionError, got: {err_str}",
                )
            finally:
                s2.close()
        finally:
            srv.stop()

    def test_ipc_unauthenticated_request_rejected(self):
        """
        Connect via raw socket and send commands without a token or with an invalid token.
        Assert that response code is 401 and the service daemon is not stopped by 'shutdown'.
        """
        test_port = 49892
        srv = TelemetryIPCServer(self.core, port=test_port)
        try:
            # 1. Unauthenticated shutdown command attempt
            with socket.create_connection(("127.0.0.1", test_port), timeout=2.0) as sock:
                req = json.dumps({"cmd": "shutdown"}).encode("utf-8") + b"\n"
                sock.sendall(req)
                raw_resp = sock.recv(4096).decode("utf-8")
                resp = json.loads(raw_resp.strip())

                self.assertFalse(resp.get("ok"), "Unauthenticated shutdown must not return ok: True")
                self.assertEqual(resp.get("code"), 401, f"Expected HTTP 401 code, got: {resp}")
                self.assertEqual(resp.get("error"), "Unauthorized")

            # Assert service daemon is still running and core was not closed
            self.assertTrue(srv.running, "Server must remain running after unauthenticated shutdown")
            self.assertFalse(self.core.closed, "Telemetry core must NOT be closed by unauthenticated shutdown")

            # 2. Unauthenticated get_stats command attempt
            with socket.create_connection(("127.0.0.1", test_port), timeout=2.0) as sock:
                req = json.dumps({"cmd": "get_stats"}).encode("utf-8") + b"\n"
                sock.sendall(req)
                raw_resp = sock.recv(4096).decode("utf-8")
                resp = json.loads(raw_resp.strip())

                self.assertFalse(resp.get("ok"), "Unauthenticated get_stats must not return ok: True")
                self.assertEqual(resp.get("code"), 401)
                self.assertEqual(resp.get("error"), "Unauthorized")

            # 3. Invalid token attempt
            with socket.create_connection(("127.0.0.1", test_port), timeout=2.0) as sock:
                req = json.dumps({"cmd": "get_stats", "auth_token": "malicious_fake_token"}).encode("utf-8") + b"\n"
                sock.sendall(req)
                raw_resp = sock.recv(4096).decode("utf-8")
                resp = json.loads(raw_resp.strip())

                self.assertFalse(resp.get("ok"))
                self.assertEqual(resp.get("code"), 401)
        finally:
            srv.stop()

    def test_ipc_authenticated_request_succeeds(self):
        """
        Connect with a valid cryptographic token. Assert that 'ping' and 'get_stats'
        return {"ok": True} and telemetry payload is properly delivered.
        """
        test_port = 49893
        srv = TelemetryIPCServer(self.core, port=test_port)
        try:
            # 1. Raw socket with auth_token for 'ping'
            with socket.create_connection(("127.0.0.1", test_port), timeout=2.0) as sock:
                req = json.dumps({"cmd": "ping", "auth_token": srv.auth_token}).encode("utf-8") + b"\n"
                sock.sendall(req)
                raw_resp = sock.recv(4096).decode("utf-8")
                resp = json.loads(raw_resp.strip())
                self.assertTrue(resp.get("ok"), f"Authenticated ping failed: {resp}")
                self.assertEqual(resp.get("service"), SERVICE_NAME)

            # 2. Raw socket with auth_token for 'get_stats'
            with socket.create_connection(("127.0.0.1", test_port), timeout=2.0) as sock:
                req = json.dumps({"cmd": "get_stats", "auth_token": srv.auth_token}).encode("utf-8") + b"\n"
                sock.sendall(req)
                raw_resp = sock.recv(4096).decode("utf-8")
                resp = json.loads(raw_resp.strip())
                self.assertTrue(resp.get("ok"), f"Authenticated get_stats failed: {resp}")
                self.assertEqual(resp.get("data", {}).get("cpu_temp"), 42.0)
                self.assertTrue(resp.get("data", {}).get("service_active"))

            # 3. TelemetryIPCClient auto-auth test
            client = TelemetryIPCClient(port=test_port)
            self.assertTrue(client.is_alive(), "TelemetryIPCClient should report is_alive() == True")
            stats = client.get_data()
            self.assertIsNotNone(stats)
            self.assertEqual(stats["cpu_temp"], 42.0)
        finally:
            srv.stop()

    def test_ipc_token_standard_user_readable(self):
        """
        Verify that _write_secure_token creates a token file that is readable by standard
        interactive users (granting read access to S-1-5-32-545 and S-1-5-11).
        """
        temp_dir = tempfile.gettempdir()
        token_filename = f"test_token_{os.getpid()}_{uuid.uuid4().hex[:8]}.token"
        token_path = os.path.join(temp_dir, token_filename)
        secret_payload = uuid.uuid4().hex

        try:
            _write_secure_token(token_path, secret_payload)
            self.assertTrue(os.path.exists(token_path), "Token file was not created on disk")

            # Verify standard user read access
            with open(token_path, "r", encoding="utf-8") as f:
                read_back = f.read().strip()
            self.assertEqual(read_back, secret_payload, "Read token payload does not match written secret")

            # Verify DACL ACE entries if win32security is available
            try:
                import win32security
                import ntsecuritycon

                sd = win32security.GetFileSecurity(token_path, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                self.assertIsNotNone(dacl, "DACL is missing from token file security descriptor")

                user_sids = {"S-1-5-32-545", "S-1-5-11"}
                found_sids = set()
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid_str = win32security.ConvertSidToStringSid(ace[2])
                    if sid_str in user_sids:
                        found_sids.add(sid_str)
                        mask = ace[1]
                        has_read = bool(mask & ntsecuritycon.GENERIC_READ) or bool(mask & ntsecuritycon.FILE_GENERIC_READ)
                        self.assertTrue(has_read, f"SID {sid_str} does not have Read permission (mask: {mask})")

                self.assertGreater(len(found_sids), 0, f"Expected standard user SIDs {user_sids} in DACL, found {found_sids}")
            except ImportError:
                pass
        finally:
            if os.path.exists(token_path):
                try:
                    os.remove(token_path)
                except Exception:
                    pass


class TestServiceAndAutostartPathIntegrity(unittest.TestCase):
    """
    R2: Validate path hygiene (zero residual user paths), secure executable path
    resolution and rejection of user/temp paths, autostart task configuration targeting
    Program Files, and canonical ExecutablePath process filtering.
    """

    def test_no_residual_user_paths(self):
        """
        Verify service_bridge.py and configurar_autostart.ps1 contain 0 hardcoded
        user paths (C:\\Users\\) and configurar_autostart.ps1 contains 0 LOCALAPPDATA references.
        """
        # 1. service_bridge.py - verify zero hardcoded C:\Users\ paths
        sb_path = os.path.join(PROJECT_ROOT, "service_bridge.py")
        with open(sb_path, "r", encoding="utf-8") as f:
            sb_content = f.read()

        self.assertFalse(
            bool(re.search(r"C:\\Users\\", sb_content, re.IGNORECASE)),
            "Residual 'C:\\Users\\' path found in service_bridge.py",
        )
        self.assertFalse(
            bool(re.search(r"C:/Users/", sb_content, re.IGNORECASE)),
            "Residual 'C:/Users/' path found in service_bridge.py",
        )

        # 2. configurar_autostart.ps1 - verify zero LOCALAPPDATA and zero C:\Users\ paths
        ps_path = os.path.join(PROJECT_ROOT, "configurar_autostart.ps1")
        with open(ps_path, "r", encoding="utf-8") as f:
            ps_content = f.read()

        self.assertFalse(
            bool(re.search(r"C:\\Users\\", ps_content, re.IGNORECASE)),
            "Residual 'C:\\Users\\' path found in configurar_autostart.ps1",
        )
        self.assertNotIn("LOCALAPPDATA", ps_content, "LOCALAPPDATA reference found in configurar_autostart.ps1")

    def test_get_secure_executable_path_raises_on_untrusted(self):
        """
        Verify get_secure_executable_path() raises FileNotFoundError when pointed
        to user or temporary directories, preventing Local Privilege Escalation (LPE).
        """
        temp_dir = tempfile.gettempdir()
        dummy_exe = os.path.join(temp_dir, f"untrusted_test_{uuid.uuid4().hex[:6]}.exe")
        with open(dummy_exe, "w") as f:
            f.write("mock binary")

        try:
            # 1. Non-frozen mode with sys.argv[0] pointing to user/temp directory
            with mock.patch("os.path.exists", side_effect=lambda p: p == dummy_exe):
                with mock.patch.object(sys, "argv", [dummy_exe]):
                    with mock.patch.object(sys, "frozen", False, create=True):
                        with self.assertRaises(FileNotFoundError) as cm:
                            get_secure_executable_path()
                        self.assertIn("A execução a partir de diretórios de usuário é proibida", str(cm.exception))

            # 2. Frozen mode with sys.executable in temp directory
            with mock.patch.object(sys, "frozen", True, create=True):
                with mock.patch.object(sys, "executable", dummy_exe):
                    with self.assertRaises(FileNotFoundError):
                        get_secure_executable_path()

            # 3. Frozen mode with sys.executable in user profile directory
            fake_user_exe = r"C:\Users\Alpha\Downloads\FulgorPCista.exe"
            with mock.patch.object(sys, "frozen", True, create=True):
                with mock.patch.object(sys, "executable", fake_user_exe):
                    with self.assertRaises(FileNotFoundError):
                        get_secure_executable_path()

            # 4. Canonical path completely absent
            with mock.patch("os.path.exists", return_value=False):
                with self.assertRaises(FileNotFoundError) as cm:
                    get_secure_executable_path()
                self.assertIn("Program Files", str(cm.exception))
        finally:
            if os.path.exists(dummy_exe):
                try:
                    os.remove(dummy_exe)
                except Exception:
                    pass

    def test_autostart_task_targets_program_files(self):
        """
        Parse configurar_autostart.ps1 and verify that both SYSTEM BootTrigger
        and User LogonTrigger tasks specify C:\\Program Files\\FulgorPCista\\FulgorPCista.exe.
        """
        ps_path = os.path.join(PROJECT_ROOT, "configurar_autostart.ps1")
        with open(ps_path, "r", encoding="utf-8") as f:
            ps_code = f.read()

        # Check target directory and binary definition
        self.assertIn('${env:ProgramFiles}', ps_code, "Target directory must use ${env:ProgramFiles}")
        self.assertIn('"FulgorPCista"', ps_code, "Target directory must be under FulgorPCista")
        self.assertIn('"FulgorPCista.exe"', ps_code, "Target binary must be FulgorPCista.exe")

        # Verify task names
        self.assertIn("FulgorPCista_BootService", ps_code, "Task URI FulgorPCista_BootService missing")
        self.assertIn("FulgorPCista_AutoStart", ps_code, "Task URI FulgorPCista_AutoStart missing")

        # Verify SYSTEM BootTrigger definition
        self.assertIn("<UserId>S-1-5-18</UserId>", ps_code, "Boot task must run under SYSTEM (S-1-5-18)")
        self.assertIn("<BootTrigger>", ps_code, "Boot task must define <BootTrigger>")
        self.assertIn("<Arguments>-daemon</Arguments>", ps_code, "Boot task must pass -daemon argument")

        # Verify User LogonTrigger definition
        self.assertIn("<LogonTrigger>", ps_code, "Logon task must define <LogonTrigger>")
        self.assertIn("<Arguments>-hide</Arguments>", ps_code, "Logon task must pass -hide argument")

        # Verify both tasks execute $exePath, which is assigned exclusively to $targetExe
        self.assertIn("<Command>$exePath</Command>", ps_code, "Tasks must execute $exePath")
        self.assertIn("$exePath = $targetExe", ps_code, "$exePath must be assigned from $targetExe")

    def test_cleanup_processes_validates_executable_path(self):
        """
        Verify that _cleanup_legacy_and_stale_processes inspects canonical ExecutablePath,
        preserves daemon/service instances and processes outside authorized path,
        and terminates only stale UI instances from the authorized path.
        """
        class MockProcess:
            def __init__(self, pid, name, exe_path, cmdline):
                self.pid = pid
                self.info = {
                    "pid": pid,
                    "name": name,
                    "exe": exe_path,
                    "cmdline": cmdline,
                }
                self.terminated = False
                self.killed = False

            def exe(self):
                return self.info["exe"]

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                pass

            def kill(self):
                self.killed = True

        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        authorized_exe = os.path.join(prog_files, "FulgorPCista", "FulgorPCista.exe")

        # Process 1: Coinciding name in C:\Temp (untrusted) -> MUST NOT be terminated
        p_untrusted = MockProcess(9001, "FulgorPCista.exe", r"C:\Temp\FulgorPCista.exe", [])

        # Process 2: Authorized path with -daemon flag -> MUST NOT be terminated
        p_daemon = MockProcess(9002, "FulgorPCista.exe", authorized_exe, ["-daemon"])

        # Process 3: Authorized path with --service flag -> MUST NOT be terminated
        p_service = MockProcess(9003, "FulgorPCista.exe", authorized_exe, ["--service"])

        # Process 4: Authorized path stale UI instance (-hide) -> MUST be terminated
        p_stale_ui = MockProcess(9004, "FulgorPCista.exe", authorized_exe, ["-hide"])

        mock_procs = [p_untrusted, p_daemon, p_service, p_stale_ui]

        with mock.patch("psutil.process_iter", return_value=mock_procs):
            main._cleanup_legacy_and_stale_processes()

        self.assertFalse(p_untrusted.terminated, "Process outside authorized path must NOT be terminated")
        self.assertFalse(p_daemon.terminated, "Daemon instance with -daemon must NOT be terminated")
        self.assertFalse(p_service.terminated, "Service instance with --service must NOT be terminated")
        self.assertTrue(p_stale_ui.terminated, "Stale UI instance in authorized path MUST be terminated")


if __name__ == "__main__":
    unittest.main()
