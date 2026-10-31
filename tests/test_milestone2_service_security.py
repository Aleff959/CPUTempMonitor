import os
import sys
import re
import socket
import json
import tempfile
import unittest
import unittest.mock as mock

from service_bridge import (
    TelemetryIPCServer,
    TelemetryIPCClient,
    get_secure_executable_path,
    _get_token_path,
    _write_secure_token,
)
import main


class DummyTelemetryCore:
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


class TestServiceSecurityM2(unittest.TestCase):
    """Automated security verification for Milestone 2 (IPC Hardening, Autostart & Process Cleanup)."""

    def test_socket_so_exclusiveaddruse(self):
        """Task 1: Verify socket is hardened with SO_EXCLUSIVEADDRUSE, preventing co-binding."""
        core = DummyTelemetryCore()
        test_port = 49881
        srv = TelemetryIPCServer(core, port=test_port)
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                with self.assertRaises((PermissionError, OSError)) as cm:
                    s2.bind(("127.0.0.1", test_port))
                # On Windows, this raises WinError 10013 (WSAEACCES)
                self.assertIn("10013", str(cm.exception))
            finally:
                s2.close()
        finally:
            srv.stop()

    def test_ipc_unauthenticated_connection_rejected(self):
        """Task 2: Verify unauthenticated commands (especially shutdown) are rejected with 401."""
        core = DummyTelemetryCore()
        test_port = 49882
        srv = TelemetryIPCServer(core, port=test_port)
        try:
            # 1. Unauthenticated shutdown attempt via raw socket
            with socket.create_connection(("127.0.0.1", test_port), timeout=1.0) as s:
                s.sendall(json.dumps({"cmd": "shutdown"}).encode("utf-8") + b"\n")
                raw = s.recv(4096).decode("utf-8")
                resp = json.loads(raw.strip())
                self.assertFalse(resp["ok"])
                self.assertEqual(resp["code"], 401)
                self.assertIn("Unauthorized", resp["error"])
                self.assertTrue(srv.running, "Server must remain running after unauthorized shutdown call")
                self.assertFalse(core.closed, "Core must not be closed")

            # 2. Invalid token get_stats attempt
            with socket.create_connection(("127.0.0.1", test_port), timeout=1.0) as s:
                s.sendall(json.dumps({"cmd": "get_stats", "auth_token": "invalid_token_12345"}).encode("utf-8") + b"\n")
                raw = s.recv(4096).decode("utf-8")
                resp = json.loads(raw.strip())
                self.assertFalse(resp["ok"])
                self.assertEqual(resp["code"], 401)
        finally:
            srv.stop()

    def test_ipc_authenticated_commands_succeed(self):
        """Task 2: Verify TelemetryIPCClient automatically authenticates with token."""
        core = DummyTelemetryCore()
        test_port = 49883
        srv = TelemetryIPCServer(core, port=test_port)
        try:
            client = TelemetryIPCClient(port=test_port)
            self.assertTrue(client.is_alive())

            data = client.get_data()
            self.assertIsNotNone(data)
            self.assertEqual(data["cpu_temp"], 42.0)
            self.assertTrue(data["service_active"])

            self.assertTrue(client.set_mode("GPU", 2.0))
            self.assertEqual(core.mode, "GPU")
            self.assertEqual(core.interval, 2.0)

            self.assertTrue(client.set_auto_switch(False))
            self.assertEqual(core.auto_sw, 0)

            self.assertTrue(client.set_led(0))
            self.assertEqual(core.led, 0)

            self.assertTrue(client.send_session_metrics(120.0, True))
            self.assertEqual(core.fps, 120.0)
            self.assertTrue(core.in_game)
        finally:
            srv.stop()

    def test_no_residual_user_paths_in_service_bridge_and_autostart(self):
        """Task 3 & 4: Ensure zero hardcoded user paths in service_bridge.py and configurar_autostart.ps1."""
        repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 1. service_bridge.py
        sb_path = os.path.join(repo_dir, "service_bridge.py")
        with open(sb_path, "r", encoding="utf-8") as f:
            sb_content = f.read()
        self.assertFalse(
            bool(re.search(r"C:\\Users\\", sb_content, re.IGNORECASE)),
            "Residual C:\\Users\\ path found in service_bridge.py",
        )

        # 2. configurar_autostart.ps1
        ps_path = os.path.join(repo_dir, "configurar_autostart.ps1")
        with open(ps_path, "r", encoding="utf-8") as f:
            ps_content = f.read()
        self.assertNotIn("LOCALAPPDATA", ps_content, "LOCALAPPDATA reference found in configurar_autostart.ps1")
        self.assertNotIn("C:\\Users\\", ps_content, "Residual C:\\Users\\ path found in configurar_autostart.ps1")
        self.assertIn("FulgorPCista_BootService", ps_content)
        self.assertIn("FulgorPCista_AutoStart", ps_content)
        self.assertIn("ProgramFiles", ps_content)

    def test_get_secure_executable_path_resolution_and_failure(self):
        """Task 3: Test secure path resolution and explicit FileNotFoundError failure."""
        # When secure path exists (in dev repository dist\FulgorPCista.exe exists)
        p = get_secure_executable_path()
        self.assertTrue(os.path.exists(p))
        self.assertIn("FulgorPCista.exe", p)

        # When no safe executable exists, must raise FileNotFoundError
        with mock.patch("os.path.exists", return_value=False):
            with self.assertRaises(FileNotFoundError) as cm:
                get_secure_executable_path()
            self.assertIn("Program Files", str(cm.exception))

    def test_cleanup_legacy_and_stale_processes_executable_validation(self):
        """Task 5: Test ExecutablePath validation in _cleanup_legacy_and_stale_processes."""
        class MockProc:
            def __init__(self, pid, name, exe, cmdline):
                self.pid = pid
                self.info = {"pid": pid, "name": name, "exe": exe, "cmdline": cmdline}
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

        prog_files_exe = r"C:\Program Files\FulgorPCista\FulgorPCista.exe"

        # Process 1: Coinciding name in C:\Temp (unauthorized path) -> MUST NOT be terminated
        p_unauth = MockProc(8001, "FulgorPCista.exe", r"C:\Temp\FulgorPCista.exe", [])
        # Process 2: Daemon instance in authorized path -> MUST NOT be terminated
        p_daemon = MockProc(8002, "FulgorPCista.exe", prog_files_exe, ["-daemon"])
        # Process 3: Service instance in authorized path -> MUST NOT be terminated
        p_service = MockProc(8003, "FulgorPCista.exe", prog_files_exe, ["--service"])
        # Process 4: Stale UI instance in authorized path -> MUST be terminated
        p_stale_ui = MockProc(8004, "FulgorPCista.exe", prog_files_exe, ["-hide"])

        mock_procs = [p_unauth, p_daemon, p_service, p_stale_ui]
        with mock.patch("psutil.process_iter", return_value=mock_procs):
            main._cleanup_legacy_and_stale_processes()

        self.assertFalse(p_unauth.terminated, "Process outside authorized path must not be terminated")
        self.assertFalse(p_daemon.terminated, "Daemon process with -daemon must not be terminated")
        self.assertFalse(p_service.terminated, "Service process with --service must not be terminated")
        self.assertTrue(p_stale_ui.terminated, "Stale UI process in authorized path must be terminated")

    def test_socket_synchronous_binding_concurrency_no_race(self):
        """Task 1: Verify synchronous socket binding eliminates any race condition across rapid iterations."""
        core = DummyTelemetryCore()
        for idx in range(5):
            port = 49920 + idx
            srv = TelemetryIPCServer(core, port=port)
            try:
                # Immediate attempt to hijack/rebind with SO_REUSEADDR must fail immediately
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    with self.assertRaises((PermissionError, OSError)) as cm:
                        s.bind(("127.0.0.1", port))
                    self.assertTrue("10013" in str(cm.exception) or isinstance(cm.exception, PermissionError))
                finally:
                    s.close()
            finally:
                srv.stop()

    def test_get_secure_executable_path_rejects_user_and_temp_directories(self):
        """Task 3: Ensure get_secure_executable_path rejects untrusted user or temporary paths."""
        # 1. Unsafe sys.argv[0] must not be returned
        temp_bad = os.path.join(tempfile.gettempdir(), "untrusted_payload.exe")
        with open(temp_bad, "w") as f:
            f.write("dummy")
        try:
            with mock.patch("os.path.exists", side_effect=lambda p: p == temp_bad):
                with mock.patch.object(sys, "argv", [temp_bad]):
                    with mock.patch.object(sys, "frozen", False, create=True):
                        with self.assertRaises(FileNotFoundError) as cm:
                            get_secure_executable_path()
                        self.assertIn("A execução a partir de diretórios de usuário é proibida", str(cm.exception))

            # 2. Frozen executable in temp directory must raise FileNotFoundError
            with mock.patch.object(sys, "frozen", True, create=True):
                with mock.patch.object(sys, "executable", temp_bad):
                    with self.assertRaises(FileNotFoundError):
                        get_secure_executable_path()

            # 3. Frozen executable in user profile (C:\Users\...) must raise FileNotFoundError
            fake_user_exe = r"C:\Users\Alpha\Downloads\FulgorPCista.exe"
            with mock.patch.object(sys, "frozen", True, create=True):
                with mock.patch.object(sys, "executable", fake_user_exe):
                    with self.assertRaises(FileNotFoundError):
                        get_secure_executable_path()
        finally:
            if os.path.exists(temp_bad):
                try:
                    os.remove(temp_bad)
                except Exception:
                    pass

    def test_ipc_token_acl_standard_users_read_access(self):
        """Task 4: Ensure _write_secure_token grants Read-Only access to standard users and Authenticated Users."""
        temp_token = os.path.join(tempfile.gettempdir(), f"test_sec_{os.getpid()}.token")
        try:
            _write_secure_token(temp_token, "test_token_secret_12345")
            self.assertTrue(os.path.exists(temp_token))

            # File must be readable by unelevated process / current user
            with open(temp_token, "r", encoding="utf-8") as f:
                content = f.read().strip()
            self.assertEqual(content, "test_token_secret_12345")

            # If win32security is available, verify S-1-5-32-545 (Users) or S-1-5-11 (Authenticated Users) in DACL
            try:
                import win32security
                import ntsecuritycon
                sd = win32security.GetFileSecurity(temp_token, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                self.assertIsNotNone(dacl)

                user_sids = {"S-1-5-32-545", "S-1-5-11"}
                found_sids = set()
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid_str = win32security.ConvertSidToStringSid(ace[2])
                    if sid_str in user_sids:
                        found_sids.add(sid_str)
                        # Verify it has read permission
                        mask = ace[1]
                        self.assertTrue(bool(mask & ntsecuritycon.GENERIC_READ) or bool(mask & ntsecuritycon.FILE_GENERIC_READ))

                self.assertTrue(len(found_sids) > 0, f"Expected standard user SIDs {user_sids} in DACL, got {found_sids}")
            except ImportError:
                pass
        finally:
            if os.path.exists(temp_token):
                try:
                    os.remove(temp_token)
                except Exception:
                    pass

    def test_client_token_invalidation_on_401(self):
        """Task 2: Verify TelemetryIPCClient invalidates cached token on HTTP 401 response and recovers."""
        core = DummyTelemetryCore()
        test_port = 49884
        srv = TelemetryIPCServer(core, port=test_port)
        try:
            # Client created with stale / invalid token
            client = TelemetryIPCClient(port=test_port, token="stale_invalid_token")
            self.assertEqual(client.token, "stale_invalid_token")

            # Request fails with 401, which invalidates client.token
            res = client._request({"cmd": "ping"})
            self.assertIsNotNone(res)
            self.assertFalse(res.get("ok"))
            self.assertEqual(res.get("code"), 401)
            self.assertIsNone(client.token, "client.token must be invalidated to None after receiving 401")

            # Subsequent request re-loads valid token from disk and succeeds
            self.assertTrue(client.is_alive())
            self.assertIsNotNone(client.token)
            self.assertEqual(client.token, srv.auth_token)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()

