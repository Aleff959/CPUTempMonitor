"""
Adversarial Verification Suite for Fulgor PCista (v1.9.0 | Comp. 28 - Black Lightning)
Target Under Test: Fulgor PCista (1.9.0 | Comp. 28)
Archived Build Under Test: FulgorPCista_1.8.0_Comp27.zip (1.8.0 | Comp. 27)
Role: Empirical Challenger (critic, specialist)
Author: challenger_final_1
"""

import os
import sys
import time
import json
import socket
import zipfile
import threading
import unittest
import winreg
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import main
from main import Api
from service_bridge import (
    TelemetryIPCServer,
    TelemetryIPCClient,
    IPC_HOST,
    _get_token_path,
)


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


class TestAdversarialSocketConcurrency(unittest.TestCase):
    """Objective 1: Adversarial Socket & Concurrency Verification."""

    def test_rapid_consecutive_socket_binding_stress(self):
        """
        Stress test: Rapid consecutive start/stop cycles of TelemetryIPCServer.
        Verify SO_EXCLUSIVEADDRUSE enables deterministic binding and clean teardown
        without socket exhaustion or port lockouts across 20 cycles.
        """
        test_port = 49880
        core = DummyTelemetryCore()

        for i in range(20):
            srv = TelemetryIPCServer(core, port=test_port)
            try:
                self.assertIsNotNone(srv.sock, f"Cycle {i}: Server socket should be active")
                # Connect client and verify alive
                client = TelemetryIPCClient(port=test_port, token=srv.auth_token, timeout=1.0)
                self.assertTrue(client.is_alive(), f"Cycle {i}: Server should respond to ping")
            finally:
                srv.stop()

            # Ensure socket is fully closed before next iteration
            time.sleep(0.02)

    def test_multithreaded_race_condition_binding_exclusivity(self):
        """
        Stress test: 16 concurrent threads race simultaneously to bind to the SAME port
        using SO_EXCLUSIVEADDRUSE.
        Oracle: Exactly ONE thread must succeed; all other 15 threads MUST fail with WSAEACCES (WinError 10013).
        """
        test_port = 49882
        exclusive_opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)

        success_count = 0
        failure_count = 0
        lock = threading.Lock()
        barrier = threading.Barrier(16)
        sockets_to_close = []

        def worker():
            nonlocal success_count, failure_count
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, exclusive_opt, 1)
            except Exception:
                pass
            barrier.wait()  # synchronize all threads for simultaneous race
            try:
                s.bind((IPC_HOST, test_port))
                s.listen(5)
                with lock:
                    success_count += 1
                    sockets_to_close.append(s)
            except OSError as e:
                with lock:
                    failure_count += 1
                s.close()

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)

        try:
            self.assertEqual(success_count, 1, f"Expected exactly 1 socket to win race, got {success_count}")
            self.assertEqual(failure_count, 15, f"Expected 15 sockets to fail, got {failure_count}")
        finally:
            for s in sockets_to_close:
                try:
                    s.close()
                except Exception:
                    pass

    def test_adversarial_port_hijack_prevention(self):
        """
        Adversarial attempt to hijack TelemetryIPCServer port with SO_REUSEADDR.
        Must be strictly rejected by Windows OS with WinError 10013.
        """
        test_port = 49883
        core = DummyTelemetryCore()
        srv = TelemetryIPCServer(core, port=test_port)
        try:
            rogue = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rogue.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                with self.assertRaises(OSError) as cm:
                    rogue.bind((IPC_HOST, test_port))
                err_str = str(cm.exception)
                self.assertTrue("10013" in err_str or isinstance(cm.exception, PermissionError))
            finally:
                rogue.close()
        finally:
            srv.stop()


class TestAdversarialIPCExploitDefense(unittest.TestCase):
    """Objective 2: IPC Exploit Defense Verification."""

    def setUp(self):
        self.test_port = 49884
        self.auth_token = "adversarial_secret_token_1234567890abcdef"
        self.core = DummyTelemetryCore()
        self.srv = TelemetryIPCServer(self.core, port=self.test_port, auth_token=self.auth_token)

    def tearDown(self):
        self.srv.stop()

    def _send_raw_json(self, payload):
        with socket.create_connection((IPC_HOST, self.test_port), timeout=1.5) as s:
            s.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            raw = s.recv(4096)
            if not raw:
                return None
            return json.loads(raw.decode("utf-8", errors="ignore").strip())

    def test_unauthenticated_commands_rejection(self):
        """All commands without token must be strictly rejected with 401 Unauthorized."""
        critical_cmds = [
            {"cmd": "shutdown"},
            {"cmd": "get_stats"},
            {"cmd": "set_mode", "mode": "GPU"},
            {"cmd": "set_auto_switch", "enabled": False},
            {"cmd": "set_led", "state": 0},
            {"cmd": "update_session_metrics", "fps": 144.0, "in_game": True},
            {"cmd": "ping"},
            {"cmd": "malicious_eval"},
        ]
        for cmd in critical_cmds:
            with self.subTest(cmd=cmd["cmd"]):
                resp = self._send_raw_json(cmd)
                self.assertIsNotNone(resp)
                self.assertFalse(resp.get("ok"))
                self.assertEqual(resp.get("code"), 401)
                self.assertEqual(resp.get("error"), "Unauthorized")
                self.assertTrue(self.srv.running, "Server must remain active after unauthorized attack")
                self.assertFalse(self.core.closed, "Core must not be closed")

    def test_invalid_tokens_and_timing_attacks(self):
        """Invalid tokens, empty tokens, non-string tokens must return 401."""
        bad_tokens = [
            "wrong_token",
            self.auth_token[:8],  # partial prefix
            "",
            None,
            12345678,
            True,
            False,
            ["token"],
            {"token": "nested"},
        ]
        for tok in bad_tokens:
            with self.subTest(tok=tok):
                payload = {"cmd": "shutdown", "token": tok}
                resp = self._send_raw_json(payload)
                self.assertIsNotNone(resp)
                self.assertFalse(resp.get("ok"))
                self.assertEqual(resp.get("code"), 401)
                self.assertTrue(self.srv.running)

    def test_sqli_null_byte_and_buffer_overflow_injections(self):
        """SQLi, null bytes, and unicode anomalies return 401; oversized buffers are dropped cleanly without crashing server."""
        attack_payloads = [
            "' OR '1'='1",
            "admin'; DROP TABLE telemetry; --",
            "token\x00extra",
            "\x00",
            "\u0000",
            "A" * 1000,
            "'; EXEC xp_cmdshell('calc.exe'); --",
            "<script>alert(1)</script>",
        ]
        for atk in attack_payloads:
            with self.subTest(atk=atk[:20]):
                payload = {"cmd": "shutdown", "auth_token": atk}
                resp = self._send_raw_json(payload)
                self.assertIsNotNone(resp)
                self.assertFalse(resp.get("ok"))
                self.assertEqual(resp.get("code"), 401)
                self.assertTrue(self.srv.running)

        # Oversized buffer (>4096 bytes) test: server should truncate/drop connection cleanly
        with socket.create_connection((IPC_HOST, self.test_port), timeout=1.5) as s:
            s.sendall(json.dumps({"cmd": "shutdown", "auth_token": "B" * 8192}).encode("utf-8") + b"\n")
            try:
                s.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
                pass  # Winsock RST on unread buffer is expected OS behavior

        # Non-JSON binary garbage packet
        with socket.create_connection((IPC_HOST, self.test_port), timeout=1.5) as s:
            s.sendall(b"\xff\x00\xfe\xca\xba\xbe\xef" * 50 + b"\n")
            time.sleep(0.05)

        # Verify server survived all attacks and accepts legitimate authenticated ping
        resp = self._send_raw_json({"cmd": "ping", "auth_token": self.auth_token})
        self.assertIsNotNone(resp)
        self.assertTrue(resp.get("ok"))
        self.assertEqual(resp.get("service"), "FulgorPCistaService")


class TestThemePersistenceStress(unittest.TestCase):
    """Objective 3: Theme Persistence & Fallback Stress."""

    REG_SUBKEYS = [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]

    @classmethod
    def setUpClass(cls):
        cls._saved = {}
        for sub in cls.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                    cls._saved[sub] = winreg.QueryValueEx(key, "selected_theme")
            except OSError:
                cls._saved[sub] = None

    @classmethod
    def tearDownClass(cls):
        for sub, saved in cls._saved.items():
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
            except Exception:
                pass

    def setUp(self):
        self.mock_core = MagicMock()
        self.api = Api(self.mock_core)

    def test_missing_registry_keys_graceful_fallback(self):
        """When registry keys do not exist, get_theme returns 'ambar' without raising."""
        for sub in self.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "selected_theme")
            except OSError:
                pass

        val = self.api.get_theme()
        self.assertEqual(val, "ambar")

    def test_empty_string_registry_fallback(self):
        """When empty string is stored, get_theme returns 'ambar'."""
        self.api.set_theme("")
        val = self.api.get_theme()
        self.assertEqual(val, "ambar")

    def test_corrupted_data_types_in_registry(self):
        """Handle REG_DWORD, REG_BINARY, null bytes, and None gracefully."""
        # Inject REG_DWORD
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
            winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_DWORD, 999)
        val = self.api.get_theme()
        self.assertEqual(val, "999")

        # Inject REG_BINARY
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
            winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_BINARY, b"\x00\x01\x02\x03")
        val = self.api.get_theme()
        self.assertIsInstance(val, str)

        # None input to set_theme
        res = self.api.set_theme(None)
        self.assertTrue(res)
        val = self.api.get_theme()
        self.assertIsInstance(val, str)

    def test_registry_permission_error_graceful_handling(self):
        """Simulate OSError during registry access, verify no unhandled crash."""
        with patch("winreg.OpenKey", side_effect=OSError("Access denied")):
            val = self.api.get_theme()
            self.assertEqual(val, "ambar")

        with patch("winreg.CreateKey", side_effect=OSError("Access denied")):
            res = self.api.set_theme("cyberpunk")
            self.assertTrue(res)


class TestBuildPackagingVerification(unittest.TestCase):
    """Objective 4: Build Packaging Verification for FulgorPCista_1.8.0_Comp27.zip."""

    ZIP_PATH = r"C:\Users\Alpha\OneDrive\Documentos\builds\FulgorPCista_1.8.0_Comp27.zip"

    def test_zip_file_exists_and_valid_size(self):
        """Verify zip file exists and has valid size (approx 15 MB)."""
        self.assertTrue(os.path.exists(self.ZIP_PATH), f"Zip not found at {self.ZIP_PATH}")
        size = os.path.getsize(self.ZIP_PATH)
        # 10 MB < size < 30 MB
        self.assertGreater(size, 10 * 1024 * 1024, f"Zip file too small: {size} bytes")
        self.assertLess(size, 30 * 1024 * 1024, f"Zip file unusually large: {size} bytes")
        print(f"\n[EMPIRICAL PROBE] Build zip verified: {self.ZIP_PATH} ({size} bytes / {size / (1024*1024):.2f} MB)")

    def test_zip_integrity_and_pe_executable(self):
        """Verify zip archive integrity (testzip) and PE executable inside."""
        with zipfile.ZipFile(self.ZIP_PATH, "r") as zf:
            corrupted = zf.testzip()
            self.assertIsNone(corrupted, f"Zip corruption detected in: {corrupted}")

            namelist = zf.namelist()
            self.assertIn("FulgorPCista.exe", namelist, f"FulgorPCista.exe missing from zip. Found: {namelist}")

            # Inspect PE header of FulgorPCista.exe
            with zf.open("FulgorPCista.exe") as exe_f:
                header = exe_f.read(1024)
                self.assertTrue(header.startswith(b"MZ"), "FulgorPCista.exe missing MZ DOS header")
                # Find PE signature
                pe_offset = int.from_bytes(header[0x3C:0x40], byteorder="little")
                exe_f.seek(pe_offset)
                pe_sig = exe_f.read(4)
                self.assertEqual(pe_sig, b"PE\x00\x00", "FulgorPCista.exe missing valid PE signature")

            info = zf.getinfo("FulgorPCista.exe")
            self.assertGreater(info.file_size, 10 * 1024 * 1024, f"Executable file size too small: {info.file_size}")
            print(f"[EMPIRICAL PROBE] FulgorPCista.exe in zip validated: {info.file_size} bytes, CRC: {info.CRC:08X}")


if __name__ == "__main__":
    unittest.main()
