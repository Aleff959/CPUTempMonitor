"""
Adversarial Empirical Verification Suite for Milestone 2 (R2 Socket & IPC Security)
Author: challenger_m2_1 (Empirical Challenger)
Target: service_bridge.py (TelemetryIPCServer, TelemetryIPCClient, SO_EXCLUSIVEADDRUSE)
"""

import os
import sys
import json
import socket
import unittest
from unittest.mock import patch, MagicMock

# Ensure repo root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from service_bridge import (
    TelemetryIPCServer,
    TelemetryIPCClient,
    get_secure_executable_path,
    _get_token_path,
    _write_secure_token,
    IPC_HOST,
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
            "cpu_temp": 45.0,
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


class TestChallengerM2Adversarial(unittest.TestCase):
    """Adversarial stress-testing of IPC socket binding, authentication, and command dispatch."""

    def test_adversarial_socket_rebinding_attack(self):
        """
        Adversarial Test 1:
        Attempt socket hijacking / co-binding using SO_REUSEADDR against TelemetryIPCServer.
        Windows must reject secondary bind with [WinError 10013] (WSAEACCES).
        """
        test_port = 49870
        core = DummyTelemetryCore()
        srv = TelemetryIPCServer(core, port=test_port)

        try:
            # 1. Attacker creates secondary raw socket with SO_REUSEADDR
            attacker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            attacker_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                with self.assertRaises((PermissionError, OSError)) as cm:
                    attacker_sock.bind((IPC_HOST, test_port))

                # Verify WinError 10013 (WSAEACCES / PermissionError)
                err_str = str(cm.exception)
                self.assertTrue(
                    "10013" in err_str or isinstance(cm.exception, PermissionError),
                    f"Expected WinError 10013 or PermissionError, got: {err_str}",
                )
                print(f"\n[EMPIRICAL PROBE] Secondary bind with SO_REUSEADDR blocked: {cm.exception}")
            finally:
                attacker_sock.close()

            # 2. Attacker attempts binding on INADDR_ANY (0.0.0.0) with SO_REUSEADDR
            attacker_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            attacker_sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                # On Windows, when 127.0.0.1 is bound with SO_EXCLUSIVEADDRUSE, binding 0.0.0.0 may also fail or be prevented
                try:
                    attacker_sock2.bind(("0.0.0.0", test_port))
                    # If bind succeeded on 0.0.0.0, check if connecting to 127.0.0.1 still routes to srv
                    with socket.create_connection((IPC_HOST, test_port), timeout=1.0) as conn:
                        conn.sendall(json.dumps({"cmd": "ping", "auth_token": srv.auth_token}).encode("utf-8") + b"\n")
                        raw = conn.recv(4096).decode("utf-8")
                        resp = json.loads(raw.strip())
                        self.assertEqual(resp.get("service"), "FulgorPCistaService")
                        print("\n[EMPIRICAL PROBE] Traffic to 127.0.0.1 correctly routed to TelemetryIPCServer despite 0.0.0.0 bind")
                except (PermissionError, OSError) as e:
                    print(f"\n[EMPIRICAL PROBE] 0.0.0.0 bind also blocked by OS: {e}")
            finally:
                attacker_sock2.close()

        finally:
            srv.stop()

    def test_adversarial_ipc_command_and_shutdown_exploitation(self):
        """
        Adversarial Test 2:
        Attempt unauthorized commands and shutdown exploits:
        - {"cmd": "shutdown"} without auth_token -> 401
        - {"cmd": "shutdown", "auth_token": "wrongtoken"} -> 401
        - {"cmd": "shutdown", "auth_token": "' OR '1'='1"} -> 401
        - {"cmd": "shutdown", "auth_token": "\\x00"} -> 401
        - Connect with legitimate token and verify normal commands succeed.
        """
        test_port = 49871
        auth_token = "valid_adversarial_test_secret_token_abcdef123456"
        core = DummyTelemetryCore()
        srv = TelemetryIPCServer(core, port=test_port, auth_token=auth_token)

        try:
            # Helper to send payload and receive json
            def send_payload(payload):
                with socket.create_connection((IPC_HOST, test_port), timeout=1.5) as s:
                    s.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                    raw = s.recv(4096)
                    if not raw:
                        return None
                    return json.loads(raw.decode("utf-8", errors="ignore").strip())

            # Exploit 1: Shutdown without auth_token
            resp = send_payload({"cmd": "shutdown"})
            self.assertIsNotNone(resp)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("code"), 401)
            self.assertEqual(resp.get("error"), "Unauthorized")
            self.assertTrue(srv.running, "Server must remain alive after unauthorized shutdown attempt")
            self.assertFalse(core.closed, "Core must not be closed")
            print("\n[EMPIRICAL PROBE] Exploit 1 (shutdown without auth_token): 401 Unauthorized, Server alive")

            # Exploit 2: Shutdown with wrong token
            resp = send_payload({"cmd": "shutdown", "auth_token": "wrongtoken"})
            self.assertIsNotNone(resp)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("code"), 401)
            self.assertEqual(resp.get("error"), "Unauthorized")
            self.assertTrue(srv.running)
            print("\n[EMPIRICAL PROBE] Exploit 2 (shutdown with wrongtoken): 401 Unauthorized, Server alive")

            # Exploit 3: Shutdown with SQL injection string
            resp = send_payload({"cmd": "shutdown", "auth_token": "' OR '1'='1"})
            self.assertIsNotNone(resp)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("code"), 401)
            self.assertEqual(resp.get("error"), "Unauthorized")
            self.assertTrue(srv.running)
            print("\n[EMPIRICAL PROBE] Exploit 3 (shutdown with SQLi payload): 401 Unauthorized, Server alive")

            # Exploit 4: Shutdown with null byte
            resp = send_payload({"cmd": "shutdown", "auth_token": "\x00"})
            self.assertIsNotNone(resp)
            self.assertFalse(resp.get("ok"))
            self.assertEqual(resp.get("code"), 401)
            self.assertEqual(resp.get("error"), "Unauthorized")
            self.assertTrue(srv.running)
            print("\n[EMPIRICAL PROBE] Exploit 4 (shutdown with null byte): 401 Unauthorized, Server alive")

            # Exploit 5: Variations of malformed auth parameters
            variations = [
                {"cmd": "shutdown", "token": "bad_token"},
                {"cmd": "shutdown", "auth_token": ""},
                {"cmd": "shutdown", "auth_token": None},
                {"cmd": "shutdown", "auth_token": 12345},
                {"cmd": "shutdown", "auth_token": []},
                {"cmd": "shutdown", "auth_token": {}},
                {"cmd": "shutdown", "auth_token": True},
            ]
            for var in variations:
                resp = send_payload(var)
                self.assertIsNotNone(resp)
                self.assertFalse(resp.get("ok"))
                self.assertEqual(resp.get("code"), 401)
                self.assertTrue(srv.running)

            # Exploit 6: Malformed non-JSON network garbage
            with socket.create_connection((IPC_HOST, test_port), timeout=1.5) as s:
                s.sendall(b"NON_JSON_CORRUPTED_PACKET_!@#$%\n")
                # Server should catch json.JSONDecodeError gracefully without terminating
            self.assertTrue(srv.running)

            # Legitimate commands with valid token
            # 1. Ping
            resp = send_payload({"cmd": "ping", "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(resp.get("service"), "FulgorPCistaService")

            # 2. Get stats
            resp = send_payload({"cmd": "get_stats", "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(resp["data"]["cpu_temp"], 45.0)
            self.assertTrue(resp["data"]["service_active"])

            # 3. Set mode
            resp = send_payload({"cmd": "set_mode", "mode": "GPU", "interval": 4.0, "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(core.mode, "GPU")
            self.assertEqual(core.interval, 4.0)

            # 4. Set auto switch
            resp = send_payload({"cmd": "set_auto_switch", "enabled": False, "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(core.auto_sw, 0)

            # 5. Set led
            resp = send_payload({"cmd": "set_led", "state": 0, "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(core.led, 0)

            # 6. Update session metrics
            resp = send_payload({"cmd": "update_session_metrics", "fps": 165.0, "in_game": True, "auth_token": auth_token})
            self.assertTrue(resp.get("ok"))
            self.assertEqual(core.fps, 165.0)
            self.assertTrue(core.in_game)

            # 7. TelemetryIPCClient integration
            client = TelemetryIPCClient(port=test_port, token=auth_token)
            self.assertTrue(client.is_alive())
            client_data = client.get_data()
            self.assertEqual(client_data["cpu_temp"], 45.0)
            print("\n[EMPIRICAL PROBE] Legitimate commands and TelemetryIPCClient verified successfully")

        finally:
            srv.stop()

    def test_authorized_shutdown_dispatch(self):
        """
        Verify that an authorized shutdown command executes server shutdown cleanup.
        We patch os._exit to intercept termination.
        """
        test_port = 49872
        auth_token = "valid_shutdown_token_9999"
        core = DummyTelemetryCore()
        srv = TelemetryIPCServer(core, port=test_port, auth_token=auth_token)

        import threading
        try:
            exit_event = threading.Event()

            def fake_exit(code):
                exit_event.set()

            with patch("os._exit", side_effect=fake_exit) as mock_exit:
                with socket.create_connection((IPC_HOST, test_port), timeout=1.5) as s:
                    s.sendall(json.dumps({"cmd": "shutdown", "auth_token": auth_token}).encode("utf-8") + b"\n")
                    raw = s.recv(4096)
                    resp = json.loads(raw.decode("utf-8", errors="ignore").strip())
                    self.assertTrue(resp.get("ok"))

                # Wait for background server thread to invoke os._exit before leaving patch context
                self.assertTrue(exit_event.wait(timeout=2.0), "os._exit was not invoked within timeout")
                mock_exit.assert_called_once_with(0)
                self.assertTrue(core.closed, "Core must be closed upon authorized shutdown")
                self.assertFalse(srv.running, "Server running flag must be False after stop")
                print("\n[EMPIRICAL PROBE] Authorized shutdown successfully intercepted os._exit(0) and closed core")
        finally:
            srv.stop()

    def test_token_file_lifecycle_and_cleanup(self):
        """
        Verify token file is created securely on disk and cleaned up on server stop.
        """
        test_port = 49873
        core = DummyTelemetryCore()
        srv = TelemetryIPCServer(core, port=test_port)
        token_path = srv.token_path

        try:
            self.assertTrue(os.path.exists(token_path), f"Token file must exist at {token_path}")
            with open(token_path, "r", encoding="utf-8") as f:
                saved_token = f.read().strip()
            self.assertEqual(saved_token, srv.auth_token)
            print(f"\n[EMPIRICAL PROBE] Token file created and verified at: {token_path}")
        finally:
            srv.stop()

        self.assertFalse(os.path.exists(token_path), "Token file must be removed when server stops")
        print("\n[EMPIRICAL PROBE] Token file successfully purged after server stop")


if __name__ == "__main__":
    unittest.main()
