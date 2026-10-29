import os
import unittest
import hashlib
import zipfile
import re
from updater import compute_sha256, parse_hash_from_checksum_file, AppUpdater
import main

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(REPO_ROOT, "dist")
EXE_PATH = os.path.join(DIST_DIR, "FulgorPCista.exe")
SHA256_FILE = os.path.join(DIST_DIR, "FulgorPCista.exe.sha256")
SHA256SUMS_FILE = os.path.join(DIST_DIR, "SHA256SUMS")
BUILDS_DIR = r"C:\Users\Alpha\Documents\builds"
PREV_BACKUP_ZIP = os.path.join(BUILDS_DIR, "FulgorPCista_1.6.0_Comp25.zip")


class TestMilestone5BuildArtifacts(unittest.TestCase):
    """E2E Verification of Milestone 5 build artifacts, checksums, and backup compliance."""

    def test_versioning_and_compilation_numbers(self):
        """Rule 1 & 2: Verify APP_VERSION is 1.7.0, APP_COMP is 26, and APP_CODENAME is Zeus across main, updater, and UI."""
        self.assertEqual(main.APP_VERSION, "1.7.0")
        self.assertEqual(main.APP_COMP, 26)
        self.assertEqual(main.APP_CODENAME, "Zeus")
        self.assertIn("1.7.0 | Comp. 26 - Zeus", main.WINDOW_TITLE)

        updater_default = AppUpdater()
        self.assertEqual(updater_default.current_version, "1.7.0")
        self.assertEqual(updater_default.current_comp, 26)

        index_path = os.path.join(REPO_ROOT, "ui", "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("v1.7.0 | Comp. 26", html)
        self.assertIn("v1.7.0 (Zeus) • Comp. 26", html)

    def test_build_backups_in_documents_builds(self):
        """Rule 3: Ensure backups are compressed inside C:\\Users\\Alpha\\Documents\\builds."""
        self.assertTrue(os.path.isdir(BUILDS_DIR), f"Builds directory must exist at {BUILDS_DIR}")
        self.assertTrue(os.path.isfile(PREV_BACKUP_ZIP), f"Previous backup {PREV_BACKUP_ZIP} must exist")

        with zipfile.ZipFile(PREV_BACKUP_ZIP, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("FulgorPCista.exe", namelist, "Previous backup zip must contain FulgorPCista.exe")
            info = zf.getinfo("FulgorPCista.exe")
            self.assertGreater(info.file_size, 10_000_000, "Zipped previous executable must be valid size")

        curr_backup_zip = os.path.join(BUILDS_DIR, "FulgorPCista_1.7.0_Comp26.zip")
        self.assertTrue(os.path.isfile(curr_backup_zip), f"Current backup {curr_backup_zip} must exist")
        with zipfile.ZipFile(curr_backup_zip, "r") as zf:
            self.assertIn("FulgorPCista.exe", zf.namelist(), "Current backup zip must contain FulgorPCista.exe")
            zipped_data = zf.read("FulgorPCista.exe")
            self.assertEqual(hashlib.sha256(zipped_data).hexdigest(), compute_sha256(EXE_PATH))

    def test_dist_executable_exists_and_valid_pe(self):
        """Verify compiled dist/FulgorPCista.exe exists, is non-empty, and has valid PE MZ header."""
        self.assertTrue(os.path.isfile(EXE_PATH), f"Executable must exist at {EXE_PATH}")
        size = os.path.getsize(EXE_PATH)
        self.assertGreater(size, 10_000_000, f"Executable size {size} bytes is unexpectedly small")

        with open(EXE_PATH, "rb") as f:
            header = f.read(2)
        self.assertEqual(header, b"MZ", "Executable must have valid Windows PE MZ header")

    def test_sha256_checksum_files_integrity(self):
        """Verify dist/FulgorPCista.exe.sha256 and dist/SHA256SUMS accurately match binary hash."""
        self.assertTrue(os.path.isfile(SHA256_FILE), "dist/FulgorPCista.exe.sha256 must exist")
        self.assertTrue(os.path.isfile(SHA256SUMS_FILE), "dist/SHA256SUMS must exist")

        actual_hash = compute_sha256(EXE_PATH)
        self.assertEqual(len(actual_hash), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in actual_hash))

        # Check FulgorPCista.exe.sha256
        with open(SHA256_FILE, "r", encoding="ascii") as f:
            sha_content = f.read().strip()
        self.assertIn(actual_hash, sha_content.lower())
        parsed_from_sha = parse_hash_from_checksum_file(sha_content, "FulgorPCista.exe")
        self.assertEqual(parsed_from_sha, actual_hash)

        # Check SHA256SUMS
        with open(SHA256SUMS_FILE, "r", encoding="ascii") as f:
            sums_content = f.read()
        self.assertIn(f"{actual_hash}  FulgorPCista.exe", sums_content)
        parsed_from_sums = parse_hash_from_checksum_file(sums_content, "FulgorPCista.exe")
        self.assertEqual(parsed_from_sums, actual_hash)

    def test_prelogon_service_bridge_ipc(self):
        """Verify TelemetryIPCServer and TelemetryIPCClient roundtrip communication."""
        from service_bridge import TelemetryIPCServer, TelemetryIPCClient

        class DummyCore:
            def __init__(self):
                self.mode = "CPU"
                self.auto_sw = 1
                self.ext_fps = 0.0
                self.ext_game = False

            def get_data(self):
                return {"cpu_temp": 45.0, "active_device": self.mode, "auto_switch_fps": self.auto_sw, "fps": int(self.ext_fps), "in_game": self.ext_game}

            def set_mode(self, mode, interval=5.0):
                self.mode = mode
                return True

            def set_auto_switch(self, enabled):
                self.auto_sw = 1 if enabled else 0
                return True

            def set_led(self, state):
                return True

            def update_external_session_metrics(self, fps, in_game):
                self.ext_fps = fps
                self.ext_game = in_game
                return True

            def close(self):
                pass

        dummy = DummyCore()
        test_port = 49842
        srv = TelemetryIPCServer(dummy, port=test_port)
        try:
            client = TelemetryIPCClient(timeout=1.0, port=test_port)
            self.assertTrue(client.is_alive())
            data = client.get_data()
            self.assertIsNotNone(data)
            self.assertEqual(data["cpu_temp"], 45.0)
            self.assertTrue(data["service_active"])

            self.assertTrue(client.set_mode("GPU"))
            self.assertEqual(dummy.mode, "GPU")

            self.assertTrue(client.send_session_metrics(144.0, True))
            self.assertEqual(dummy.ext_fps, 144.0)
            self.assertTrue(dummy.ext_game)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
