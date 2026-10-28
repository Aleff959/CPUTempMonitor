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
PREV_BACKUP_ZIP = os.path.join(BUILDS_DIR, "FulgorPCista_1.4.0_Comp21.zip")


class TestMilestone5BuildArtifacts(unittest.TestCase):
    """E2E Verification of Milestone 5 build artifacts, checksums, and backup compliance."""

    def test_versioning_and_compilation_numbers(self):
        """Rule 1 & 2: Verify APP_VERSION is 1.5.0 and APP_COMP is 22 across main, updater, and UI."""
        self.assertEqual(main.APP_VERSION, "1.5.0")
        self.assertEqual(main.APP_COMP, 22)
        self.assertIn("1.5.0 | Comp. 22", main.WINDOW_TITLE)

        updater_default = AppUpdater()
        self.assertEqual(updater_default.current_version, "1.5.0")
        self.assertEqual(updater_default.current_comp, 22)

        index_path = os.path.join(REPO_ROOT, "ui", "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("v1.5.0 | Comp. 22", html)

    def test_build_backups_in_documents_builds(self):
        """Rule 3: Ensure backups are compressed inside C:\\Users\\Alpha\\Documents\\builds."""
        self.assertTrue(os.path.isdir(BUILDS_DIR), f"Builds directory must exist at {BUILDS_DIR}")
        self.assertTrue(os.path.isfile(PREV_BACKUP_ZIP), f"Previous backup {PREV_BACKUP_ZIP} must exist")

        with zipfile.ZipFile(PREV_BACKUP_ZIP, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("FulgorPCista.exe", namelist, "Previous backup zip must contain FulgorPCista.exe")
            info = zf.getinfo("FulgorPCista.exe")
            self.assertGreater(info.file_size, 10_000_000, "Zipped previous executable must be valid size")

        curr_backup_zip = os.path.join(BUILDS_DIR, "FulgorPCista_1.5.0_Comp22.zip")
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


if __name__ == "__main__":
    unittest.main()
