"""
Regression Test Suite for Milestone 1 Remediation (Iteration 3).
Covers:
1. Recursive unquoting and backslash normalization in is_safe_github_url.
2. Port restriction (strictly None or 443) in is_safe_github_url.
3. Userinfo/credential rejection in is_safe_github_url.
4. Safe filename extraction and path containment in apply_update.
5. Temp sandbox isolation and clean purge guarantees.
"""

import unittest
import os
import sys
import tempfile
import io
from unittest.mock import patch

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import updater
from updater import (
    is_safe_github_url,
    AppUpdater,
    _cleanup_dir,
    GITHUB_REPO,
)


class MockHTTPStreamResponse:
    def __init__(self, data: bytes):
        self._bio = io.BytesIO(data)

    def read(self, amt=-1):
        return self._bio.read(amt)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TestIteration3URLHardening(unittest.TestCase):
    """Test recursive unquoting, backslash normalization, port check, and credential checks."""

    def test_recursive_percent_encoded_traversals_rejected(self):
        """Single and double percent-encoded traversals must be decoded and rejected."""
        traversals = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/%2e%2e/%2e%2e/attacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/%2E%2E/%2E%2E/attacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/.%2e/.%2e/attacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/%2e./%2e./attacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/%252e%252e/%252e%252e/attacker/repo/releases/download/v1/bad.exe",
            "https://raw.githubusercontent.com/Aleff959/CPUTempMonitor/%2e%2e/%2e%2e/attacker/malware/main/FulgorPCista.exe",
            "https://codeload.github.com/Aleff959/CPUTempMonitor/%2e%2e/%2e%2e/attacker/repo/zip/refs/tags/v1.0",
            "https://api.github.com/repos/Aleff959/CPUTempMonitor/releases/%2e%2e/%2e%2e/%2e%2e/attacker/repo/releases",
        ]
        for url in traversals:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Traversal URL should be rejected: {url}")

    def test_backslash_and_encoded_slash_rejected(self):
        """Backslashes and encoded slashes attempting traversal must be normalized and rejected."""
        bypasses = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/..\\..\\attacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/..%2f..%2fattacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/..%5c..%5cattacker/repo/releases/download/v1/bad.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/%2e%2e%5c%2e%2e%5cattacker/repo/releases/download/v1/bad.exe",
        ]
        for url in bypasses:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Backslash/encoded slash URL should be rejected: {url}")

    def test_arbitrary_ports_rejected(self):
        """Only default HTTPS (None or 443) is permitted."""
        valid_ports = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com:443/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
        ]
        for url in valid_ports:
            with self.subTest(url=url):
                self.assertTrue(is_safe_github_url(url), f"Valid port should be accepted: {url}")

        invalid_ports = [
            "https://github.com:8443/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com:80/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com:8080/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://api.github.com:8443/repos/Aleff959/CPUTempMonitor/releases/latest",
            "https://objects.githubusercontent.com:1234/asset.exe",
        ]
        for url in invalid_ports:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Arbitrary port should be rejected: {url}")

    def test_credential_embedded_urls_rejected(self):
        """URLs containing username and/or password must be strictly rejected."""
        cred_urls = [
            "https://user:pass@github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://token@github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://attacker:@github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://:secret@github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
        ]
        for url in cred_urls:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Credential URL should be rejected: {url}")


class TestIteration3ApplyUpdateContainment(unittest.TestCase):
    """Test apply_update filename sanitization and path containment enforcement."""

    def setUp(self):
        self.update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        if os.path.exists(self.update_dir):
            _cleanup_dir(self.update_dir)
        self.app = AppUpdater(current_version="1.5.0", current_comp=22)

    def tearDown(self):
        if os.path.exists(self.update_dir):
            _cleanup_dir(self.update_dir)

    def test_traversal_filename_cannot_escape_sandbox(self):
        """Adversarial filename with backslash traversal must be stripped and contained."""
        canary = "iter3_escaped_canary.exe"
        canary_outside = os.path.abspath(os.path.join(tempfile.gettempdir(), canary))
        if os.path.exists(canary_outside):
            os.remove(canary_outside)

        url = f"https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/..\\{canary}"
        payload = b"PAYLOAD_DATA"
        mismatch_hash = "0" * 64

        try:
            with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPStreamResponse(payload)):
                res = self.app.apply_update(download_url=url, expected_hash=mismatch_hash)

            self.assertFalse(res["success"])
            # Canary must NEVER exist outside update_dir
            self.assertFalse(os.path.exists(canary_outside), "File must not be written outside update_dir!")
            # update_dir must be cleanly purged on mismatch
            self.assertFalse(os.path.exists(self.update_dir), "update_dir must be purged on mismatch!")
        finally:
            if os.path.exists(canary_outside):
                os.remove(canary_outside)


if __name__ == "__main__":
    unittest.main()
