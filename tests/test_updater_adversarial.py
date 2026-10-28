"""
Adversarial Stress Test Suite & Bug Reproduction for Fulgor PCista OTA Updater (Milestone 1).

Objectives:
1. Adversarially stress-test OTA Updater implementation against:
   - Malicious/phishing download URLs (HTTP, spoofed domains, untrusted third-party hosts).
   - Foreign GitHub repositories and raw user-content bypasses.
   - Bit-flip / corrupted payloads vs expected SHA-256 hash.
   - Missing or malformed hash scenarios.
   - Zip Slip / path traversal malicious archive payloads.
2. Confirm empirical behavior: does updater abort and purge temporary files in all failure cases?
3. Reproduce and verify discovered security vulnerabilities and edge-case defects.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import io
import shutil
import tempfile
import zipfile
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import posixpath

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import updater


class MockHTTPResponse:
    """Mock streaming HTTP response for urllib.request."""
    def __init__(self, data: bytes, status=200):
        self._bio = io.BytesIO(data)
        self.status = status

    def read(self, amt=-1):
        return self._bio.read(amt)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TestURLValidationAdversarial(unittest.TestCase):
    """Stress-test URL validation and strict HTTPS redirect handling."""

    def test_insecure_http_rejected(self):
        """HTTP scheme must be blocked even if targeting official GitHub domain."""
        url = "http://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"
        self.assertFalse(updater.is_safe_github_url(url))

    def test_arbitrary_schemes_rejected(self):
        """Non-HTTPS schemes (ftp, file, data, javascript) must be blocked."""
        schemes = ["ftp", "file", "data", "javascript", "ws", "gopher"]
        for s in schemes:
            url = f"{s}://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"
            self.assertFalse(updater.is_safe_github_url(url), f"Scheme {s} should be rejected")

    def test_phishing_and_typosquatting_domains_rejected(self):
        """Phishing subdomains and domain spoofs must be rejected."""
        spoofed_urls = [
            "https://evil.com/FulgorPCista.exe",
            "https://pastebin.com/raw/FulgorPCista.exe",
            "https://s3.amazonaws.com/malicious/FulgorPCista.exe",
            "https://github.com.attacker.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github-com.evil.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://objects-githubusercontent.evil.com/download.exe",
            "https://attacker-github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://fakeapi.github.com/repos/Aleff959/CPUTempMonitor/releases/latest",
        ]
        for url in spoofed_urls:
            self.assertFalse(updater.is_safe_github_url(url), f"Spoofed domain {url} should be rejected")

    def test_foreign_github_main_repository_rejected(self):
        """Downloads pointing to third-party GitHub repositories on github.com must be rejected."""
        foreign_urls = [
            "https://github.com/attacker/malicious-repo/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com/torvalds/linux/releases/download/v1.5.0/FulgorPCista.exe",
            "https://api.github.com/repos/attacker/malicious-repo/releases/latest",
            "https://codeload.github.com/attacker/malicious-repo/zip/refs/tags/v1.5.0",
        ]
        for url in foreign_urls:
            self.assertFalse(updater.is_safe_github_url(url), f"Foreign repo {url} should be rejected")

    def test_vulnerability_raw_githubusercontent_foreign_repo_bypass(self):
        """
        Adversarial probe: foreign repository hosted on raw.githubusercontent.com
        must be strictly rejected by is_safe_github_url.
        """
        url = "https://raw.githubusercontent.com/attacker/malicious-repo/main/FulgorPCista.exe"
        is_safe = updater.is_safe_github_url(url)
        print(f"\n[EMPIRICAL FINDING] Foreign raw.githubusercontent.com URL was accepted as safe: {is_safe}")
        self.assertFalse(is_safe, "Foreign raw.githubusercontent.com URL must be rejected!")

    def test_vulnerability_url_path_traversal_bypass(self):
        """
        Adversarial probe: URL path traversal attempting to escape the official repo namespace
        must be normalized and strictly rejected.
        """
        traversal_url = "https://github.com/Aleff959/CPUTempMonitor/releases/../../attacker/malware/releases/download/v1/FulgorPCista.exe"
        is_safe = updater.is_safe_github_url(traversal_url)
        print(f"\n[EMPIRICAL FINDING] URL path traversal URL was accepted as safe: {is_safe}")
        self.assertFalse(is_safe, "URL path traversal must be rejected!")

    def test_malformed_and_none_urls_rejected(self):
        """Empty, non-string, or malformed inputs must return False gracefully."""
        invalid_inputs = [None, "", "   ", 12345, [], {}, "not_a_url", "https://", "https:///foo/bar"]
        for inp in invalid_inputs:
            self.assertFalse(updater.is_safe_github_url(inp), f"Invalid input {inp} should be rejected")

    def test_valid_github_urls_accepted(self):
        """Legitimate release assets and API endpoints for official repo must be accepted."""
        valid_urls = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.zip",
            "https://github.com/aleff959/cputempmonitor/releases/download/v1.5.0/FulgorPCista.exe",  # Case insensitivity
            "https://api.github.com/repos/Aleff959/CPUTempMonitor/releases/latest",
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/123456?response-content-disposition=attachment",
            "https://raw.githubusercontent.com/Aleff959/CPUTempMonitor/main/README.md",
        ]
        for url in valid_urls:
            self.assertTrue(updater.is_safe_github_url(url), f"Legitimate URL {url} should be accepted")

    def test_strict_https_redirect_handler_blocks_insecure_hops(self):
        """Redirect handler must throw URLError on insecure schemes or untrusted hosts."""
        handler = updater.StrictHTTPSRedirectHandler()
        dummy_req = urllib.request.Request("https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe")

        # Insecure redirect to HTTP
        with self.assertRaises(urllib.error.URLError) as ctx:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "http://objects.githubusercontent.com/asset.exe")
        self.assertIn("Protocolo inseguro", str(ctx.exception))

        # Redirect to external domain
        with self.assertRaises(urllib.error.URLError) as ctx:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "https://evil-server.com/malware.exe")
        self.assertIn("Redirecionamento não autorizado", str(ctx.exception))

        # Empty redirect
        with self.assertRaises(urllib.error.URLError) as ctx:
            handler.redirect_request(dummy_req, None, 302, "Found", {}, "")
        self.assertIn("vazia", str(ctx.exception))


class TestBitFlipAndCorruptedPayload(unittest.TestCase):
    """Stress-test payload integrity verification and fail-safe abortion."""

    def setUp(self):
        self.update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)
        self.app = updater.AppUpdater(current_version="1.5.0", current_comp=22)

    def tearDown(self):
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)

    def test_bit_flip_corruption_aborts_and_purges(self):
        """A single bit flip in binary payload must trigger SHA256_MISMATCH and purge directory."""
        original_payload = b"Genuine FulgorPCista executable binary payload bytes \x00\x01\x02\x03" * 1024
        expected_hash = hashlib.sha256(original_payload).hexdigest()

        # Corrupt one bit in payload
        corrupted_payload = bytearray(original_payload)
        corrupted_payload[42] ^= 0x01
        corrupted_payload = bytes(corrupted_payload)

        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(corrupted_payload)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertFalse(result["success"])
        self.assertEqual(result.get("code"), "SHA256_MISMATCH")
        self.assertIn("Falha de integridade criptográfica", result["error"])
        # Empirical proof: Temporary update directory must NOT exist on disk!
        self.assertFalse(os.path.exists(self.update_dir), "Temporary directory was not purged after bit-flip mismatch!")

    def test_truncated_payload_aborts_and_purges(self):
        """Incomplete or truncated download payload must fail SHA-256 and purge."""
        full_payload = b"Full 10MB payload simulation data..." * 2048
        expected_hash = hashlib.sha256(full_payload).hexdigest()

        truncated_payload = full_payload[:512]  # Dropped connection simulation
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(truncated_payload)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertFalse(result["success"])
        self.assertEqual(result.get("code"), "SHA256_MISMATCH")
        self.assertFalse(os.path.exists(self.update_dir), "Temporary directory was not purged after truncated download!")

    def test_rogue_payload_substitution_aborts_and_purges(self):
        """Attacker substituting a different binary must be caught by SHA-256 check."""
        rogue_payload = b"MZ\x90\x00\x03\x00\x00\x00calc.exe dummy payload"
        claimed_hash = "a" * 64  # Claimed hash of legitimate release
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(rogue_payload)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=claimed_hash)

        self.assertFalse(result["success"])
        self.assertEqual(result.get("code"), "SHA256_MISMATCH")
        self.assertFalse(os.path.exists(self.update_dir), "Temporary directory was not purged after rogue payload!")


class TestMissingHashScenarios(unittest.TestCase):
    """Stress-test missing or malformed hash scenarios."""

    def setUp(self):
        self.update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)
        self.app = updater.AppUpdater(current_version="1.5.0", current_comp=22)

    def tearDown(self):
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)

    def test_missing_hash_aborts_and_purges(self):
        """Release asset downloaded but no hash available anywhere must abort with SHA256_MISSING."""
        payload = b"MZ\x90\x00Some Valid Executable Bytes"
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        self.app.update_info = {
            "download_url": valid_url,
            "expected_sha256": "",
            "checksum_url": None,
        }

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(payload)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=None)

        self.assertFalse(result["success"])
        self.assertEqual(result.get("code"), "SHA256_MISSING")
        self.assertIn("Nenhum hash SHA-256 oficial válido", result["error"])
        self.assertFalse(os.path.exists(self.update_dir), "Temporary directory was not purged when hash is missing!")

    def test_malformed_hashes_rejected_and_purged(self):
        """MD5 (32 chars), SHA-1 (40 chars), or invalid-length hashes must be rejected."""
        payload = b"Payload data"
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        malformed_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 (32 chars)
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 (40 chars)
            "short",
            "0" * 63,  # 63 chars (one too short)
            "0" * 65,  # 65 chars (one too long)
            " " * 64,  # 64 whitespace chars
        ]

        for bad_hash in malformed_hashes:
            with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(payload)):
                result = self.app.apply_update(download_url=valid_url, expected_hash=bad_hash)
            self.assertFalse(result["success"])
            self.assertEqual(result.get("code"), "SHA256_MISSING", f"Malformed hash {bad_hash} should fail with SHA256_MISSING")
            self.assertFalse(os.path.exists(self.update_dir), f"Directory was not purged for bad hash: {bad_hash}")


class TestZipSlipPathTraversal(unittest.TestCase):
    """Stress-test malicious archive payloads attempting path traversal (Zip Slip)."""

    def setUp(self):
        self.update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)
        self.app = updater.AppUpdater(current_version="1.5.0", current_comp=22)

    def tearDown(self):
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)

    def _create_malicious_zip(self, entries):
        """Create in-memory zip bytes with custom entry names."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
            for arcname, content in entries.items():
                z.writestr(arcname, content)
        return bio.getvalue()

    def test_relative_zip_slip_blocked_and_purged(self):
        """Relative path traversal (../../evil.exe) must be detected and aborted without extracting outside."""
        slip_entries = {
            "../../pwned.txt": "MALICIOUS PAYLOAD OUTSIDE DESTINATION",
            "FulgorPCista.exe": "Dummy Exe Content",
        }
        zip_bytes = self._create_malicious_zip(slip_entries)
        expected_hash = hashlib.sha256(zip_bytes).hexdigest()
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.zip"

        canary_path = os.path.abspath(os.path.join(self.update_dir, "..", "pwned.txt"))
        if os.path.exists(canary_path):
            os.remove(canary_path)

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(zip_bytes)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertFalse(result["success"])
        self.assertIn("path traversal", result["error"].lower())
        # Canary check: outside file must NEVER have been written!
        self.assertFalse(os.path.exists(canary_path), "CRITICAL: Zip Slip canary was written to parent directory!")
        # Update dir must be purged
        self.assertFalse(os.path.exists(self.update_dir), "Temporary directory was not purged after zip slip attempt!")

    def test_nested_zip_slip_blocked(self):
        """Subdirectory traversal (folder/../../pwned2.txt) must be detected and blocked."""
        slip_entries = {
            "subfolder/../../../pwned2.txt": "TRAVERSAL TEST",
            "FulgorPCista.exe": "Exe",
        }
        zip_bytes = self._create_malicious_zip(slip_entries)
        expected_hash = hashlib.sha256(zip_bytes).hexdigest()
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.zip"

        canary_path = os.path.abspath(os.path.join(tempfile.gettempdir(), "pwned2.txt"))
        if os.path.exists(canary_path):
            os.remove(canary_path)

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(zip_bytes)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertFalse(result["success"])
        self.assertFalse(os.path.exists(canary_path), "Nested Zip Slip wrote file!")
        self.assertFalse(os.path.exists(self.update_dir))

    def test_legitimate_zip_extracts_and_locates_exe(self):
        """A safe zip archive containing FulgorPCista.exe must be extracted cleanly."""
        safe_entries = {
            "README.txt": "Release notes",
            "bin/FulgorPCista.exe": "Legitimate PE Binary Content",
        }
        zip_bytes = self._create_malicious_zip(safe_entries)
        expected_hash = hashlib.sha256(zip_bytes).hexdigest()
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.zip"

        # Mock Popen and Timer so update batch does not actually execute or kill test runner
        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(zip_bytes)), \
             patch("subprocess.Popen") as mock_popen, \
             patch("threading.Timer") as mock_timer:
            mock_timer.return_value = MagicMock()
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertTrue(result["success"])
        self.assertIn("Atualização verificada com sucesso", result["message"])
        self.assertTrue(mock_popen.called)


class TestPurgeAndCleanlinessGuarantees(unittest.TestCase):
    """Stress-test cleanup guarantees on pre-existing trash, exceptions, and missing target binaries."""

    def setUp(self):
        self.update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)
        self.app = updater.AppUpdater(current_version="1.5.0", current_comp=22)

    def tearDown(self):
        if os.path.exists(self.update_dir):
            shutil.rmtree(self.update_dir, ignore_errors=True)

    def test_preexisting_temp_files_cleared_on_entry(self):
        r"""If %TEMP%\FulgorPCista_Update has stale/leftover files, it must be cleared at start."""
        os.makedirs(self.update_dir, exist_ok=True)
        stale_file = os.path.join(self.update_dir, "stale_malware.exe")
        with open(stale_file, "w") as f:
            f.write("stale")

        # Invoking apply_update with rejected URL should clear the stale file
        result = self.app.apply_update(download_url="http://insecure.url/bad.exe")
        self.assertFalse(result["success"])
        self.assertFalse(os.path.exists(stale_file), "Stale leftover file was not purged on entry!")
        self.assertFalse(os.path.exists(self.update_dir))

    def test_network_exception_during_stream_purges_temp(self):
        """Network drop or socket reset midway through download must purge partially written files."""
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        class FailingStreamResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, amt=-1):
                raise urllib.error.URLError("Connection reset by peer (simulated drop)")

        with patch("urllib.request.OpenerDirector.open", return_value=FailingStreamResponse()):
            result = self.app.apply_update(download_url=valid_url, expected_hash="0" * 64)

        self.assertFalse(result["success"])
        self.assertIn("Connection reset by peer", result["error"])
        self.assertFalse(os.path.exists(self.update_dir), "Partial download directory was not purged on network exception!")

    def test_missing_exe_inside_valid_zip_aborts_and_purges(self):
        """If a zip passes SHA-256 and has no traversal, but contains no FulgorPCista.exe, abort and purge."""
        entries = {"unrelated_file.txt": "hello"}
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as z:
            for name, data in entries.items():
                z.writestr(name, data)
        zip_bytes = bio.getvalue()
        expected_hash = hashlib.sha256(zip_bytes).hexdigest()
        valid_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.zip"

        with patch("urllib.request.OpenerDirector.open", return_value=MockHTTPResponse(zip_bytes)):
            result = self.app.apply_update(download_url=valid_url, expected_hash=expected_hash)

        self.assertFalse(result["success"])
        self.assertIn("FulgorPCista.exe não encontrado", result["error"])
        self.assertFalse(os.path.exists(self.update_dir), "Directory was not purged when required exe was missing from zip!")


class TestVersionAndCompParsing(unittest.TestCase):
    """Stress-test version parsing against edge cases, strings, and comp numbers."""

    def test_parse_version_tuple(self):
        """Verify version tuple parsing for user rule formats."""
        cases = [
            ("(1.5.0 | Comp. 22)", (1, 5, 0)),
            ("v1.5.0", (1, 5, 0)),
            ("1.5.0", (1, 5, 0)),
            ("2.0", (2, 0)),
            ("v1.0.1 | Comp. 23", (1, 0, 1)),
            ("invalid", (0,)),
            ("", (0,)),
            (None, (0,)),
        ]
        for v_input, expected in cases:
            self.assertEqual(updater._parse_version_tuple(v_input), expected, f"Failed for version input: {v_input}")

    def test_defect_pre_release_tag_corrupts_version_tuple(self):
        r"""
        Verifies that pre-release suffixes (e.g. '1.4.9-beta.1') are stripped so they
        do not invert semantic version comparison against final release versions.
        """
        parsed = updater._parse_version_tuple("1.4.9-beta.1")
        print(f"\n[EMPIRICAL FINDING] Pre-release version '1.4.9-beta.1' parsed as: {parsed}")
        self.assertEqual(parsed, (1, 4, 9), "Pre-release tag must parse to base semantic version tuple")
        self.assertLessEqual(parsed, (1, 4, 9), "Pre-release tag must NOT be considered higher than final release!")

    def test_parse_comp_number_adversarial(self):
        """Extract compilation numbers accurately."""
        cases = [
            ("Comp. 22", 22),
            ("(1.5.0 | Comp. 22)", 22),
            ("comp 19", 19),
            ("COMP.105", 105),
            ("Build 55 without comp tag", 0),
            ("", 0),
            (None, 0),
        ]
        for text, expected in cases:
            self.assertEqual(updater._parse_comp_number(text), expected, f"Failed for comp input: {text}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
