"""
Adversarial Stress Test Suite for OTA Updater (Milestone 1)
Author: Challenger 2 (Empirical Challenger)
Target: Fulgor PCista updater.py & main.py

Tests:
1. Redirection chain safety (HTTPS -> HTTP downgrade, GitHub -> external IP/domain, empty/invalid URLs)
2. Tricky version and compilation strings
3. Cascade hash parsing edge cases (spaces, hex case, comments, file formats, body markdown)
"""

import unittest
import urllib.request
import urllib.error
import urllib.parse
import os
import sys
import tempfile
import io
import shutil
from unittest.mock import patch, MagicMock

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import updater
from updater import (
    ALLOWED_HOSTS,
    GITHUB_REPO,
    StrictHTTPSRedirectHandler,
    is_safe_github_url,
    compute_sha256,
    parse_hash_from_checksum_file,
    parse_hash_from_body,
    _parse_version_tuple,
    _parse_comp_number,
    _cleanup_dir,
    AppUpdater,
)


class TestRedirectSafety(unittest.TestCase):
    """Adversarially test redirect chains, protocol downgrades, and domain boundaries."""

    def setUp(self):
        self.handler = StrictHTTPSRedirectHandler()
        self.dummy_req = urllib.request.Request("https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe")

    def test_redirect_to_http_downgrade_blocked(self):
        """Redirect from HTTPS to HTTP must be blocked with URLError."""
        http_targets = [
            "http://objects.githubusercontent.com/asset.exe",
            "http://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "http://192.168.1.1/update.exe",
            "http://evil.com/update.exe",
        ]
        for target in http_targets:
            with self.subTest(target=target):
                with self.assertRaises(urllib.error.URLError) as ctx:
                    self.handler.redirect_request(self.dummy_req, None, 302, "Found", {}, target)
                self.assertIn("inseguro", str(ctx.exception).lower())

    def test_redirect_to_external_ip_or_domain_blocked(self):
        """Redirects jumping to external IPs or untrusted domains must be rejected."""
        untrusted_targets = [
            "https://evil.com/malicious.exe",
            "https://192.168.1.100/FulgorPCista.exe",
            "https://1.1.1.1/update.exe",
            "https://github.com.evil.com/FulgorPCista.exe",
            "https://githubusercontent.com.evil.com/asset.exe",
            "https://evilgithubusercontent.com/asset.exe",
            "https://api.github.com.attacker.com/releases",
            "https://gitlab.com/attacker/repo/raw/main/FulgorPCista.exe",
            "https://bitbucket.org/attacker/repo/downloads/FulgorPCista.exe",
        ]
        for target in untrusted_targets:
            with self.subTest(target=target):
                with self.assertRaises(urllib.error.URLError) as ctx:
                    self.handler.redirect_request(self.dummy_req, None, 302, "Found", {}, target)
                self.assertIn("não autorizado", str(ctx.exception).lower())

    def test_redirect_empty_or_malformed_url(self):
        """Redirect with empty or malformed URL must be rejected."""
        invalid_urls = [
            "",
            None,
        ]
        for target in invalid_urls:
            with self.subTest(target=target):
                with self.assertRaises(urllib.error.URLError):
                    self.handler.redirect_request(self.dummy_req, None, 302, "Found", {}, target)

    def test_redirect_non_http_schemes(self):
        """Redirect to file://, ftp://, javascript:, data: schemes must be rejected."""
        dangerous_schemes = [
            "file:///C:/Windows/System32/calc.exe",
            "ftp://files.example.com/update.exe",
            "data:text/plain;base64,SGVsbG8=",
            "javascript:alert(1)",
        ]
        for target in dangerous_schemes:
            with self.subTest(target=target):
                with self.assertRaises(urllib.error.URLError) as ctx:
                    self.handler.redirect_request(self.dummy_req, None, 302, "Found", {}, target)
                self.assertIn("inseguro", str(ctx.exception).lower())

    def test_redirect_legitimate_github_targets_allowed(self):
        """Redirects to valid GitHub domains (e.g. objects.githubusercontent.com) must succeed."""
        legitimate_targets = [
            "https://objects.githubusercontent.com/github-production-release-asset-2e6506/12345/FulgorPCista.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://raw.githubusercontent.com/Aleff959/CPUTempMonitor/main/SHA256SUMS.txt",
            "https://codeload.github.com/Aleff959/CPUTempMonitor/zip/refs/tags/v1.5.0",
        ]
        for target in legitimate_targets:
            with self.subTest(target=target):
                req = self.handler.redirect_request(self.dummy_req, None, 302, "Found", {}, target)
                self.assertIsNotNone(req)
                self.assertEqual(req.full_url, target)

    def test_is_safe_github_url_boundaries(self):
        """Stress-test is_safe_github_url against boundary conditions and spoofing."""
        safe_urls = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista-v1.5.0-windows-x64.zip",
            "https://github.com/Aleff959/CPUTempMonitor/archive/refs/tags/v1.5.0.zip",
            "https://api.github.com/repos/Aleff959/CPUTempMonitor/releases/latest",
            "https://api.github.com/repos/Aleff959/CPUTempMonitor/releases",
            "https://objects.githubusercontent.com/github-production-release-asset/123",
        ]
        for url in safe_urls:
            with self.subTest(url=url):
                self.assertTrue(is_safe_github_url(url), f"Should be safe: {url}")

        unsafe_urls = [
            # Insecure schemes
            "http://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "ftp://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "file:///C:/FulgorPCista.exe",
            # Wrong repository
            "https://github.com/OtherUser/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://github.com/Aleff959/MaliciousRepo/releases/download/v1.5.0/FulgorPCista.exe",
            "https://api.github.com/repos/OtherUser/CPUTempMonitor/releases",
            # Domain typosquatting / spoofing
            "https://github.com.evil.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://evilgithub.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe",
            "https://evilgithubusercontent.com/Aleff959/CPUTempMonitor/asset.exe",
            # Path traversal / bypass attempts
            "https://github.com/Aleff959/CPUTempMonitor/issues/1",
            "https://github.com/Aleff959/CPUTempMonitor/pull/1",
            # Non-string / empty
            "",
            None,
            12345,
        ]
        for url in unsafe_urls:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Should NOT be safe: {url}")

    def test_is_safe_github_url_vulnerability_attacker_raw(self):
        """
        Adversarial probe: can an attacker supply https://raw.githubusercontent.com/attacker/malicious/main/FulgorPCista.exe?
        Verifies that foreign repos on raw.githubusercontent.com are strictly rejected.
        """
        official_raw = "https://raw.githubusercontent.com/Aleff959/CPUTempMonitor/main/SHA256SUMS.txt"
        attacker_raw = "https://raw.githubusercontent.com/attacker/malicious/main/FulgorPCista.exe"

        # Official repo should be True
        self.assertTrue(is_safe_github_url(official_raw))

        # Attacker repo must evaluate to False:
        attacker_eval = is_safe_github_url(attacker_raw)
        self.assertFalse(attacker_eval, "Empirically confirms is_safe_github_url rejects untrusted raw.githubusercontent.com repos")


class TestVersionAndCompilationParsing(unittest.TestCase):
    """Stress-test version string parsing and compilation extraction."""

    def test_standard_user_rule_format(self):
        """Format: (1.5.0 | Comp. 22) -> ver: (1, 5, 0), comp: 22."""
        s = "(1.5.0 | Comp. 22)"
        self.assertEqual(_parse_version_tuple(s), (1, 5, 0))
        self.assertEqual(_parse_comp_number(s), 22)

    def test_window_title_format_with_codename(self):
        """Format matching main.py WINDOW_TITLE: (1.5.0 | Comp. 22 - Ororo)."""
        s = "(1.5.0 | Comp. 22 - Ororo)"
        self.assertEqual(_parse_version_tuple(s), (1, 5, 0))
        self.assertEqual(_parse_comp_number(s), 22)

    def test_various_compilation_formats(self):
        """Test variations in compilation representation."""
        cases = [
            ("(1.5.0 | Comp. 104)", 104),         # Multi-digit compilation (3 digits)
            ("(1.5.0 | Comp. 005)", 5),           # Leading zeros
            ("(1.5.0 | comp 22)", 22),            # Lowercase, no dot
            ("(1.5.0 | Comp.22)", 22),            # No space after dot
            ("(1.5.0 | COMP. 9999)", 9999),       # Large 4-digit comp
            ("Comp. 35", 35),                     # Comp only
            ("Build Comp. 42", 42),               # Prefix
            ("No compilation mentioned", 0),      # Missing
            ("", 0),                              # Empty
            (None, 0),                            # None
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(_parse_comp_number(text), expected)

    def test_various_version_formats(self):
        """Test variations in version representation."""
        cases = [
            ("1.5.0", (1, 5, 0)),
            ("v1.4.0", (1, 4, 0)),
            ("V2.0.1", (2, 0, 1)),
            ("(1.5.0 | Comp. 22)", (1, 5, 0)),
            ("(1.5.0)", (1, 5, 0)),
            ("1.5", (1, 5)),
            ("1.10.5", (1, 10, 5)),
            ("10.20.30", (10, 20, 30)),
            ("1.5.0-dirty", (1, 5, 0)),           # Dirty tag
            ("v1.5.0-beta", (1, 5, 0)),            # Pre-release tag without digits
            ("", (0,)),                           # Empty string
            (None, (0,)),                         # None
            ("unknown", (0,)),                    # Non-numeric
        ]
        for v_str, expected in cases:
            with self.subTest(v_str=v_str):
                self.assertEqual(_parse_version_tuple(v_str), expected)

    def test_version_tuple_comparison_behavior(self):
        """Test version comparison semantics in AppUpdater."""
        updater_inst = AppUpdater(current_version="1.5.0", current_comp=22)
        curr_ver = _parse_version_tuple(updater_inst.current_version)

        # Newer versions
        self.assertGreater(_parse_version_tuple("1.5.1"), curr_ver)
        self.assertGreater(_parse_version_tuple("1.6.0"), curr_ver)
        self.assertGreater(_parse_version_tuple("2.0.0"), curr_ver)
        self.assertGreater(_parse_version_tuple("v1.5.1"), curr_ver)
        self.assertGreater(_parse_version_tuple("(1.5.1 | Comp. 1)"), curr_ver)

        # Same version, different comp
        same_ver = _parse_version_tuple("1.5.0")
        self.assertEqual(same_ver, curr_ver)

        # Older versions
        self.assertLess(_parse_version_tuple("1.4.9"), curr_ver)
        self.assertLess(_parse_version_tuple("1.4.0"), curr_ver)
        self.assertLess(_parse_version_tuple("0.9.9"), curr_ver)


class TestCascadeHashParsing(unittest.TestCase):
    """Stress-test cascade hash extraction from checksum files and release body."""

    SAMPLE_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    OTHER_HASH  = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"

    def test_checksum_file_standard_formats(self):
        """Test standard sha256sum line formats (2 spaces, 1 space, asterisk)."""
        formats = [
            f"{self.SAMPLE_HASH}  FulgorPCista.exe\n",            # sha256sum default (2 spaces)
            f"{self.SAMPLE_HASH} *FulgorPCista.exe\n",           # sha256sum binary mode (* prefix)
            f"{self.SAMPLE_HASH} FulgorPCista.exe\n",            # single space
            f"{self.SAMPLE_HASH}\tFulgorPCista.exe\n",           # tab separated
            f"{self.SAMPLE_HASH}   FulgorPCista.exe\n",          # multi space
        ]
        for content in formats:
            with self.subTest(content=content):
                res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH)

    def test_checksum_file_whitespace_and_casing(self):
        """Test leading/trailing spaces and uppercase hex."""
        content = f"   {self.SAMPLE_HASH.upper()}   FulgorPCista.exe   \n"
        res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
        self.assertEqual(res, self.SAMPLE_HASH.lower())

    def test_checksum_file_comments_and_blank_lines(self):
        """Test checksum files containing comments and blank lines."""
        content = f"""
# SHA256 checksums generated by CI
# Date: 2026-10-28
# Project: Fulgor PCista

{self.OTHER_HASH}  OtherFile.zip

# The main binary
{self.SAMPLE_HASH}  FulgorPCista.exe

# End of checksums
"""
        res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
        self.assertEqual(res, self.SAMPLE_HASH)

        # Check other file extraction
        res_other = parse_hash_from_checksum_file(content, "OtherFile.zip")
        self.assertEqual(res_other, self.OTHER_HASH)

    def test_checksum_file_path_prefixes(self):
        """Test checksum files that contain subfolder paths e.g. dist/ or ./."""
        cases = [
            f"{self.SAMPLE_HASH}  dist/FulgorPCista.exe",
            f"{self.SAMPLE_HASH}  .\\dist\\FulgorPCista.exe",
            f"{self.SAMPLE_HASH}  ./FulgorPCista.exe",
        ]
        for content in cases:
            with self.subTest(content=content):
                res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH)

    def test_checksum_file_single_hash_standalone(self):
        """Test standalone .sha256 file containing only the 64-character hash."""
        cases = [
            f"{self.SAMPLE_HASH}\n",
            f"  {self.SAMPLE_HASH}  \r\n",
            f"{self.SAMPLE_HASH.upper()}\n",
        ]
        for content in cases:
            with self.subTest(content=content):
                res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH.lower())

    def test_checksum_file_unrelated_file_skipped(self):
        """Checksum for a different file should not be returned for target."""
        content = f"{self.OTHER_HASH}  SomeOtherBinary.exe\n"
        res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
        self.assertEqual(res, "")

    def test_checksum_file_corrupt_lines_handled_gracefully(self):
        """Corrupt hex lines (not 64 chars or invalid hex) should be skipped without error."""
        content = f"""
not-a-hash FulgorPCista.exe
123456 FulgorPCista.exe
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  FulgorPCista.exe
{self.SAMPLE_HASH}  FulgorPCista.exe
"""
        res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
        self.assertEqual(res, self.SAMPLE_HASH)

    def test_body_markdown_formats(self):
        """Test parsing SHA-256 from release body markdown."""
        cases = [
            # Target filename specific
            (f"FulgorPCista.exe: `{self.SAMPLE_HASH}`", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"FulgorPCista.exe - {self.SAMPLE_HASH}", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"FulgorPCista.exe = `{self.SAMPLE_HASH}`", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"{self.SAMPLE_HASH}  FulgorPCista.exe", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"{self.SAMPLE_HASH} *FulgorPCista.exe", "FulgorPCista.exe", self.SAMPLE_HASH),
            # Generic labels
            (f"SHA-256: `{self.SAMPLE_HASH}`", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"SHA256: {self.SAMPLE_HASH}", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"checksum: `{self.SAMPLE_HASH}`", "FulgorPCista.exe", self.SAMPLE_HASH),
            (f"hash = {self.SAMPLE_HASH}", "FulgorPCista.exe", self.SAMPLE_HASH),
            # Uppercase hex in body
            (f"SHA256: `{self.SAMPLE_HASH.upper()}`", "FulgorPCista.exe", self.SAMPLE_HASH),
        ]
        for body, target, expected in cases:
            with self.subTest(body=body, target=target):
                res = parse_hash_from_body(body, target)
                self.assertEqual(res, expected)

    def test_body_markdown_multi_asset_isolation(self):
        """Ensure hash for target asset is chosen when body mentions multiple assets."""
        body = f"""
## Release Hashes
- FulgorPCista.exe: `{self.SAMPLE_HASH}`
- FulgorPCista-v1.5.0-windows-x64.zip: `{self.OTHER_HASH}`
"""
        res_exe = parse_hash_from_body(body, "FulgorPCista.exe")
        res_zip = parse_hash_from_body(body, "FulgorPCista-v1.5.0-windows-x64.zip")

        self.assertEqual(res_exe, self.SAMPLE_HASH)
        self.assertEqual(res_zip, self.OTHER_HASH)

    def test_checksum_file_utf8_bom_defect(self):
        """
        Adversarial probe: Windows PowerShell typically writes UTF-8 files with a BOM (\ufeff).
        Verifies UTF-8 BOM is stripped and hash is parsed successfully.
        """
        bom_content = f"\ufeff{self.SAMPLE_HASH}  FulgorPCista.exe\n"
        res = parse_hash_from_checksum_file(bom_content, "FulgorPCista.exe")
        self.assertEqual(res, self.SAMPLE_HASH, "Empirically confirms UTF-8 BOM is stripped and parsed cleanly")

    def test_body_markdown_table_and_bold_formatting_defect(self):
        """
        Adversarial probe: release notes containing markdown tables or bold filenames.
        Verifies markdown table and bold bullet point hash extraction.
        """
        table_body = f"| Asset | SHA256 |\n| FulgorPCista.exe | {self.SAMPLE_HASH} |"
        res_table = parse_hash_from_body(table_body, "FulgorPCista.exe")
        self.assertEqual(res_table, self.SAMPLE_HASH, "Empirically confirms markdown tables parse cleanly in release body")

        bold_body = f"### Checksums\n- **FulgorPCista.exe**: `{self.SAMPLE_HASH}`"
        res_bold = parse_hash_from_body(bold_body, "FulgorPCista.exe")
        self.assertEqual(res_bold, self.SAMPLE_HASH, "Empirically confirms bold bullet points parse cleanly in release body")


class TestE2ESecurityAndFailureModes(unittest.TestCase):
    """Adversarially test full updater apply_update workflow with mocks."""

    def setUp(self):
        self.updater = AppUpdater(current_version="1.5.0", current_comp=22)
        self.temp_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")

    def tearDown(self):
        _cleanup_dir(self.temp_dir)

    def test_apply_update_blocks_http_and_purges(self):
        """Calling apply_update with HTTP URL must fail and leave no temp files."""
        res = self.updater.apply_update("http://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe")
        self.assertFalse(res["success"])
        self.assertIn("segurança", res["error"].lower())
        self.assertFalse(os.path.exists(self.temp_dir))

    def test_apply_update_blocks_external_domain_and_purges(self):
        """Calling apply_update with external domain must fail and leave no temp files."""
        res = self.updater.apply_update("https://evil.com/releases/FulgorPCista.exe")
        self.assertFalse(res["success"])
        self.assertIn("segurança", res["error"].lower())
        self.assertFalse(os.path.exists(self.temp_dir))

    def test_apply_update_redirect_to_http_fails_gracefully(self):
        """A network redirect to HTTP during apply_update raises URLError and cleans up."""
        dummy_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        def raise_redirect_error(*args, **kwargs):
            raise urllib.error.URLError("Protocolo inseguro bloqueado em redirecionamento: http")

        with patch("urllib.request.OpenerDirector.open", side_effect=raise_redirect_error):
            res = self.updater.apply_update(dummy_url, expected_hash="a" * 64)
            self.assertFalse(res["success"])
            self.assertIn("Erro durante atualização", res["error"])
            self.assertFalse(os.path.exists(self.temp_dir))

    def test_apply_update_redirect_to_external_ip_fails_gracefully(self):
        """A network redirect to an external IP during apply_update raises URLError and cleans up."""
        dummy_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"

        def raise_redirect_error(*args, **kwargs):
            raise urllib.error.URLError("Redirecionamento não autorizado para domínio externo: 192.168.1.1")

        with patch("urllib.request.OpenerDirector.open", side_effect=raise_redirect_error):
            res = self.updater.apply_update(dummy_url, expected_hash="a" * 64)
            self.assertFalse(res["success"])
            self.assertIn("Erro durante atualização", res["error"])
            self.assertFalse(os.path.exists(self.temp_dir))

    def test_apply_update_missing_hash_aborts_and_purges(self):
        """When expected hash is missing/empty, download is purged and aborts."""
        dummy_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"
        mock_payload = b"FAKE_EXE_DATA"

        class MockResp:
            def __init__(self, data): self._bio = io.BytesIO(data)
            def read(self, s=-1): return self._bio.read(s)
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch("urllib.request.OpenerDirector.open", return_value=MockResp(mock_payload)):
            self.updater.update_info = {"download_url": dummy_url, "expected_sha256": ""}
            res = self.updater.apply_update()
            self.assertFalse(res["success"])
            self.assertEqual(res.get("code"), "SHA256_MISSING")
            self.assertFalse(os.path.exists(self.temp_dir))

    def test_apply_update_tampered_payload_aborts_and_purges(self):
        """When downloaded payload hash doesn't match expected hash, abort and purge."""
        dummy_url = "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.0/FulgorPCista.exe"
        mock_payload = b"CORRUPTED_OR_TAMPERED_EXE"
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

        class MockResp:
            def __init__(self, data): self._bio = io.BytesIO(data)
            def read(self, s=-1): return self._bio.read(s)
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch("urllib.request.OpenerDirector.open", return_value=MockResp(mock_payload)):
            res = self.updater.apply_update(dummy_url, expected_hash=expected)
            self.assertFalse(res["success"])
            self.assertEqual(res.get("code"), "SHA256_MISMATCH")
            self.assertFalse(os.path.exists(self.temp_dir))


if __name__ == "__main__":
    unittest.main()
