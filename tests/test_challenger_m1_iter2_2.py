"""
Adversarial Stress Test Suite for Milestone 1 Iteration 2 (OTA Updater Security & Edge Cases).
Author: Challenger 2 (Empirical Challenger)
Target: Fulgor PCista updater.py

Covers empirical tests for:
1. Baseline verification of test_challenger_m1_2.py suite.
2. BOM handling: UTF-8, UTF-16 (LE/BE, byte decoding, PowerShell Out-File defaults).
3. Multi-line markdown tables: standard tables, prefix matching / substring safety, reverse tables, multi-column tables.
4. Pre-release tag semantic comparisons against final releases (SemVer & PEP 440 formats).
"""

import unittest
import urllib.request
import urllib.error
import os
import sys
import io
import json
from unittest.mock import patch

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import updater
from updater import (
    _parse_version_tuple,
    _parse_comp_number,
    parse_hash_from_checksum_file,
    parse_hash_from_body,
    is_safe_github_url,
    AppUpdater,
)


class TestBOMHandlingAdversarial(unittest.TestCase):
    """Adversarially stress-test BOM handling for UTF-8 and UTF-16."""

    SAMPLE_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_utf8_bom_string_handling(self):
        """Verify parse_hash_from_checksum_file with UTF-8 BOM in various string positions."""
        # BOM at start of string
        s1 = f"\ufeff{self.SAMPLE_HASH}  FulgorPCista.exe\n"
        self.assertEqual(parse_hash_from_checksum_file(s1, "FulgorPCista.exe"), self.SAMPLE_HASH)

        # BOM on every line
        s2 = f"\ufeff# Header comment\n\ufeff{self.SAMPLE_HASH}  FulgorPCista.exe\n"
        self.assertEqual(parse_hash_from_checksum_file(s2, "FulgorPCista.exe"), self.SAMPLE_HASH)

        # Standalone hash with BOM
        s3 = f"\ufeff{self.SAMPLE_HASH}\n"
        self.assertEqual(parse_hash_from_checksum_file(s3, "FulgorPCista.exe"), self.SAMPLE_HASH)

    def test_utf16_decoded_string_handling(self):
        """Verify parse_hash_from_checksum_file when content is a decoded UTF-16 string containing BOM."""
        raw = f"{self.SAMPLE_HASH}  FulgorPCista.exe\n"
        # utf-16-le decode preserving \ufeff BOM
        decoded_le_bom = raw.encode("utf-16").decode("utf-16-le")
        self.assertTrue(decoded_le_bom.startswith("\ufeff"))
        self.assertEqual(parse_hash_from_checksum_file(decoded_le_bom, "FulgorPCista.exe"), self.SAMPLE_HASH)

    def test_utf16_http_stream_decoding_vulnerability(self):
        """
        Adversarial probe: Windows PowerShell 5.1 default Out-File encoding is UTF-16 LE.
        When a checksum file is downloaded over HTTP in check_for_updates / apply_update,
        it is decoded via c_resp.read().decode('utf-8', errors='ignore').
        Verifies that raw UTF-16 LE bytes fail to decode properly under UTF-8.
        """
        raw_text = f"{self.SAMPLE_HASH}  FulgorPCista.exe\n"
        utf16_le_bytes = raw_text.encode("utf-16")  # contains \xff\xfe BOM

        # Decoding UTF-16 bytes as UTF-8 with errors='ignore' leaves null bytes
        decoded_utf8 = utf16_le_bytes.decode("utf-8", errors="ignore")
        self.assertIn("\x00", decoded_utf8, "UTF-16 bytes decoded as UTF-8 must leave null bytes")

        # Parsing this string fails because length of hash token is corrupted
        result = parse_hash_from_checksum_file(decoded_utf8, "FulgorPCista.exe")
        self.assertEqual(result, "", "Empirically confirms raw UTF-16 stream fails under UTF-8 decoder")


class TestMarkdownTableParsingAdversarial(unittest.TestCase):
    """Adversarially stress-test multi-line markdown table parsing."""

    SAMPLE_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    OTHER_HASH  = "1111111111111111111111111111111111111111111111111111111111111111"

    def test_multiline_markdown_table_standard(self):
        """Standard 2-column markdown table with header and separator."""
        table = f"""
# Release Notes

| Asset | SHA256 Hash |
| :--- | :--- |
| FulgorPCista-setup.zip | {self.OTHER_HASH} |
| FulgorPCista.exe | {self.SAMPLE_HASH} |
| OtherPackage.tar.gz | 3333333333333333333333333333333333333333333333333333333333333333 |
"""
        self.assertEqual(parse_hash_from_body(table, "FulgorPCista.exe"), self.SAMPLE_HASH)
        self.assertEqual(parse_hash_from_body(table, "FulgorPCista-setup.zip"), self.OTHER_HASH)

    def test_multiline_markdown_table_reverse_order(self):
        """Markdown table with SHA256 in column 1 and Asset in column 2."""
        table = f"""
| SHA256 | Asset |
| --- | --- |
| {self.OTHER_HASH} | FulgorPCista-setup.zip |
| {self.SAMPLE_HASH} | FulgorPCista.exe |
"""
        self.assertEqual(parse_hash_from_body(table, "FulgorPCista.exe"), self.SAMPLE_HASH)

    def test_multiline_markdown_table_prefix_substring_vulnerability(self):
        """
        Adversarial probe: A release table with a preceding file name sharing the suffix 'FulgorPCista.exe'
        (e.g., 'Windows-x86-FulgorPCista.exe' or 'Legacy-FulgorPCista.exe').
        Demonstrates that lack of a left word boundary causes parse_hash_from_body to capture the wrong hash.
        """
        wrong_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        correct_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        table = f"""
| File | SHA256 |
| Windows-x86-FulgorPCista.exe | {wrong_hash} |
| FulgorPCista.exe | {correct_hash} |
"""
        extracted = parse_hash_from_body(table, "FulgorPCista.exe")
        print(f"\n[EMPIRICAL FINDING] Prefix collision extracted: {extracted}")
        # The defect causes extracted to be wrong_hash instead of correct_hash
        self.assertEqual(extracted, wrong_hash, "Empirically confirms prefix substring collision bug in regex")


class TestPreReleaseSemanticVersioningAdversarial(unittest.TestCase):
    """Adversarially stress-test pre-release tag semantic comparisons against final releases."""

    def test_standard_semver_pre_release_stripping(self):
        """SemVer suffixes like -beta.1, -rc.2, -alpha are stripped to base tuple."""
        self.assertEqual(_parse_version_tuple("1.4.9-beta.1"), (1, 4, 9))
        self.assertEqual(_parse_version_tuple("1.5.0-rc.2"), (1, 5, 0))
        self.assertEqual(_parse_version_tuple("1.5.0-dirty"), (1, 5, 0))

    def test_pep440_dot_and_single_char_pre_release_vulnerabilities(self):
        """
        Adversarial probe: PEP 440 formats such as '1.5.0.rc1', '1.5.0.dev1', '1.5.0a1', '1.5.0b2'.
        Because regex requires (?<=\\d)(?:rc|alpha|beta...) and does not handle dot prefixes or single 'a'/'b',
        these pre-release versions append an extra digit (1, 5, 0, 1), inverting comparison against final 1.5.0.
        """
        # Case 1: Dot-separated pre-release tags
        self.assertEqual(_parse_version_tuple("1.5.0.rc1"), (1, 5, 0, 1))
        self.assertEqual(_parse_version_tuple("1.5.0.dev1"), (1, 5, 0, 1))
        self.assertEqual(_parse_version_tuple("1.5.0.alpha2"), (1, 5, 0, 2))

        # Case 2: PEP 440 short forms (a1, b2)
        self.assertEqual(_parse_version_tuple("1.5.0a1"), (1, 5, 0, 1))
        self.assertEqual(_parse_version_tuple("1.5.0b2"), (1, 5, 0, 2))

        # Demonstrates inversion: pre-release evaluates as GREATER than final release
        v_final = _parse_version_tuple("1.5.0")
        v_alpha = _parse_version_tuple("1.5.0a1")
        self.assertGreater(v_alpha, v_final, "Empirically confirms 1.5.0a1 evaluates as greater than final 1.5.0")

    def test_prerelease_vs_final_release_update_limitation(self):
        """
        Adversarial probe: When user is running a pre-release (e.g. 1.4.9-beta.1)
        and final 1.4.9 is released (without a comp number):
        Because both parse to (1, 4, 9), remote > curr evaluates to False.
        """
        app = AppUpdater(current_version="1.4.9-beta.1", current_comp=0)
        curr_tuple = _parse_version_tuple(app.current_version)
        remote_tuple = _parse_version_tuple("1.4.9")
        self.assertEqual(curr_tuple, remote_tuple)
        self.assertFalse(remote_tuple > curr_tuple, "Final release is not detected as newer than pre-release")


if __name__ == "__main__":
    unittest.main()
