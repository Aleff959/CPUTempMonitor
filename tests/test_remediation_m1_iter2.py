"""
Regression and Verification Test Suite for Milestone 1 Remediation (Iteration 2).
Covers:
1. URL path traversal and strict host isolation in is_safe_github_url.
2. Checksum cascade priority (API digest -> Checksum file -> Body markdown).
3. UTF-8 BOM handling in parse_hash_from_checksum_file.
4. Markdown table pipes and bold formatting in parse_hash_from_body.
5. Semantic version comparison and pre-release tag parsing in _parse_version_tuple.
"""

import unittest
import io
import json
import urllib.request
import urllib.error
from unittest.mock import patch, MagicMock

import updater
from updater import (
    is_safe_github_url,
    parse_hash_from_checksum_file,
    parse_hash_from_body,
    _parse_version_tuple,
    _parse_comp_number,
    AppUpdater,
)


class TestURLSafetyRemediation(unittest.TestCase):
    """Verify URL path traversal prevention and strict host/repo pinning."""

    def test_path_traversal_on_github_com_rejected(self):
        traversals = [
            "https://github.com/Aleff959/CPUTempMonitor/releases/../../attacker/malware/releases/download/v1/FulgorPCista.exe",
            "https://github.com/Aleff959/CPUTempMonitor/../../attacker/repo/releases/download/v1/FulgorPCista.exe",
            "https://github.com/Aleff959/CPUTempMonitor/releases/../archive/../../evil/repo/archive/v1.zip",
        ]
        for url in traversals:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Path traversal should be rejected: {url}")

    def test_raw_and_codeload_foreign_repos_rejected(self):
        foreign_urls = [
            "https://raw.githubusercontent.com/attacker/malicious/main/FulgorPCista.exe",
            "https://raw.githubusercontent.com/evil-user/CPUTempMonitor/main/SHA256SUMS.txt",
            "https://raw.githubusercontent.com/Aleff959/OtherRepo/main/SHA256SUMS.txt",
            "https://codeload.github.com/attacker/malicious/zip/refs/tags/v1.5.0",
        ]
        for url in foreign_urls:
            with self.subTest(url=url):
                self.assertFalse(is_safe_github_url(url), f"Foreign raw/codeload repo must be rejected: {url}")

    def test_raw_and_codeload_official_repo_accepted(self):
        official_urls = [
            "https://raw.githubusercontent.com/Aleff959/CPUTempMonitor/main/SHA256SUMS.txt",
            "https://raw.githubusercontent.com/aleff959/cputempmonitor/v1.5.0/SHA256SUMS",
            "https://codeload.github.com/Aleff959/CPUTempMonitor/zip/refs/tags/v1.5.0",
        ]
        for url in official_urls:
            with self.subTest(url=url):
                self.assertTrue(is_safe_github_url(url), f"Official raw/codeload URL must be accepted: {url}")

    def test_objects_strict_host_equality(self):
        # Strict equality required
        self.assertTrue(is_safe_github_url("https://objects.githubusercontent.com/github-production-release-asset/123"))
        # Broad subdomains must not pass
        self.assertFalse(is_safe_github_url("https://sub.objects.githubusercontent.com/asset"))
        self.assertFalse(is_safe_github_url("https://malicious.githubusercontent.com/asset"))
        self.assertFalse(is_safe_github_url("https://attackergithubusercontent.com/asset"))


class TestChecksumAndBodyParsingRemediation(unittest.TestCase):
    """Verify UTF-8 BOM stripping and expanded markdown table/bold syntax."""

    SAMPLE_HASH = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_utf8_bom_in_checksum_file(self):
        bom_contents = [
            f"\ufeff{self.SAMPLE_HASH}  FulgorPCista.exe\n",
            f"\ufeff{self.SAMPLE_HASH} *FulgorPCista.exe\r\n",
            f"\ufeff{self.SAMPLE_HASH}\n",
            f"\ufeff# Header comment\n{self.SAMPLE_HASH}  FulgorPCista.exe\n",
            f"# Header\n\ufeff{self.SAMPLE_HASH}  FulgorPCista.exe\n",
        ]
        for content in bom_contents:
            with self.subTest(content=content[:20]):
                res = parse_hash_from_checksum_file(content, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH)

    def test_markdown_tables_in_release_body(self):
        table_markdowns = [
            f"| Asset | SHA256 |\n|---|---|\n| FulgorPCista.exe | {self.SAMPLE_HASH} |",
            f"| File | Hash |\n| **FulgorPCista.exe** | `{self.SAMPLE_HASH}` |",
            f"| {self.SAMPLE_HASH} | FulgorPCista.exe |",
            f"| `{self.SAMPLE_HASH}` | **FulgorPCista.exe** |",
        ]
        for md in table_markdowns:
            with self.subTest(md=md):
                res = parse_hash_from_body(md, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH)

    def test_markdown_bold_and_backticks_in_release_body(self):
        bold_markdowns = [
            f"- **FulgorPCista.exe**: `{self.SAMPLE_HASH}`",
            f"* **FulgorPCista.exe**: {self.SAMPLE_HASH}",
            f"- `FulgorPCista.exe`: `{self.SAMPLE_HASH}`",
            f"- *FulgorPCista.exe* = `{self.SAMPLE_HASH}`",
            f"- _FulgorPCista.exe_ - {self.SAMPLE_HASH}",
        ]
        for md in bold_markdowns:
            with self.subTest(md=md):
                res = parse_hash_from_body(md, "FulgorPCista.exe")
                self.assertEqual(res, self.SAMPLE_HASH)


class TestCascadePriorityRemediation(unittest.TestCase):
    """Verify checksum_url takes priority over body markdown."""

    CHECKSUM_FILE_HASH = "1111111111111111111111111111111111111111111111111111111111111111"
    BODY_MARKDOWN_HASH = "2222222222222222222222222222222222222222222222222222222222222222"

    def test_checksum_file_prioritized_over_body_markdown(self):
        app = AppUpdater(current_version="1.5.0", current_comp=22)

        release_api_response = {
            "tag_name": "v1.5.1",
            "name": "v1.5.1 | Comp. 23",
            "body": f"### Release Notes\n- FulgorPCista.exe: `{self.BODY_MARKDOWN_HASH}`",
            "assets": [
                {
                    "name": "FulgorPCista.exe",
                    "browser_download_url": "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.1/FulgorPCista.exe",
                    "size": 10240,
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/Aleff959/CPUTempMonitor/releases/download/v1.5.1/SHA256SUMS.txt",
                    "size": 256,
                },
            ],
        }

        checksum_file_content = f"{self.CHECKSUM_FILE_HASH}  FulgorPCista.exe\n".encode("utf-8")

        class MockResp:
            def __init__(self, data):
                self._data = data
            def read(self, *a):
                return self._data
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def mock_open(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "api.github.com" in url:
                return MockResp(json.dumps(release_api_response).encode("utf-8"))
            elif "SHA256SUMS.txt" in url:
                return MockResp(checksum_file_content)
            raise ValueError(f"Unexpected url: {url}")

        with patch("urllib.request.OpenerDirector.open", side_effect=mock_open):
            info = app.check_for_updates()

        self.assertTrue(info["success"])
        self.assertTrue(info["has_update"])
        # Crucial: Checksum file hash MUST win over the body markdown hash!
        self.assertEqual(info["expected_sha256"], self.CHECKSUM_FILE_HASH)


class TestVersioningRemediation(unittest.TestCase):
    """Verify pre-release tags do not invert version comparisons."""

    def test_pre_release_tags_stripped_correctly(self):
        cases = [
            ("1.4.9-beta.1", (1, 4, 9)),
            ("1.5.0-rc2", (1, 5, 0)),
            ("1.5.0-rc.1", (1, 5, 0)),
            ("v1.5.0-alpha", (1, 5, 0)),
            ("1.5.0-dirty", (1, 5, 0)),
            ("1.5.0+build123", (1, 5, 0)),
            ("1.5.0rc1", (1, 5, 0)),
            ("(1.5.0 | Comp. 22)", (1, 5, 0)),
        ]
        for v_input, expected in cases:
            with self.subTest(v_input=v_input):
                self.assertEqual(_parse_version_tuple(v_input), expected)

    def test_pre_release_comparison_semantics(self):
        # A pre-release of 1.4.9 must NOT be greater than 1.4.9 final
        self.assertLessEqual(_parse_version_tuple("1.4.9-beta.1"), _parse_version_tuple("1.4.9"))
        # A release of 1.5.0 must be greater than 1.4.9-beta.1
        self.assertGreater(_parse_version_tuple("1.5.0"), _parse_version_tuple("1.4.9-beta.1"))
        # 1.5.0 final must NOT be smaller than 1.5.0-rc1
        self.assertGreaterEqual(_parse_version_tuple("1.5.0"), _parse_version_tuple("1.5.0-rc1"))


if __name__ == "__main__":
    unittest.main()
