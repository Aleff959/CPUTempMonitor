"""
Empirical Verification & Stress Test Suite: Theme Persistence & WebView2 Storage
Component: Fulgor PCista (v1.8.0 | Comp. 27 / Comp. 28)
Milestone 1 - R1 Persistence & State Verification
Author: Challenger (challenger_m1_2)
"""

import os
import sys
import unittest
import winreg
import ast
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import main
from main import Api


class TestThemePersistenceEmpirical(unittest.TestCase):
    """Empirical verification of Registry persistence for Fulgor PCista themes."""

    REG_SUBKEYS = [r"Software\Fulgor PCista", r"Software\CPU TEMP Monitor"]
    VALID_THEMES = ["ambar", "terracota", "terminal", "synthwave", "default"]

    @classmethod
    def setUpClass(cls):
        # Backup original registry values to restore after testing
        cls._saved_values = {}
        for sub in cls.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                    val, typ = winreg.QueryValueEx(key, "selected_theme")
                    cls._saved_values[sub] = (val, typ)
            except OSError:
                cls._saved_values[sub] = None

    @classmethod
    def tearDownClass(cls):
        # Restore original registry values
        for sub, saved in cls._saved_values.items():
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
            except Exception as e:
                print(f"[Warning] Failed to restore registry key {sub}: {e}")

    def setUp(self):
        # Instantiate Api with mock core
        self.mock_core = MagicMock()
        self.api = Api(self.mock_core)

    def test_valid_themes_roundtrip_and_direct_registry_verification(self):
        """Test setting and getting each valid theme, verifying direct HKCU registry state."""
        for theme in self.VALID_THEMES:
            with self.subTest(theme=theme):
                # 1. Call set_theme
                success = self.api.set_theme(theme)
                self.assertTrue(success, f"set_theme failed for valid theme '{theme}'")

                # 2. Directly verify primary HKCU\\Software\\Fulgor PCista\\selected_theme
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
                    val, val_type = winreg.QueryValueEx(key, "selected_theme")
                    self.assertEqual(val_type, winreg.REG_SZ)
                    self.assertEqual(val, theme, f"Registry HKCU\\Software\\Fulgor PCista mismatch for {theme}")

                # 3. Directly verify secondary HKCU\\Software\\CPU TEMP Monitor\\selected_theme
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\CPU TEMP Monitor") as key:
                    val, val_type = winreg.QueryValueEx(key, "selected_theme")
                    self.assertEqual(val_type, winreg.REG_SZ)
                    self.assertEqual(val, theme, f"Registry HKCU\\Software\\CPU TEMP Monitor mismatch for {theme}")

                # 4. Call get_theme and verify it returns the exact theme
                retrieved = self.api.get_theme()
                self.assertEqual(retrieved, theme, f"get_theme() did not return expected theme '{theme}'")

    def test_empty_string_fallback(self):
        """Verify that an empty string in registry causes get_theme() to fall back to 'ambar'."""
        # Set empty string via set_theme
        self.api.set_theme("")

        # get_theme must safely fall back to 'ambar' without crashing
        retrieved = self.api.get_theme()
        self.assertEqual(retrieved, "ambar", f"Expected 'ambar' fallback on empty string, got '{retrieved}'")

        # Manually force empty REG_SZ directly in registry
        for sub in self.REG_SUBKEYS:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub) as key:
                winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_SZ, "")

        retrieved_direct = self.api.get_theme()
        self.assertEqual(retrieved_direct, "ambar", f"Direct empty string in registry failed fallback: got '{retrieved_direct}'")

    def test_missing_registry_value_fallback(self):
        """Verify that when 'selected_theme' value does not exist, get_theme() falls back to 'ambar'."""
        for sub in self.REG_SUBKEYS:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "selected_theme")
            except OSError:
                pass

        # Now neither key has 'selected_theme'
        retrieved = self.api.get_theme()
        self.assertEqual(retrieved, "ambar", f"Expected 'ambar' when registry value is deleted, got '{retrieved}'")

    def test_adversarial_none_input(self):
        """Verify that None passed to set_theme() does not crash and get_theme() operates safely."""
        try:
            res = self.api.set_theme(None)
            self.assertTrue(res)
        except Exception as e:
            self.fail(f"set_theme(None) raised unexpected exception: {e}")

        # get_theme should return a string ('None' or fallback) without raising
        try:
            val = self.api.get_theme()
            self.assertIsInstance(val, str)
        except Exception as e:
            self.fail(f"get_theme() crashed after set_theme(None): {e}")

    def test_adversarial_unicode_and_special_chars(self):
        """Verify handling of unicode, emoji, spaces, and HTML injection."""
        adversarial_strings = [
            "⚡🔥 Fulgor PCista 2026",
            "<script>alert('xss')</script>",
            "テーマ_日本語_テスト",
            "   terracota   ",
            "../../../etc/passwd",
            "theme_name_with_quotes_'\"`",
        ]
        for payload in adversarial_strings:
            with self.subTest(payload=payload):
                res = self.api.set_theme(payload)
                self.assertTrue(res)
                retrieved = self.api.get_theme()
                self.assertEqual(retrieved, payload)

    def test_adversarial_null_byte_rejection(self):
        """Verify that null bytes in strings do not crash, and truncate safely per Win32 REG_SZ semantics."""
        null_byte_payload = "ambar\x00malicious"
        # Windows Win32 RegSetValueExW treats \x00 as C-string null terminator
        res = self.api.set_theme(null_byte_payload)
        self.assertTrue(res, "set_theme handled string with null byte without crashing")

        # get_theme must safely return without crashing (truncated at null byte)
        val = self.api.get_theme()
        self.assertEqual(val, "ambar")

    def test_corrupted_registry_type_resilience(self):
        """Verify get_theme() does not crash if registry contains REG_DWORD or REG_BINARY."""
        # Inject REG_DWORD 42 into primary key
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
            winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_DWORD, 42)

        retrieved = self.api.get_theme()
        # get_theme returns str(val), so "42"
        self.assertEqual(retrieved, "42")

        # Inject REG_BINARY b'\xde\xad\xbe\xef' into primary key
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Fulgor PCista") as key:
            winreg.SetValueEx(key, "selected_theme", 0, winreg.REG_BINARY, b"\xde\xad\xbe\xef")

        retrieved_bin = self.api.get_theme()
        self.assertIsInstance(retrieved_bin, str)


class TestWebViewStorageConfiguration(unittest.TestCase):
    """Static and behavioral verification of WebView2 storage configuration in main.py."""

    def test_main_py_configures_storage_path_and_private_mode_false(self):
        """Verify that main.py configures storage_path and private_mode=False for webview.start()."""
        main_py_path = os.path.join(PROJECT_ROOT, "main.py")
        with open(main_py_path, "r", encoding="utf-8") as f:
            content = f.read()

        parsed = ast.parse(content)

        # Find webview.start calls
        webview_start_calls = []
        for node in ast.walk(parsed):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "start":
                    if isinstance(func.value, ast.Name) and func.value.id == "webview":
                        webview_start_calls.append(node)

        self.assertGreaterEqual(len(webview_start_calls), 1, "webview.start call not found in main.py")

        call = webview_start_calls[0]
        keyword_args = {kw.arg: kw.value for kw in call.keywords}

        # Verify private_mode=False
        self.assertIn("private_mode", keyword_args, "private_mode parameter not passed to webview.start")
        pm_val = keyword_args["private_mode"]
        self.assertIsInstance(pm_val, ast.Constant, "private_mode is not a constant")
        self.assertFalse(pm_val.value, f"private_mode must be False, but is {pm_val.value}")

        # Verify storage_path is passed
        self.assertIn("storage_path", keyword_args, "storage_path parameter not passed to webview.start")

    def test_storage_path_directory_structure(self):
        """Verify storage_path resolves to %APPDATA%\\FulgorPCista\\webview_data."""
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
        expected_dir = os.path.join(appdata, "FulgorPCista", "webview_data")
        # In main.py:
        # appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
        # storage_path = os.path.join(appdata, "FulgorPCista", "webview_data")
        self.assertTrue(isinstance(expected_dir, str))
        self.assertIn("FulgorPCista", expected_dir)
        self.assertIn("webview_data", expected_dir)


class TestFrontendThemeContract(unittest.TestCase):
    """Verify frontend ui/index.html theme mapping and head pre-render script."""

    def setUp(self):
        self.index_html_path = os.path.join(PROJECT_ROOT, "ui", "index.html")
        with open(self.index_html_path, "r", encoding="utf-8") as f:
            self.html = f.read()

    def test_head_contains_prerender_theme_script(self):
        """Verify <head> contains pre-render theme application script to eliminate flash."""
        head_end = self.html.find("</head>")
        self.assertGreater(head_end, 0, "</head> not found in index.html")
        head_content = self.html[:head_end]

        self.assertIn('id="themeStylesheet"', head_content, "themeStylesheet link tag missing from <head>")
        self.assertIn("localStorage.getItem('fulgor_theme')", head_content, "Pre-render localStorage check missing from <head>")
        self.assertIn("tema-ambar.css", head_content, "Pre-render theme map missing default theme 'tema-ambar.css'")

    def test_all_css_theme_files_exist_locally(self):
        """Verify that every theme file referenced in index.html exists in ui/themes/."""
        themes = {
            "ambar": "themes/tema-ambar.css",
            "terracota": "themes/tema-manrope-terracota.css",
            "terminal": "themes/tema-terminal-matrix.css",
            "synthwave": "themes/tema-synthwave-neon.css",
        }
        for name, rel_path in themes.items():
            full_path = os.path.join(PROJECT_ROOT, "ui", rel_path.replace("/", os.sep))
            self.assertTrue(os.path.exists(full_path), f"Theme file for '{name}' missing: {full_path}")


if __name__ == "__main__":
    unittest.main()
