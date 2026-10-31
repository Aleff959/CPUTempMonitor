"""
Empirical Challenger Verification Suite for Milestone 2:
R2 Path Integrity, Autostart LPE Resistance & Process Cleanup Discrimination.

Author: challenger_m2_2 (Empirical Challenger)
Target: service_bridge.py, configurar_autostart.ps1, main.py
"""

import os
import sys
import re
import xml.etree.ElementTree as ET
import unittest
from unittest.mock import patch, MagicMock

# Ensure repo root is in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import service_bridge
import main


class TestChallengerM2PathAndProcess(unittest.TestCase):
    """Empirical verification for Milestone 2 path integrity and process discrimination."""

    def test_residual_user_path_audit_service_bridge(self):
        """
        Audit 1: Scan service_bridge.py for residual hardcoded user paths.
        Assert absence of C:\\Users\\, %USERPROFILE%, and unauthorized user profile paths.
        """
        sb_file = os.path.join(REPO_ROOT, "service_bridge.py")
        self.assertTrue(os.path.exists(sb_file), "service_bridge.py must exist")

        with open(sb_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            # Assert no hardcoded C:\Users\
            match_users = re.search(r"C:[\\/]Users[\\/]", line, re.IGNORECASE)
            self.assertIsNone(
                match_users,
                f"Line {idx} in service_bridge.py contains hardcoded user path: {line.strip()}",
            )

            # Assert no %USERPROFILE% or environment variable leaks
            match_uenv = re.search(r"%USERPROFILE%", line, re.IGNORECASE)
            self.assertIsNone(
                match_uenv,
                f"Line {idx} in service_bridge.py contains %USERPROFILE%: {line.strip()}",
            )

        print("\n[EMPIRICAL PROBE] service_bridge.py scanned: 0 hardcoded user paths found.")

    def test_residual_user_path_audit_autostart_ps1(self):
        """
        Audit 2: Scan configurar_autostart.ps1 for residual user paths.
        Assert absence of C:\\Users\\, LOCALAPPDATA, and %USERPROFILE%.
        """
        ps_file = os.path.join(REPO_ROOT, "configurar_autostart.ps1")
        self.assertTrue(os.path.exists(ps_file), "configurar_autostart.ps1 must exist")

        with open(ps_file, "r", encoding="utf-8") as f:
            ps_content = f.read()

        # Check for user paths
        self.assertFalse(
            bool(re.search(r"C:[\\/]Users[\\/]", ps_content, re.IGNORECASE)),
            "configurar_autostart.ps1 must not contain hardcoded C:\\Users\\ path",
        )
        self.assertNotIn(
            "LOCALAPPDATA",
            ps_content,
            "configurar_autostart.ps1 must not reference LOCALAPPDATA",
        )
        self.assertNotIn(
            "%USERPROFILE%",
            ps_content,
            "configurar_autostart.ps1 must not reference %USERPROFILE%",
        )

        # Check canonical target directory
        self.assertIn('${env:ProgramFiles}', ps_content)
        self.assertIn('"FulgorPCista"', ps_content)
        print("\n[EMPIRICAL PROBE] configurar_autostart.ps1 scanned: 0 residual user paths found.")

    def test_get_secure_executable_path_resolution_and_file_not_found(self):
        """
        Objective 1: Assert get_secure_executable_path() raises FileNotFoundError
        when canonical Program Files executable does not exist and running uncompiled
        outside dev repo.
        """
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        canonical_exe = os.path.join(prog_files, "FulgorPCista", "FulgorPCista.exe")

        # Scenario A: Canonical executable exists
        with patch("os.path.exists", side_effect=lambda p: os.path.normcase(p) == os.path.normcase(canonical_exe)):
            resolved = service_bridge.get_secure_executable_path()
            self.assertEqual(os.path.normcase(resolved), os.path.normcase(canonical_exe))

        # Scenario B: Outside dev repo, not frozen, canonical does not exist, running script
        def fake_exists_nondev(path):
            # Neither Program Files nor dist\FulgorPCista.exe exists
            norm = os.path.normcase(path)
            if "fulgorpcista.exe" in norm:
                return False
            return False

        with patch("os.path.exists", side_effect=fake_exists_nondev):
            with patch.object(sys, "frozen", False, create=True):
                with patch.object(sys, "argv", [os.path.join(REPO_ROOT, "main.py")]):
                    with self.assertRaises(FileNotFoundError) as ctx:
                        service_bridge.get_secure_executable_path()

                    err_msg = str(ctx.exception)
                    self.assertIn("FulgorPCista.exe", err_msg)
                    self.assertIn("Program Files", err_msg)
                    self.assertIn("A execução a partir de diretórios de usuário é proibida", err_msg)

        print("\n[EMPIRICAL PROBE] get_secure_executable_path raised FileNotFoundError outside dev repo as required.")

    def test_autostart_boot_service_xml_lpe_resistance(self):
        """
        Objective 2: Parse configurar_autostart.ps1 and extract the SYSTEM BootTrigger
        XML ($bootXml). Verify:
        1. Context / UserId is S-1-5-18 (NT AUTHORITY\\SYSTEM)
        2. Trigger is BootTrigger
        3. <Command> strictly points to $exePath which resolves to Program Files\\FulgorPCista\\FulgorPCista.exe
        4. Zero references to user-writable directories in the XML
        """
        ps_file = os.path.join(REPO_ROOT, "configurar_autostart.ps1")
        with open(ps_file, "r", encoding="utf-8") as f:
            ps_code = f.read()

        # Extract $bootXml = @" ... "@
        match = re.search(r'\$bootXml\s*=\s*@"([\s\S]*?)"@', ps_code)
        self.assertIsNotNone(match, "Failed to extract $bootXml block from configurar_autostart.ps1")

        boot_xml_raw = match.group(1).strip()

        # Verify $exePath assignment in script before $bootXml
        # In script: $targetProgramFilesDir = Join-Path ${env:ProgramFiles} "FulgorPCista"
        #            $targetExe = Join-Path $targetProgramFilesDir "FulgorPCista.exe"
        #            $exePath = $targetExe
        self.assertIn('$targetProgramFilesDir = Join-Path ${env:ProgramFiles} "FulgorPCista"', ps_code)
        self.assertIn('$targetExe = Join-Path $targetProgramFilesDir "FulgorPCista.exe"', ps_code)
        self.assertIn('$exePath = $targetExe', ps_code)

        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        expected_target_exe = os.path.join(prog_files, "FulgorPCista", "FulgorPCista.exe")

        # Substitute $exePath as PowerShell does
        boot_xml_rendered = boot_xml_raw.replace("$exePath", expected_target_exe)

        # Parse XML
        root = ET.fromstring(boot_xml_rendered)
        ns = {"ns": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

        # 1. Principal / UserId
        user_id_elem = root.find(".//ns:Principals/ns:Principal/ns:UserId", ns)
        self.assertIsNotNone(user_id_elem, "Principal UserId element missing in XML")
        self.assertEqual(user_id_elem.text.strip(), "S-1-5-18", "BootService must run under SYSTEM (S-1-5-18)")

        # 2. BootTrigger
        boot_trigger = root.find(".//ns:Triggers/ns:BootTrigger", ns)
        self.assertIsNotNone(boot_trigger, "BootTrigger element missing in XML")
        enabled = boot_trigger.find("ns:Enabled", ns)
        self.assertEqual(enabled.text.strip(), "true")

        # 3. Exec Command & Arguments
        cmd_elem = root.find(".//ns:Actions/ns:Exec/ns:Command", ns)
        self.assertIsNotNone(cmd_elem, "Exec Command element missing in XML")
        self.assertEqual(
            os.path.normcase(cmd_elem.text.strip()),
            os.path.normcase(expected_target_exe),
            f"<Command> must strictly point to {expected_target_exe}",
        )

        args_elem = root.find(".//ns:Actions/ns:Exec/ns:Arguments", ns)
        self.assertIsNotNone(args_elem, "Exec Arguments element missing in XML")
        self.assertEqual(args_elem.text.strip(), "-daemon")

        # 4. Zero references to user-writable directories in bootXml
        for dangerous_path in ["users", "appdata", "temp", "tmp", "localsettings", "roaming"]:
            self.assertNotIn(
                dangerous_path,
                boot_xml_rendered.lower(),
                f"Dangerous path '{dangerous_path}' found inside SYSTEM Boot XML!",
            )

        print("\n[EMPIRICAL PROBE] BootTrigger XML strictly bound to Program Files and SYSTEM SID S-1-5-18.")

    def test_process_cleanup_path_discrimination_unauthorized_path(self):
        """
        Objective 3: Test _cleanup_legacy_and_stale_processes.
        Simulate a process with name 'fulgorpcista.exe' residing outside authorized directories
        (e.g., C:\\Users\\Attacker\\fulgorpcista.exe). Assert it is NOT terminated.
        """
        class MockProc:
            def __init__(self, pid, name, exe_path, cmdline):
                self.pid = pid
                self.info = {
                    "pid": pid,
                    "name": name,
                    "exe": exe_path,
                    "cmdline": cmdline,
                }
                self.terminated = False
                self.killed = False

            def exe(self):
                return self.info["exe"]

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                pass

            def kill(self):
                self.killed = True

        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        canonical_exe = os.path.join(prog_files, "FulgorPCista", "FulgorPCista.exe")

        unauth_proc1 = MockProc(9101, "FulgorPCista.exe", r"C:\Users\Public\FulgorPCista.exe", [])
        unauth_proc2 = MockProc(9102, "fulgorpcista.exe", r"C:\Users\Alpha\AppData\Local\Temp\FulgorPCista.exe", ["-hide"])
        unauth_proc3 = MockProc(9103, "FulgorPCista.exe", r"C:\Windows\Temp\FulgorPCista.exe", [])

        # Legitimate stale UI process (should be terminated)
        stale_ui_proc = MockProc(9104, "FulgorPCista.exe", canonical_exe, ["-hide"])

        mock_procs = [unauth_proc1, unauth_proc2, unauth_proc3, stale_ui_proc]

        with patch("psutil.process_iter", return_value=mock_procs):
            main._cleanup_legacy_and_stale_processes()

        self.assertFalse(unauth_proc1.terminated, "Unauthorized process 1 must NOT be terminated")
        self.assertFalse(unauth_proc2.terminated, "Unauthorized process 2 must NOT be terminated")
        self.assertFalse(unauth_proc3.terminated, "Unauthorized process 3 must NOT be terminated")
        self.assertTrue(stale_ui_proc.terminated, "Legitimate stale UI process MUST be terminated")

        print("\n[EMPIRICAL PROBE] Process cleanup strictly discriminated unauthorized executable paths.")

    def test_process_cleanup_daemon_flags_discrimination(self):
        """
        Objective 3: Verify that processes running with -daemon or --daemon (as well as
        -service or --service) in the canonical path are strictly skipped and NOT terminated.
        """
        class MockProc:
            def __init__(self, pid, name, exe_path, cmdline):
                self.pid = pid
                self.info = {
                    "pid": pid,
                    "name": name,
                    "exe": exe_path,
                    "cmdline": cmdline,
                }
                self.terminated = False
                self.killed = False

            def exe(self):
                return self.info["exe"]

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                pass

            def kill(self):
                self.killed = True

        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        canonical_exe = os.path.join(prog_files, "FulgorPCista", "FulgorPCista.exe")

        daemon_1 = MockProc(9201, "FulgorPCista.exe", canonical_exe, ["-daemon"])
        daemon_2 = MockProc(9202, "FulgorPCista.exe", canonical_exe, ["--daemon"])
        daemon_3_caps = MockProc(9203, "FulgorPCista.exe", canonical_exe, ["-DAEMON"])
        daemon_4_multi = MockProc(9204, "FulgorPCista.exe", canonical_exe, [canonical_exe, "-daemon", "--extra"])
        service_1 = MockProc(9205, "FulgorPCista.exe", canonical_exe, ["-service"])
        service_2 = MockProc(9206, "FulgorPCista.exe", canonical_exe, ["--service"])

        all_daemons = [daemon_1, daemon_2, daemon_3_caps, daemon_4_multi, service_1, service_2]

        with patch("psutil.process_iter", return_value=all_daemons):
            main._cleanup_legacy_and_stale_processes()

        for proc in all_daemons:
            cmd = proc.info["cmdline"]
            self.assertFalse(
                proc.terminated,
                f"Process with daemon/service flag {cmd} was terminated when it must be skipped!",
            )

        print("\n[EMPIRICAL PROBE] Process cleanup strictly skipped all processes with daemon/service flags.")


if __name__ == "__main__":
    unittest.main()
