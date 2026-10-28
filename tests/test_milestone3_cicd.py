import os
import unittest
import yaml
import re
from updater import parse_hash_from_checksum_file, compute_sha256

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REQUIREMENTS_PATH = os.path.join(REPO_ROOT, "requirements.txt")
WORKFLOW_PATH = os.path.join(REPO_ROOT, ".github", "workflows", "build.yml")


class TestRequirementsReproducibility(unittest.TestCase):
    """Validates the structure and pinning of requirements.txt."""

    def test_requirements_file_exists(self):
        self.assertTrue(os.path.isfile(REQUIREMENTS_PATH), "requirements.txt must exist at repo root")

    def test_pinned_dependencies_present(self):
        with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        expected_pins = {
            "psutil": "7.2.2",
            "pywebview": "6.2.1",
            "pythonnet": "3.1.0",
            "clr_loader": "0.3.1",
            "pyinstaller": "6.22.3",
            "pyinstaller-hooks-contrib": "2026.7",
        }

        found_pins = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                pkg, ver = line.split("==", 1)
                found_pins[pkg.strip()] = ver.strip()

        for pkg, ver in expected_pins.items():
            self.assertIn(pkg, found_pins, f"Package {pkg} must be listed in requirements.txt")
            self.assertEqual(found_pins[pkg], ver, f"Package {pkg} version mismatch: expected {ver}, got {found_pins[pkg]}")


class TestGitHubActionsWorkflow(unittest.TestCase):
    """Validates the GitHub Actions workflow syntax and required steps."""

    def test_workflow_file_exists(self):
        self.assertTrue(os.path.isfile(WORKFLOW_PATH), ".github/workflows/build.yml must exist")

    def test_workflow_yaml_syntax(self):
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIsInstance(data, dict, "Workflow root must be a YAML dictionary")
        self.assertIn("name", data)
        self.assertIn("on", data)
        self.assertIn("jobs", data)

    def test_workflow_triggers(self):
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        triggers = data.get("on")
        self.assertIsInstance(triggers, dict, "'on' must be a mapping of triggers")
        self.assertIn("push", triggers, "Workflow must trigger on push")
        self.assertIn("workflow_dispatch", triggers, "Workflow must trigger on workflow_dispatch")

        push_branches = triggers["push"].get("branches", [])
        self.assertIn("main", push_branches, "Push trigger must include 'main'")
        self.assertIn("master", push_branches, "Push trigger must include 'master'")

    def test_workflow_runner_and_steps(self):
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        jobs = data.get("jobs", {})
        self.assertIn("build", jobs, "Must define a 'build' job")
        job = jobs["build"]

        self.assertEqual(job.get("runs-on"), "windows-latest", "Runner must be windows-latest")

        steps = job.get("steps", [])
        self.assertGreaterEqual(len(steps), 6, "Must contain all required build and publishing steps")

        # Step 1: Checkout
        checkout_step = steps[0]
        self.assertEqual(checkout_step.get("uses"), "actions/checkout@v4")

        # Step 2: Setup Python 3.12
        python_step = steps[1]
        self.assertEqual(python_step.get("uses"), "actions/setup-python@v5")
        self.assertEqual(python_step.get("with", {}).get("python-version"), "3.12")

        # Step 3: Install dependencies
        install_step = steps[2]
        self.assertIn("requirements.txt", install_step.get("run", ""))
        self.assertIn("pip install --upgrade pip", install_step.get("run", ""))

        # Step 4: Compile OneFile
        compile_step = steps[3]
        self.assertIn("PyInstaller", compile_step.get("run", ""))
        self.assertIn("FulgorPCista.spec", compile_step.get("run", ""))

        # Step 5: Verify executable & calculate SHA-256
        hash_step = steps[4]
        hash_script = hash_step.get("run", "")
        self.assertIn("Get-FileHash", hash_script)
        self.assertIn("SHA256", hash_script)
        self.assertIn("dist/FulgorPCista.exe.sha256", hash_script)
        self.assertIn("dist/SHA256SUMS", hash_script)

        # Step 6: Upload artifacts
        upload_step = steps[5]
        self.assertEqual(upload_step.get("uses"), "actions/upload-artifact@v4")
        upload_with = upload_step.get("with", {})
        self.assertEqual(upload_with.get("name"), "FulgorPCista-Windows-x64")
        self.assertIn("dist/FulgorPCista.exe", upload_with.get("path", ""))
        self.assertIn("dist/FulgorPCista.exe.sha256", upload_with.get("path", ""))
        self.assertIn("dist/SHA256SUMS", upload_with.get("path", ""))

    def test_checksum_file_compatibility_with_updater(self):
        """Ensures the checksum format produced by the workflow is parseable by updater.py."""
        dummy_hash = "c38942b5d49527a8a1464fca442a19df60c5b8653c4b26b50918ad43d29a3312"
        checksum_content = f"{dummy_hash}  FulgorPCista.exe\n"

        parsed_hash = parse_hash_from_checksum_file(checksum_content, "FulgorPCista.exe")
        self.assertEqual(parsed_hash, dummy_hash)

        # Also test with asterisks (binary mode)
        checksum_content_bin = f"{dummy_hash} *FulgorPCista.exe\n"
        parsed_hash_bin = parse_hash_from_checksum_file(checksum_content_bin, "FulgorPCista.exe")
        self.assertEqual(parsed_hash_bin, dummy_hash)


if __name__ == "__main__":
    unittest.main()
