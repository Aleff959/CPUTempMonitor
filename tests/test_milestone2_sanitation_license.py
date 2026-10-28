import os
import unittest
from pathlib import Path


class TestMilestone2SanitationAndLicense(unittest.TestCase):
    """
    Validation test suite for Milestone 2:
    - Removal of obsolete CPUTempMonitor.spec
    - Canonical status of FulgorPCista.spec (onefile packaging)
    - Licensing documentation and build path accuracy in README.md
    - Sanitization of build zip archives from repository root
    """

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent

    def test_legacy_spec_removed_from_disk(self):
        legacy_spec = self.repo_root / "CPUTempMonitor.spec"
        self.assertFalse(
            legacy_spec.exists(),
            "CPUTempMonitor.spec must be deleted from the repository root.",
        )

    def test_canonical_spec_is_valid_onefile(self):
        canonical_spec = self.repo_root / "FulgorPCista.spec"
        self.assertTrue(
            canonical_spec.exists(),
            "FulgorPCista.spec must exist as the canonical PyInstaller specification.",
        )

        content = canonical_spec.read_text(encoding="utf-8")
        self.assertIn(
            "name='FulgorPCista'",
            content,
            "Executable name must be FulgorPCista.",
        )
        self.assertIn(
            "LibreHardwareMonitorLib.dll",
            content,
            "FulgorPCista.spec must bundle LibreHardwareMonitorLib.dll.",
        )
        self.assertIn(
            "OpenHardwareMonitorServer.exe",
            content,
            "FulgorPCista.spec must bundle OpenHardwareMonitorServer.exe.",
        )
        self.assertIn(
            "collect_all('pythonnet')",
            content,
            "FulgorPCista.spec must collect pythonnet hooks.",
        )
        self.assertNotIn(
            "coll = COLLECT(",
            content,
            "FulgorPCista.spec must not contain a COLLECT block (must be OneFile mode).",
        )

    def test_readme_build_path_and_instructions(self):
        readme_path = self.repo_root / "README.md"
        self.assertTrue(readme_path.exists(), "README.md must exist.")

        content = readme_path.read_text(encoding="utf-8")
        self.assertIn(
            "dist/FulgorPCista.exe",
            content,
            "README.md must reference the onefile output binary at dist/FulgorPCista.exe.",
        )
        self.assertNotIn(
            "dist/FulgorPCista/FulgorPCista.exe",
            content,
            "README.md must not reference legacy onedir folder path dist/FulgorPCista/FulgorPCista.exe.",
        )
        self.assertNotIn(
            "dist/CPUTempMonitor",
            content,
            "README.md must not reference legacy binary path dist/CPUTempMonitor.",
        )

    def test_readme_mpl2_licensing_section(self):
        readme_path = self.repo_root / "README.md"
        content = readme_path.read_text(encoding="utf-8")

        # Section header
        self.assertIn(
            "## 📄 Licenciamento e Créditos de Terceiros",
            content,
            "README.md must contain dedicated section '## 📄 Licenciamento e Créditos de Terceiros'.",
        )

        # Attribution to LibreHardwareMonitorLib.dll and OpenHardwareMonitorServer.exe
        self.assertIn("LibreHardwareMonitorLib.dll", content)
        self.assertIn("v0.9.4.0", content)
        self.assertIn("OpenHardwareMonitorServer.exe", content)

        # License MPL 2.0 and Upstream repo link
        self.assertIn("Mozilla Public License 2.0 (MPL 2.0)", content)
        self.assertIn(
            "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor",
            content,
            "README.md must provide the official upstream link to LibreHardwareMonitor source code.",
        )

        # Source code availability terms
        self.assertTrue(
            "Seções 3.1 e 3.2" in content or "disponível" in content,
            "README.md must explain source availability requirements under MPL 2.0.",
        )

        # Boundary between MIT and MPL 2.0 (Larger Work)
        self.assertIn("Licença MIT", content)
        self.assertTrue(
            "Larger Work" in content or "Obra Maior" in content,
            "README.md must clarify the Larger Work boundary between MIT and MPL 2.0.",
        )

    def test_no_zip_archives_in_repo_root(self):
        root_zips = list(self.repo_root.glob("*.zip"))
        self.assertEqual(
            root_zips,
            [],
            f"Repository root must not contain legacy zip files: {root_zips}",
        )


if __name__ == "__main__":
    unittest.main()
