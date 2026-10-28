import os
import unittest
from pathlib import Path


class TestMilestone4UiDocs(unittest.TestCase):
    """
    Automated test suite for Milestone 4: UI Transparency & Hardware Documentation.
    Validates:
    - In ui/index.html:
      * Telemetry conventions across CPU, GPU, and FPS/VRAM modes.
      * Informative tooltips / title attributes on metric cards and selector buttons.
      * Expanded control-note explaining all 3 modes and why °F is illuminated for GPU and W.
      * Hardware telemetry explanation section in the About modal.
    - In README.md:
      * Dedicated section 'Convenção de Unidades do Cooler Digital' with register mapping (0x10 and 0x01).
      * Technical rationale for °F physical marker and Watts coupling.
      * Homologated hardware matrix covering Rise Mode TEMP 6 PRO, Aura Ice, Ocypus Iota/Delta, OEM Semico.
      * GPU telemetry support documentation (NVIDIA NVAPI Hot Spot and AMD Radeon).
    """

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.ui_html_path = self.repo_root / "ui" / "index.html"
        self.readme_path = self.repo_root / "README.md"

        self.assertTrue(self.ui_html_path.exists(), "ui/index.html must exist")
        self.assertTrue(self.readme_path.exists(), "README.md must exist")

        self.ui_content = self.ui_html_path.read_text(encoding="utf-8")
        self.readme_content = self.readme_path.read_text(encoding="utf-8")

    # =========================================================================
    # UI / HTML TESTS
    # =========================================================================

    def test_ui_metric_cards_tooltips(self):
        """Verify that metric cards have descriptive title attributes for telemetry conventions."""
        # CPU card
        self.assertIn('id="cardCpu"', self.ui_content)
        self.assertIn('title="Processador (CPU): Visor Principal = Temp. CPU (°C) | Visor Secundário = Carga de Trabalho (%)', self.ui_content)

        # GPU card
        self.assertIn('id="cardGpu"', self.ui_content)
        self.assertIn('title="Placa de Vídeo (GPU): Visor Principal = GPU Hot Spot (°C com marcador físico °F no visor) | Visor Secundário = Consumo Elétrico (W)', self.ui_content)

        # FPS card
        self.assertIn('id="cardFps"', self.ui_content)
        self.assertIn('title="Jogos (FPS & VRAM): Visor Principal = Taxa de Quadros em Tempo Real (FPS) | Visor Secundário = Consumo de Memória VRAM (%)', self.ui_content)

        # Motherboard card
        self.assertIn('id="cardMb"', self.ui_content)
        self.assertIn('Telemetria de Sistema: Monitoramento térmico de VRM e barramento da Placa-Mãe', self.ui_content)

    def test_ui_gpu_info_badge_present(self):
        """Verify that the GPU card header contains an informative badge explaining °F convention."""
        self.assertIn('class="info-badge"', self.ui_content)
        self.assertIn("Convenção do Visor: O hardware do cooler acende o marcador luminoso '°F'", self.ui_content)
        self.assertIn("O valor exibido na tela do app é a temperatura real em °C", self.ui_content)

    def test_ui_selector_buttons_tooltips(self):
        """Verify that segmented selector buttons have informative tooltips."""
        # CPU button
        self.assertIn('id="btnCpu"', self.ui_content)
        self.assertIn('title="Modo CPU: Visor Principal = Temp. CPU (°C) | Visor Secundário = Carga (%) [Registrador 0x10]"', self.ui_content)

        # GPU button
        self.assertIn('id="btnGpu"', self.ui_content)
        self.assertIn('title="Modo GPU: Visor Principal = GPU Hot Spot (°C com marcador físico °F) | Visor Secundário = Consumo em Watts (W) [Registrador 0x01]"', self.ui_content)

        # FPS button
        self.assertIn('id="btnFps"', self.ui_content)
        self.assertIn('title="Modo FPS & VRAM: Visor Principal = Taxa de Quadros (FPS) | Visor Secundário = Consumo de VRAM (%) [Registrador 0x10]"', self.ui_content)

    def test_ui_banner_badge_title(self):
        """Verify banner unit badge explains the hardware register convention."""
        self.assertIn('id="bannerUnitBadge"', self.ui_content)
        self.assertIn('title="Convenção de hardware: Registrador 0x10 (°C & %) e Registrador 0x01 (°F & W)"', self.ui_content)

    def test_ui_expanded_control_note(self):
        """Verify that control-note clearly explains all 3 modes and why °F illuminates for GPU/W."""
        self.assertIn('class="control-note"', self.ui_content)
        self.assertIn("Convenção de Exibição no Visor Digital do Cooler:", self.ui_content)

        # CPU mode in control-note
        self.assertIn("Processador (CPU)", self.ui_content)
        self.assertIn("Temp. CPU (<strong>°C</strong>)", self.ui_content)
        self.assertIn("Carga da CPU (<strong>%</strong>)", self.ui_content)

        # GPU mode in control-note
        self.assertIn("Placa de Vídeo (GPU)", self.ui_content)
        self.assertIn("GPU Hot Spot", self.ui_content)
        self.assertIn("marcador luminoso <strong>°F</strong>", self.ui_content)
        self.assertIn("Consumo em Watts (<strong>W</strong>)", self.ui_content)

        # FPS mode in control-note
        self.assertIn("Jogos (FPS & VRAM)", self.ui_content)
        self.assertIn("Taxa de Quadros (<strong>FPS</strong>)", self.ui_content)
        self.assertIn("Consumo de VRAM (<strong>%</strong>)", self.ui_content)

        # Explanation of °F hardware reason
        self.assertIn("Por que o visor acende °F na GPU?", self.ui_content)
        self.assertIn("VID 1A2C / PID 4984", self.ui_content)
        self.assertIn("registrador 0x01 (°F)", self.ui_content)

    def test_ui_about_modal_telemetry_section(self):
        """Verify that About modal contains dedicated hardware telemetry convention section."""
        self.assertIn('class="about-sec"', self.ui_content)
        self.assertIn("Convenção de Unidades do Cooler Digital", self.ui_content)
        self.assertIn("telemetry-convention-card", self.ui_content)
        self.assertIn("Modo CPU (0x10)", self.ui_content)
        self.assertIn("Modo GPU (0x01)", self.ui_content)
        self.assertIn("Modo FPS & VRAM (0x10)", self.ui_content)
        self.assertIn("Racional da Arquitetura do Firmware:", self.ui_content)
        self.assertIn("índice térmico diferenciador de hardware", self.ui_content)

    # =========================================================================
    # README.MD TESTS
    # =========================================================================

    def test_readme_unit_convention_section(self):
        """Verify README contains dedicated section on cooler unit convention and registers."""
        self.assertIn("## 📊 Convenção de Unidades do Cooler Digital", self.readme_content)
        self.assertIn("Mapeamento dos Registradores de Modo (Byte 4)", self.readme_content)
        self.assertIn("Registrador `0x10`", self.readme_content)
        self.assertIn("Registrador `0x01`", self.readme_content)
        self.assertIn("0x10", self.readme_content)
        self.assertIn("0x01", self.readme_content)

        # Explains the physical pairing
        self.assertIn("Acende o glifo **`°C`** no visor principal e o glifo **`%`** no visor secundário", self.readme_content)
        self.assertIn("Acende o glifo **`°F`** no visor principal e o glifo **`W`** no visor secundário", self.readme_content)

        # Technical rationale
        self.assertIn("Racional Técnico da Convenção (°F & Watts)", self.readme_content)
        self.assertIn("índice térmico diferenciador de hardware", self.readme_content)

        # Table of conventions
        self.assertIn("Tabela de Convenções de Telemetria", self.readme_content)
        self.assertIn("Processador (CPU)", self.readme_content)
        self.assertIn("Placa de Vídeo (GPU)", self.readme_content)
        self.assertIn("Jogos (FPS & VRAM)", self.readme_content)

    def test_readme_homologated_hardware_matrix(self):
        """Verify README contains the full homologated hardware compatibility matrix."""
        self.assertIn("## 🎯 Dispositivos Homologados e Matriz de Compatibilidade", self.readme_content)
        self.assertIn("### 📋 Tabela de Dispositivos Compatíveis Homologados", self.readme_content)

        # Required homologated devices
        self.assertIn("Rise Mode", self.readme_content)
        self.assertIn("AIR COOLER TEMP 6 PRO BLACK", self.readme_content)
        self.assertIn("AIR COOLER TEMP 6 PRO WHITE", self.readme_content)
        self.assertIn("WATER COOLER AURA ICE DIGITAL", self.readme_content)
        self.assertIn("Ocypus", self.readme_content)
        self.assertIn("Iota A62 Digital", self.readme_content)
        self.assertIn("Delta L36 Digital", self.readme_content)
        self.assertIn("OEM Xinyao / Semico", self.readme_content)

        # USB hardware identifiers
        self.assertIn("1A2C:4984", self.readme_content)
        self.assertIn("Report `0x07`", self.readme_content)

    def test_readme_gpu_telemetry_support(self):
        """Verify README documents GPU telemetry support for NVIDIA NVAPI and AMD Radeon."""
        self.assertIn("### 🎮 Suporte à Telemetria de GPU (NVIDIA NVAPI Hot Spot & AMD Radeon)", self.readme_content)
        self.assertIn("NVIDIA GeForce", self.readme_content)
        self.assertIn("NVAPI", self.readme_content)
        self.assertIn("Hot Spot", self.readme_content)
        self.assertIn("AMD Radeon", self.readme_content)
        self.assertIn("Junction Temperature", self.readme_content)
        self.assertIn("VRAM", self.readme_content)
        self.assertIn("RivaTuner Statistics Server (RTSS)", self.readme_content)
        self.assertIn("PresentMon", self.readme_content)


if __name__ == "__main__":
    unittest.main()
