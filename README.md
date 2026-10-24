# CPU TEMP Monitor (Material You)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Aleff959/CPUTempMonitor)
[![Platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%2010-0078D6.svg)](https://github.com/Aleff959/CPUTempMonitor)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Aplicativo moderno e independente para Windows com design **Material You (Dark Mode)** para monitoramento de hardware em tempo real e controle direto do display digital de coolers USB (Semico / Ocypus / Rise Mode e similares).

Substitui completamente softwares proprietários instáveis (`DeviceDriver.exe` / `OpenHardwareMonitorServer`), comunicando-se diretamente via protocolo **USB HID** nativo e eliminando dependências externas.

---

## ✨ Recursos

* **🎨 Interface Material You:** Visual escuro moderno (paleta `#111418`), bordas arredondadas e integração com as bordas nativas do Windows 11 DWM.
* **❄️ Controle Direto USB HID:** Comunicação direta com microcontroladores de cooler (`VID_1A2C & PID_4984`, interface HID vendor-defined).
* **🔒 Modos Fixos de Exibição (Sem Alternância Indesejada):**
  * **Modo CPU:** Exibe a temperatura da CPU com o glifo fixo `°C` e o uso percentual (`%`).
  * **Modo GPU:** Exibe a temperatura da GPU (em Celsius) com o glifo `°F` como marcador visual e a potência em tempo real (`Watts`).
* **🔔 Integração Completa com a Bandeja (System Tray):**
  * Ícone personalizado na área de notificação do Windows.
  * Início minimizado silencioso via flag `-hide`.
  * Minimização ao fechar (`X`) ou minimizar (`_`), mantendo a telemetria ativa.
  * Menu de contexto de clique direito com opções de abrir, ocultar e fechar.
* **⚡ Alta Precisão e Baixo Consumo:** Telemetria via memória compartilhada ultrarrápida com fallback para `nvidia-smi` e `psutil`.

---

## 🛠️ Tecnologias Utilizadas

* **Python 3.12**
* **pywebview + WebView2** (Frontend moderno renderizado nativamente)
* **HTML5 / CSS3 / JavaScript** (Design responsivo Material You)
* **WinForms / ctypes / Win32 API** (Ciclo de vida de bandeja e comunicação USB HID)
* **PyInstaller** (Compilação para binário único empacotado)

---

## 🚀 Como Executar

### Pré-requisitos
* Windows 10 ou 11 (64-bit)
* Python 3.10+ (para execução a partir do código fonte)
* Microsoft Edge WebView2 Runtime (nativo no Windows 10/11)

### Instalação das dependências
```bash
pip install pywebview psutil pythonnet pyinstaller
```

### Executar a partir do código-fonte
```bash
python main.py
```

### Iniciar minimizado na bandeja:
```bash
python main.py -hide
```

---

## 📦 Como Compilar

Para gerar o executável autônomo com o PyInstaller:

```bash
python -m PyInstaller CPUTempMonitor.spec --noconfirm
```

O executável final estará disponível no diretório `dist/CPUTempMonitor/CPUTempMonitor.exe`.

---

## 📄 Licença

Distribuído sob a licença MIT. Consulte `LICENSE` para mais detalhes.
