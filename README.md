# ⚡ Fulgor PCista (v1.2.0 - Ororo)

[![Versão](https://img.shields.io/badge/vers%C3%A3o-1.2.0--Ororo-00b0ff.svg)](https://github.com/Aleff959/CPUTempMonitor/releases)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows%2011%20%7C%2010-0078D6.svg)](https://github.com/Aleff959/CPUTempMonitor)
[![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green.svg)](LICENSE)
[![Design](https://img.shields.io/badge/estilo-Material%20You%20Dark-111418.svg)](https://github.com/Aleff959/CPUTempMonitor)

O **Fulgor PCista** é uma suíte moderna, elegante e autônoma para Windows desenvolvida sob a filosofia de design **Material You (Dark Mode)**. O aplicativo realiza telemetria de hardware de alta precisão em tempo real e fornece controle direto do visor digital integrado de air coolers e water coolers USB (homologado especialmente no **Rise Mode AIR COOLER TEMP 6 PRO BLACK** e modelos equivalentes compatíveis com controladores Semico / Ocypus).

Substitui totalmente os utilitários proprietários pesados e instáveis (`DeviceDriver.exe` / `OpenHardwareMonitorServer`), comunicando-se diretamente via protocolo **USB HID** nativo, sem publicidade, sem telemetria intrusiva e com consumo mínimo de recursos do sistema.

---

## ✨ Principais Funcionalidades

* **🎨 Interface Material You Moderna:** Visual escuro sofisticado com paleta de cores orgânica, bordas arredondadas e integração imersiva com a barra de título nativa do Windows 11.
* **❄️ Controle Nativo USB HID:** Comunicação direta com microcontroladores de cooler digital (`VID 1A2C & PID 4984`, interface HID vendor-defined).
* **🔥 Monitoramento de GPU Hot Spot via NVAPI:** Leitura do ponto térmico mais crítico do silício de placas de vídeo NVIDIA através de integração de baixo nível, superando as limitações do `nvidia-smi` tradicional.
* **🎛️ Telemetria Dedicada da Placa-Mãe:** Acompanhamento térmico do barramento do sistema, chipset e circuitos de alimentação (VRM) exclusivo na tela do aplicativo, mantendo o display do cooler focado nos alvos principais de resfriamento.
* **🔒 Seleção Dinâmica para o Visor Físico:**
  * **Modo Processador (CPU):** Envia a temperatura da CPU acompanhada do indicador fixo `°C` e da carga de trabalho (`%`).
  * **Modo Placa de Vídeo (GPU):** Envia a temperatura de Hot Spot da GPU com o marcador `°F` (usado por especificação de hardware para rápida identificação visual) e o consumo elétrico real em `Watts`.
* **🔔 Integração Completa com a Bandeja do Sistema (System Tray):**
  * Inicialização silenciosa opcional em segundo plano através do parâmetro `-hide`.
  * Menu de contexto comercial em português para restauração, ocultação e encerramento limpo da aplicação.
  * Automação sem alertas repetitivos de UAC via Agendador de Tarefas do Windows.
* **ℹ️ Painel Informativo "Sobre":** Seção integrada com dados do hardware testado, referências da fabricante, créditos de engenharia reversa e tecnologias empregadas.

---

## 🎯 Dispositivo Homologado

* **Modelo:** Rise Mode AIR COOLER TEMP 6 PRO BLACK ([Página Oficial da Fabricante](https://risemode.com/p/temp-6-pro-black-argb))
* **Identificação de Hardware:** USB VID `1A2C` / PID `4984`
* **Formato de Envio:** Relatório de funcionalidades (Feature Report) de 64 bytes transmitido diretamente via Win32 HID API.

---

## 🤝 Créditos e Agradecimentos

Agradecimento especial à comunidade Open Source e ao desenvolvedor Linux que realizou a análise inicial do protocolo USB HID do cooler digital, tornando possível a comunicação nativa e o porte para esta aplicação independente.

---

## 🛠️ Tecnologias Utilizadas

* **Python 3.12**
* **pywebview + Microsoft Edge WebView2** (Interface visual leve e moderna)
* **HTML5 / CSS3 / JavaScript** (Design responsivo e paleta Material You)
* **LibreHardwareMonitorLib / .NET CLR (pythonnet)** (Leitura nativa NVAPI e barramentos)
* **WinForms / ctypes / Win32 API** (Ciclo de vida, bandeja do sistema e comunicação USB HID)
* **PyInstaller** (Empacotamento em executável autônomo de alta performance)

---

## 🚀 Como Executar

### Pré-requisitos
* Windows 10 ou 11 (64-bit)
* Python 3.10 ou superior (caso execute diretamente do código-fonte)
* Microsoft Edge WebView2 Runtime (já presente de forma nativa no Windows 10 e 11)

### Instalação das dependências
```bash
pip install pywebview psutil pythonnet pyinstaller
```

### Execução a partir do código-fonte
```bash
python main.py
```

### Iniciar silenciosamente na bandeja:
```bash
python main.py -hide
```

---

## 📦 Como Compilar

Para gerar o executável autônomo:

```bash
python -m PyInstaller FulgorPCista.spec --noconfirm
```

O executável final será gerado no diretório `dist/FulgorPCista/FulgorPCista.exe`.

---

## 📄 Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.
