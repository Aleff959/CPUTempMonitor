# ⚡ Fulgor PCista (v1.3.0 - Ororo)

[![Versão](https://img.shields.io/badge/vers%C3%A3o-1.3.0--Ororo-00b0ff.svg)](https://github.com/Aleff959/CPUTempMonitor/releases)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows%2011%20%7C%2010-0078D6.svg)](https://github.com/Aleff959/CPUTempMonitor)
[![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green.svg)](LICENSE)
[![Design](https://img.shields.io/badge/estilo-Material%20You%20Dark-111418.svg)](https://github.com/Aleff959/CPUTempMonitor)

O **Fulgor PCista** é uma suíte moderna, elegante e autônoma para Windows desenvolvida sob a filosofia de design **Material You (Dark Mode)**. O aplicativo realiza telemetria de hardware de alta precisão em tempo real e fornece controle direto do visor digital integrado de air coolers e water coolers USB (homologado especialmente no **Rise Mode AIR COOLER TEMP 6 PRO BLACK** e modelos equivalentes compatíveis com controladores Semico / Ocypus).

Substitui totalmente os utilitários proprietários pesados e instáveis (`DeviceDriver.exe` / `OpenHardwareMonitorServer`), comunicando-se diretamente via protocolo **USB HID** nativo, sem publicidade, sem telemetria intrusiva e com consumo mínimo de recursos do sistema.

---

## ✨ Principais Funcionalidades

* **🎨 Interface Material You Moderna:** Visual escuro sofisticado com paleta de cores orgânica, grade balanceada 2x2, bordas arredondadas e integração imersiva com a barra de título nativa do Windows 11.
* **❄️ Controle Nativo USB HID:** Comunicação direta com microcontroladores de cooler digital (`VID 1A2C & PID 4984`, interface HID vendor-defined).
* **🔥 Monitoramento de GPU Hot Spot via NVAPI:** Leitura do ponto térmico mais crítico do silício de placas de vídeo NVIDIA através de integração de baixo nível, superando as limitações do `nvidia-smi` tradicional.
* **🎯 Taxa de Quadros (FPS) e Consumo de VRAM em Tempo Real:** Motor híbrido de alta fidelidade integrando memória compartilhada do RivaTuner Statistics Server (RTSS) e rastreamento ETW via PresentMon, exibindo a taxa de quadros e o percentual de consumo da memória de vídeo.
* **🕹️ Troca Automática Inteligente para Jogos:** Detecção em tempo real de renderização 3D e processos de jogos em execução. O aplicativo comuta o display do cooler para o modo FPS & VRAM automaticamente ao entrar em qualquer jogo e restaura a visualização anterior (CPU ou GPU) logo após sair.
* **🎛️ Telemetria Dedicada da Placa-Mãe:** Acompanhamento térmico do barramento do sistema, chipset e circuitos de alimentação (VRM) exclusivo na tela do aplicativo, mantendo o display do cooler focado nos alvos principais de resfriamento.
* **🔒 Seleção Dinâmica para o Visor Físico:**
  * **Modo Processador (CPU):** Envia a temperatura da CPU acompanhada do indicador fixo `°C` e da carga de trabalho (`%`).
  * **Modo Placa de Vídeo (GPU):** Envia a temperatura de Hot Spot da GPU com o marcador `°F` (usado por especificação de hardware para rápida identificação visual) e o consumo elétrico real em `Watts`.
  * **Modo FPS & VRAM:** Envia a taxa de quadros em tempo real (`FPS`) no display principal e o percentual de consumo de `VRAM` (`%`) no display secundário.
* **🔔 Integração Completa com a Bandeja do Sistema (System Tray):**
  * Inicialização silenciosa opcional em segundo plano através do parâmetro `-hide`.
  * Menu de contexto comercial em português para restauração, ocultação e encerramento limpo da aplicação.
  * Automação sem alertas repetitivos de UAC via Agendador de Tarefas do Windows.
* **🚀 Executável Único & Central de Atualizações OTA:** Distribuído em executável único portátil (.exe OneFile) com sistema de atualização integrado ao GitHub Releases. Notifica sobre novas versões, permite verificar novidades e aplica atualizações automaticamente com reinício transparente.
* **ℹ️ Painel Informativo "Sobre":** Seção integrada com dados do hardware testado, referências da fabricante, créditos de engenharia reversa e tecnologias empregadas.

---

## 📊 Convenção de Unidades do Cooler Digital

O microcontrolador do cooler digital (fabricado sob arquitetura OEM Semico / Ocypus, identificado pelo USB VID `1A2C` e PID `4984`) utiliza a interface USB HID com pacotes Feature Report de 64 bytes (`Report ID 0x07`). O painel físico é composto por dois visores de 7 segmentos de 3 dígitos com glifos luminosos silkscreened fixos:
* **Visor Principal (Esquerda/Superior):** Exibe 3 dígitos numéricos acompanhados dos glifos luminosos **`°C`** e **`°F`**.
* **Visor Secundário (Direita/Inferior):** Exibe 3 dígitos numéricos acompanhados dos glifos luminosos **`%`** e **`W`**.

### Mapeamento dos Registradores de Modo (Byte 4)
A ativação dos glifos luminosos no painel de LED é controlada diretamente pelo **Byte 4** do relatório USB HID:
* **Registrador `0x10`:** Acende o glifo **`°C`** no visor principal e o glifo **`%`** no visor secundário.
* **Registrador `0x01`:** Acende o glifo **`°F`** no visor principal e o glifo **`W`** no visor secundário.

> **💡 Racional Técnico da Convenção (°F & Watts):**  
> Por limitação física de firmware do microcontrolador do cooler, a unidade de potência elétrica em Watts (`W`) é acoplada exclusivamente ao modo `0x01` (`°F`). Não existe combinação de registrador de fábrica que permita acender simultaneamente `°C` e `W`.  
> Para disponibilizar a telemetria de consumo elétrico da GPU sem prejuízo da precisão térmica, o **Fulgor PCista** transmite o valor de Hot Spot em **graus Celsius (°C)** reais e utiliza o glifo físico **`°F`** como um **índice térmico diferenciador de hardware**. Essa convenção permite ao usuário identificar à distância se o visor está exibindo a CPU (`°C`) ou a GPU (`°F`), ao mesmo tempo em que ativa o medidor de consumo em Watts (`W`).

### Tabela de Convenções de Telemetria
| Modo de Operação | Visor Principal | Glifo Físico | Telemetria Transmitida | Visor Secundário | Glifo Físico | Telemetria Secundária | Registrador (Byte 4) | Racional e Finalidade |
|---|---|---|---|---|---|---|---|---|
| **Processador (CPU)** | Temp. CPU | **`°C`** | Temperatura da CPU (°C) | Carga CPU | **`%`** | Uso percentual da CPU (%) | `0x10` | Padrão clássico internacional para processadores. |
| **Placa de Vídeo (GPU)** | Hot Spot GPU | **`°F`** | Ponto crítico da GPU (°C) | Consumo GPU | **`W`** | Potência real da placa de vídeo (Watts) | `0x01` | O glifo `°F` opera como marcador visual de hardware para a GPU e habilita o medidor de consumo em Watts. |
| **Jogos (FPS & VRAM)** | Taxa de Quadros | *(Numérico)* | Taxa de quadros em tempo real (FPS) | Consumo VRAM | **`%`** | Percentual de memória de vídeo ocupada (%) | `0x10` | O modo `0x10` mantém o glifo `%` aceso para saturação de memória VRAM em jogos (comutação manual ou via Troca Automática). |

---

## 🎯 Dispositivos Homologados e Matriz de Compatibilidade

* **Dispositivo de Referência Homologado:** Rise Mode AIR COOLER TEMP 6 PRO BLACK ([Página Oficial da Fabricante](https://risemode.com/p/temp-6-pro-black-argb))
* **Identificação de Hardware:** USB VID `1A2C` / PID `4984`
* **Formato de Envio:** Relatório de funcionalidades (Feature Report) de 64 bytes transmitido diretamente via Win32 HID API (Report ID `0x07`).

### 📋 Tabela de Dispositivos Compatíveis Homologados
A tabela abaixo apresenta os coolers digitais com visor duplo homologados e compatíveis com o protocolo USB HID do Fulgor PCista:

| Fabricante | Linha / Modelo | Identificador USB (VID:PID) | Interface & Protocolo | Suporte a Hot Spot / FPS | Status de Homologação |
|---|---|---|---|---|---|
| **Rise Mode** | **AIR COOLER TEMP 6 PRO BLACK** | `1A2C:4984` | USB HID 64-byte (Report `0x07`) | Sim (Total) | 🟢 **Homologado & Testado (Dispositivo de Referência)** |
| **Rise Mode** | **AIR COOLER TEMP 6 PRO WHITE** | `1A2C:4984` | USB HID 64-byte (Report `0x07`) | Sim (Total) | 🟢 **Homologado (Mesmo PCB e Firmware)** |
| **Rise Mode** | **WATER COOLER AURA ICE DIGITAL (240/360mm)** | `1A2C:4984` | USB HID 64-byte (Report `0x07`) | Sim (Total) | 🟢 **Compatível (Mesmo Barramento USB)** |
| **Ocypus** | **Iota A62 Digital / Delta L36 Digital** | `1A2C:4984` | USB HID 64-byte (Report `0x07`) | Sim (Total) | 🟢 **Compatível (Controlador Semico OEM)** |
| **OEM Xinyao / Semico** | **Coolers Digitais Chineses (Genéricos)** | `1A2C:4984` | USB HID 64-byte / Memória Compartilhada | Sim | 🟡 **Compatível via Driver Nativo ou Servidor Local** |

### 🎮 Suporte à Telemetria de GPU (NVIDIA NVAPI Hot Spot & AMD Radeon)
* **NVIDIA GeForce:** Suporte nativo completo a sensores de GPU Hot Spot via NVAPI (GTX 16xx, RTX 20xx, RTX 30xx, RTX 40xx e superiores) através da `LibreHardwareMonitorLib.dll`. A leitura do Hot Spot identifica o ponto térmico mais crítico do silício gráfico.
* **AMD Radeon:** Suporte à temperatura de junção (Junction Temperature) e temperatura de core/borda (Edge Temperature), acompanhado de leitura de consumo e uso de VRAM, com mecanismo de fallback gracioso para sensores disponíveis.
* **Captura de Taxa de Quadros (FPS):** Mecanismo híbrido de alto desempenho lendo a memória compartilhada do RivaTuner Statistics Server (RTSS) com fallback para rastreamento de eventos ETW via PresentMon, garantindo monitoramento sem sobrecarga em taxas de quadros competitivas.

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

O executável final autônomo será gerado em `dist/FulgorPCista.exe`.

---

## 📄 Licenciamento e Créditos de Terceiros

### Código Autoral do Fulgor PCista
O código-fonte autoral do **Fulgor PCista** é distribuído sob os termos da **Licença MIT**. Para maiores detalhes, consulte o arquivo [`LICENSE`](LICENSE).  
Copyright (c) 2026 Aleff959.

### Componentes de Terceiros e Licença Mozilla Public License 2.0 (MPL 2.0)
Para viabilizar a telemetria de sensores de hardware de baixo nível (incluindo leitura térmica do silício via barramentos da placa-mãe e sensores NVIDIA NVAPI), este projeto redistribui e integra binários compilados a partir do projeto de código aberto **LibreHardwareMonitor**:

* **`LibreHardwareMonitorLib.dll`** (v0.9.4.0)
  * **Projeto de Origem:** [LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor)
  * **Autoria e Direitos Autorais:** Copyright (c) LibreHardwareMonitor Contributors e Open Hardware Monitor Contributors.
  * **Termos de Licença:** Licenciado sob a [Mozilla Public License 2.0 (MPL 2.0)](https://www.mozilla.org/en-US/MPL/2.0/).
  * **Acesso ao Código-Fonte Upstream:** Em estrita conformidade com as Seções 3.1 e 3.2 da licença MPL 2.0, o código-fonte integral original correspondente encontra-se publicamente disponível no repositório oficial do projeto: [https://github.com/LibreHardwareMonitor/LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor).

* **`OpenHardwareMonitorServer.exe` & `OpenHardwareMonitorServer.exe.config`** (v1.0.0.0)
  * **Finalidade:** Serviço auxiliar em segundo plano (.NET Framework 4.7.2) que consome a biblioteca `LibreHardwareMonitorLib.dll` para alimentar a memória compartilhada Win32 (`xinyao_hardware_mapfile`) com dados térmicos de CPU e placa-mãe.
  * **Termos de Licença:** Vincula e distribui componentes cobertos sob a [Mozilla Public License 2.0 (MPL 2.0)](https://www.mozilla.org/en-US/MPL/2.0/).

### Fronteira de Licenciamento e Obras Maiores (Larger Works - MPL 2.0, Seção 3.3)
A distribuição conjunta desses binários com o executável Fulgor PCista constitui uma "Obra Maior" (*Larger Work*) nos termos da Seção 3.3 da Mozilla Public License 2.0. Os termos da Licença MIT aplicam-se exclusivamente ao código-fonte autoral deste projeto, permanecendo os componentes `LibreHardwareMonitorLib.dll` e `OpenHardwareMonitorServer.exe` estritamente regidos pela Mozilla Public License 2.0.
