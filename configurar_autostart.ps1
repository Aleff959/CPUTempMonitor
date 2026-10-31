param(
    [switch]$Silent,
    [string]$ExePath = ""
)

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Silent) { $argList += " -Silent" }
    if ($ExePath) { $argList += " -ExePath `"$ExePath`"" }
    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
    exit 0
}

if (-not $Silent) {
    Add-Type -AssemblyName System.Windows.Forms
}

# Definição estrita do caminho seguro de instalação em Program Files para mitigar LPE
$targetProgramFilesDir = Join-Path ${env:ProgramFiles} "FulgorPCista"
$targetExe = Join-Path $targetProgramFilesDir "FulgorPCista.exe"

# Se o executável não estiver presente no destino seguro, estagiar a partir de dist ou diretório atual
if (-not (Test-Path $targetExe)) {
    $candSources = @(
        $ExePath,
        (Join-Path $PSScriptRoot "dist\FulgorPCista.exe"),
        (Join-Path $PSScriptRoot "FulgorPCista.exe")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $foundSource = $null
    foreach ($cand in $candSources) {
        if (Test-Path $cand) {
            $foundSource = $cand
            break
        }
    }
    if ($foundSource) {
        New-Item -ItemType Directory -Path $targetProgramFilesDir -Force | Out-Null
        Copy-Item -Path $foundSource -Destination $targetExe -Force
        $sourceDir = Split-Path $foundSource -Parent
        Get-ChildItem -Path $sourceDir -Include "*.dll","*.config","*.ico" -Recurse | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $targetProgramFilesDir -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not (Test-Path $targetExe)) {
    if (-not $Silent) {
        [System.Windows.Forms.MessageBox]::Show(
            "Executável do Fulgor PCista não localizado em: $targetExe`n`nPara garantir a integridade do sistema e mitigar riscos de elevação de privilégios (LPE), a execução em nível SYSTEM exige que o binário resida em 'C:\Program Files\FulgorPCista'.",
            "Erro de Configuração - Fulgor PCista",
            0,
            16
        )
    }
    exit 1
}

$exePath = $targetExe

# 1. Obter o SID do usuário atual
$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

# 2. Tarefa Nível 2 (Serviço de Boot Pré-Logon na primeira tela do Windows - NT AUTHORITY\SYSTEM)
$bootXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\FulgorPCista_BootService</URI>
    <Description>Motor de Telemetria e Controle USB HID Pré-Logon do Fulgor PCista (Inicia junto com a primeira tela do Windows)</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Priority>4</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>$exePath</Command>
      <Arguments>-daemon</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# 3. Tarefa de Interface Gráfica e Bandeja Instantânea no Logon (Atraso Zero + Prioridade 4)
$logonXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\FulgorPCista_AutoStart</URI>
    <Description>Interface e Bandeja do Fulgor PCista no Logon sem UAC e atraso zero</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>$userSid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Priority>4</Priority>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>$exePath</Command>
      <Arguments>-hide</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$tempBootXml = Join-Path $env:TEMP "FulgorPCista_BootTask.xml"
$tempLogonXml = Join-Path $env:TEMP "FulgorPCista_LogonTask.xml"
[System.IO.File]::WriteAllText($tempBootXml, $bootXml, [System.Text.Encoding]::Unicode)
[System.IO.File]::WriteAllText($tempLogonXml, $logonXml, [System.Text.Encoding]::Unicode)

try {
    # Registrar Tarefa de Boot Pré-Logon (SYSTEM) e iniciar imediatamente
    $resBoot = & schtasks /create /tn "FulgorPCista_BootService" /xml $tempBootXml /f
    & schtasks /run /tn "FulgorPCista_BootService" | Out-Null

    # Registrar Tarefa de Interface no Logon
    $resLogon = & schtasks /create /tn "FulgorPCista_AutoStart" /xml $tempLogonXml /f

    Remove-Item $tempBootXml -Force -ErrorAction SilentlyContinue
    Remove-Item $tempLogonXml -Force -ErrorAction SilentlyContinue

    # Limpar qualquer resíduo anterior de StartupDelayInMSec caso existente
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name "StartupDelayInMSec" -ErrorAction SilentlyContinue
    }

    if (-not $Silent) {
        [System.Windows.Forms.MessageBox]::Show(
            "Serviço de Boot Pré-Logon (Nível 2) configurado com sucesso!`n`n- Motor USB HID: Inicia no Boot (junto com a 1ª tela do Windows / tela de bloqueio)`n- Interface e Bandeja: Disparo instantâneo no Logon (Prioridade 4, atraso zero)`n- Sem alertas de UAC",
            "Fulgor PCista - Serviço Pré-Logon",
            0,
            64
        )
    }
} catch {
    if (-not $Silent) {
        [System.Windows.Forms.MessageBox]::Show("Erro ao configurar inicialização: $_", "Erro", 0, 16)
    }
    exit 1
}
