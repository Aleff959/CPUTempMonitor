Add-Type -AssemblyName System.Windows.Forms

$exePath = Join-Path $env:LOCALAPPDATA "Programs\FulgorPCista\FulgorPCista.exe"
if (-not (Test-Path $exePath)) {
    [System.Windows.Forms.MessageBox]::Show("Executável não encontrado em: $exePath", "Erro - Fulgor PCista", 0, 16)
    exit 1
}

# 1. Obter o SID do usuário atual
$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

# 2. Montar XML com Prioridade Normal balanceada (Priority 7) e disparo no Logon sem UAC
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\FulgorPCista_AutoStart</URI>
    <Description>Inicialização do Fulgor PCista no boot com privilégios adequados e sem UAC</Description>
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
    <Priority>7</Priority>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
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

$tempXml = Join-Path $env:TEMP "FulgorPCista_Task.xml"
[System.IO.File]::WriteAllText($tempXml, $xml, [System.Text.Encoding]::Unicode)

try {
    # 3. Registrar a tarefa usando o XML
    $res = & schtasks /create /tn "FulgorPCista_AutoStart" /xml $tempXml /f
    Remove-Item $tempXml -Force -ErrorAction SilentlyContinue

    # 4. Limpar qualquer resíduo anterior de StartupDelayInMSec caso existente
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name "StartupDelayInMSec" -ErrorAction SilentlyContinue
    }

    [System.Windows.Forms.MessageBox]::Show("Inicialização configurada com sucesso!`n`n- Prioridade de Processamento: Normal (Nível 7)`n- Sem UAC no boot`n`nO Fulgor PCista iniciará de forma silenciosa na inicialização do sistema.", "Fulgor PCista - Autostart", 0, 64)
} catch {
    [System.Windows.Forms.MessageBox]::Show("Erro ao configurar inicialização: $_", "Erro", 0, 16)
}
