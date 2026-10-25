Add-Type -AssemblyName System.Windows.Forms

$exePath = "C:\Users\Alpha\AppData\Local\Programs\FulgorPCista\FulgorPCista.exe"
if (-not (Test-Path $exePath)) {
    [System.Windows.Forms.MessageBox]::Show("Executável não encontrado em: $exePath", "Erro - Fulgor PCista", 0, 16)
    exit 1
}

# 1. Obter o SID do usuário atual
$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

# 2. Montar XML com Prioridade Máxima de CPU/I-O (Priority 0) e disparo instantâneo no Logon sem Delay
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\FulgorPCista_AutoStart</URI>
    <Description>Inicialização Prioritária do Fulgor PCista no boot com privilégios máximos e sem UAC</Description>
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
    <Priority>0</Priority>
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

$tempXml = "$env:TEMP\FulgorPCista_Task_Priority0.xml"
[System.IO.File]::WriteAllText($tempXml, $xml, [System.Text.Encoding]::Unicode)

try {
    # 3. Registrar a tarefa usando o XML prioritário
    $res = & schtasks /create /tn "FulgorPCista_AutoStart" /xml $tempXml /f
    Remove-Item $tempXml -Force -ErrorAction SilentlyContinue

    # 4. Otimizar o atraso de inicialização do Windows (StartupDelay) para arranque instantâneo de apps
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "StartupDelayInMSec" -Value 0 -Type DWord -Force

    [System.Windows.Forms.MessageBox]::Show("Prioridade máxima configurada com sucesso!`n`n- Prioridade de Processamento: Nível 0 (Tempo Real)`n- Atraso de boot do Windows zerado (StartupDelay: 0ms)`n`nO Fulgor PCista agora será um dos primeiros aplicativos a iniciar no boot.", "Fulgor PCista - Prioridade Máxima", 0, 64)
} catch {
    [System.Windows.Forms.MessageBox]::Show("Erro ao aplicar prioridade: $_", "Erro", 0, 16)
}
