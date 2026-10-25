Add-Type -AssemblyName System.Windows.Forms

$exePath = "C:\Users\Alpha\AppData\Local\Programs\FulgorPCista\FulgorPCista.exe"
if (-not (Test-Path $exePath)) {
    [System.Windows.Forms.MessageBox]::Show("Executavel nao encontrado em: $exePath", "Erro - Fulgor PCista", 0, 16)
    exit 1
}

$action = New-ScheduledTaskAction -Execute $exePath -Argument "-hide"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

try {
    Register-ScheduledTask -TaskName "FulgorPCista_AutoStart" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    
    # Remove inicializacao antiga da chave Run tradicional que provocava o alerta UAC
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CPUTempMonitor" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "FulgorPCista" -ErrorAction SilentlyContinue

    [System.Windows.Forms.MessageBox]::Show("Configuração concluída com sucesso!`n`nO Fulgor PCista agora iniciará automaticamente com o Windows em segundo plano, com permissões completas e SEM pedir autorização UAC.", "Fulgor PCista - Sucesso", 0, 64)
} catch {
    [System.Windows.Forms.MessageBox]::Show("Erro ao registrar tarefa: $_", "Erro", 0, 16)
}
