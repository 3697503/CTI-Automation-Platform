# Powershell script to execute when a new Windows VM is set up. 

Write-Output "[*] Initializing Provision Script..."

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$DefaultUsername = "your username"
$DefaultPassword = "your password"
Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String 
Set-ItemProperty $RegPath "DefaultUsername" -Value "vagrant" -type String 
Set-ItemProperty $RegPath "DefaultPassword" -Value "vagrant" -type String

Write-Output "[*] Autologon Configured"

powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 3600
powercfg.exe /SETACTIVE SCHEME_CURRENT

powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 3600
powercfg.exe /SETACTIVE SCHEME_CURRENT

Write-Output "[*] Screen Timeout extended"

Set-MpPreference -ExclusionPath C:\Users\vagrant\vagrant_data

cd C:\Users\vagrant\vagrant_data
Set-ExecutionPolicy Unrestricted -Force

# Install PsExec with Choco 
$choco_command = Get-Command choco
if(-Not $choco_command) {
  iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}
choco install -y psexec
choco install -y 7zip

# Attempt to disable the firewall and WinDefend
netsh advfirewall set allprofiles state off
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Unblock-File disable-defender.ps1
.\disable-defender.ps1

# Launch Meterpreter at start up
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Meterpreter-Agent" `
    -Value "C:\Users\vagrant\vagrant_data\meterpreter\meterpreter-0.exe"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\vagrant\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\meterpreter-0.lnk")
$Shortcut.TargetPath = "C:\Users\vagrant\vagrant_data\meterpreter\meterpreter-0.exe"
$Shortcut.Save()

# Sysmon
cp "C:\Users\vagrant\vagrant_data\elastic_configs\sysmon-config.xml" "C:\Windows\config.xml"
C:\Users\vagrant\vagrant_data\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\config.xml

# Winlogbeat
cp "C:\Users\vagrant\vagrant_data\Winlogbeat\" "C:\Program Files\"
cd "C:\Program Files\Winlogbeat\"
.\install-service-winlogbeat.ps1
.\winlogbeat.exe -c winlogbeat.yml -e
.\winlogbeat.exe setup -e
Start-Service winlogbeat

# Setup Elastic Agent
(New-Object Net.WebClient).DownloadFile("https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-7.16.2-windows-x86_64.zip", "C:\Users\vagrant\Downloads\elastic-agent.zip")
cd "C:\Users\vagrant\Downloads\"
Expand-Archive .\elastic-agent.zip
cd .\elastic-agent\elastic-agent-7.16.2-windows-x86_64
cp "C:\Users\vagrant\vagrant_data\elastic_configs\elastic-agent.yml" ".\"
.\elastic-agent install

