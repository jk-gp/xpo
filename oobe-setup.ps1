# oobe-setup.ps1 (PS 5.1 compatible - no ternary operator)
# OEM Windows 11 24H2 bootstrap – creates GPAdmin2 (no password), disables OOBE,
# pins to 24H2, sets power to Never, downloads Hub with progress, installs+enrolls,
# opens Entra ID Join on first logon, logs/validates, then reboots.

$ErrorActionPreference = 'Stop'
$LogRoot = "C:\ITSetup"
New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
$LogFile = Join-Path $LogRoot ("OOBE-Setup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $LogFile -Append | Out-Null

function Write-Log {
  param([string]$Message,[ValidateSet("INFO","WARN","ERROR","SUCCESS")]$Level="INFO")
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "$ts [$Level] $Message"
  Add-Content -Path $LogFile -Value $line
  $color = switch ($Level) { "SUCCESS" {"Green"} "WARN" {"Yellow"} "ERROR" {"Red"} Default {"Gray"} }
  Write-Host $line -ForegroundColor $color
}
trap {
  Write-Log "UNHANDLED: $($_.Exception.Message)" "ERROR"
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Log "=== Starting Windows 11 24H2 OOBE bootstrap ==="

# 1) Local admin GPAdmin2 (no password)
try {
  if (-not (Get-LocalUser -Name "GPAdmin2" -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name "GPAdmin2" -NoPassword -AccountNeverExpires:$true -PasswordNeverExpires:$true | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member "GPAdmin2"
    Write-Log "Created local admin 'GPAdmin2' (no password) and added to Administrators." "SUCCESS"
  } else {
    Add-LocalGroupMember -Group "Administrators" -Member "GPAdmin2" -ErrorAction SilentlyContinue
    Write-Log "Local user 'GPAdmin2' exists; ensured admin group membership." "WARN"
  }

  $adminOk = (Get-LocalUser -Name "GPAdmin2" -ErrorAction SilentlyContinue) -and
             ((Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -match ("^$env:COMPUTERNAME\\GPAdmin2$") }))
  if ($adminOk) { Write-Log ("Verify local admin present+admin: {0}" -f $adminOk) "SUCCESS" }
  else { Write-Log ("Verify local admin present+admin: {0}" -f $adminOk) "ERROR" }
} catch { Write-Log "Create local admin failed: $($_.Exception.Message)" "ERROR"; throw }

# 2) Disable OOBE
try {
  $oobeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
  if (-not (Test-Path $oobeKey)) { New-Item -Path $oobeKey -Force | Out-Null }
  New-ItemProperty -Path $oobeKey -Name "SkipMachineOOBE" -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "SkipUserOOBE"    -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "PrivacyConsentStatus" -PropertyType DWord -Value 1 -Force | Out-Null

  $sysSetup = "HKLM:\SYSTEM\Setup"
  New-ItemProperty -Path $sysSetup -Name "OOBEInProgress"        -PropertyType DWord -Value 0 -Force | Out-Null
  New-ItemProperty -Path $sysSetup -Name "SetupType"             -PropertyType DWord -Value 0 -Force | Out-Null
  New-ItemProperty -Path $sysSetup -Name "SystemSetupInProgress" -PropertyType DWord -Value 0 -Force | Out-Null

  $o = Get-ItemProperty -Path $oobeKey
  $s = Get-ItemProperty -Path $sysSetup
  $oobeOk = ($o.SkipMachineOOBE -eq 1 -and $o.SkipUserOOBE -eq 1 -and $s.OOBEInProgress -eq 0)
  if ($oobeOk) { Write-Log ("OOBE disabled; verify: {0}" -f $oobeOk) "SUCCESS" }
  else { Write-Log ("OOBE disabled; verify: {0}" -f $oobeOk) "ERROR" }
} catch { Write-Log "Failed to set OOBE flags: $($_.Exception.Message)" "ERROR"; throw }

# 3) Pin to Windows 11 24H2 (TRV)
try {
  $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
  if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }
  New-ItemProperty -Path $wuKey -Name "ProductVersion"           -PropertyType String -Value "Windows 11" -Force | Out-Null
  New-ItemProperty -Path $wuKey -Name "TargetReleaseVersion"     -PropertyType DWord  -Value 1 -Force | Out-Null
  New-ItemProperty -Path $wuKey -Name "TargetReleaseVersionInfo" -PropertyType String -Value "24H2" -Force | Out-Null
  $trv = Get-ItemProperty -Path $wuKey
  $trvOk = ($trv.ProductVersion -eq "Windows 11" -and $trv.TargetReleaseVersion -eq 1 -and $trv.TargetReleaseVersionInfo -eq "24H2")
  if ($trvOk) { Write-Log ("Configured TRV for Windows 11 24H2. Verify: {0}" -f $trvOk) "SUCCESS" }
  else { Write-Log ("Configured TRV for Windows 11 24H2. Verify: {0}" -f $trvOk) "ERROR" }
} catch { Write-Log "Failed configuring TRV: $($_.Exception.Message)" "ERROR"; throw }

# 4) Power: Screen & Sleep = Never (AC/DC)
try {
  powercfg /change monitor-timeout-ac 0 | Out-Null
  powercfg /change monitor-timeout-dc 0 | Out-Null
  powercfg /change standby-timeout-ac 0 | Out-Null
  powercfg /change standby-timeout-dc 0 | Out-Null
  Write-Log "Set monitor/sleep timeouts to 'Never' for AC/DC." "SUCCESS"

  $pc = (powercfg /query) | Out-String
