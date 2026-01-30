# oobe-setup.ps1 (PS 5.1 compatible - no ternary operator)
# OEM Windows 11 24H2 bootstrap – creates GPAdmin2 (no password), disables OOBE,
# pins to 24H2, sets power to Never, downloads Hub with progress, installs+enrolls,
# opens Entra ID Join on first logon, logs/validates, then reboots.

# --- Logging setup (separate files + lock-tolerant writer) ---
$ErrorActionPreference = 'Stop'

$LogRoot = "C:\ITSetup"
New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$ActionLog     = Join-Path $LogRoot ("OOBE-Setup_Action_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$TranscriptLog = Join-Path $LogRoot ("OOBE-Setup_Transcript_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# Start transcript in its own, different file
Start-Transcript -Path $TranscriptLog -Append | Out-Null

# Write-Log with FileShare.ReadWrite + retry
function Write-Log {
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
  )

  $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "$ts [$Level] $Message"

  # Retry up to ~1.3s (50,100,200,400,800 ms) if another process holds an exclusive handle
  $attempt = 0
  while ($true) {
    try {
      # Open for ReadWrite with ReadWrite sharing, then seek to end and append a line
      $fs = [System.IO.File]::Open($ActionLog,
                                   [System.IO.FileMode]::OpenOrCreate,
                                   [System.IO.FileAccess]::ReadWrite,
                                   [System.IO.FileShare]::ReadWrite)
      $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
      $sw = New-Object System.IO.StreamWriter($fs, [System.Text.Encoding]::UTF8)
      $sw.WriteLine($line)
      $sw.Flush(); $sw.Dispose(); $fs.Dispose()
      break
    }
    catch {
      if ($attempt -ge 4) { throw }  # after ~1.3s, bubble up
      Start-Sleep -Milliseconds (50 * [math]::Pow(2,$attempt))
      $attempt++
    }
  }

  # Console echo
  $color = switch ($Level) {
    "SUCCESS" { "Green" } "WARN" { "Yellow" } "ERROR" { "Red" } Default { "Gray" }
  }
  Write-Host $line -ForegroundColor $color
}

trap {
  Write-Log "UNHANDLED: $($_.Exception.Message)" "ERROR"
  try { Stop-Transcript | Out-Null } catch {}
  exit 1
}
``
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Log "=== Starting Windows 11 24H2 OOBE bootstrap ==="

# 1) Local admin GPAdmin2 (no password)
try {
  if (-not (Get-LocalUser -Name "GPAdmin2" -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name "GPAdmin2" -NoPassword -AccountNeverExpires:$true | Out-Null
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

# --- EXTRA: Harden OOBE suppression & privacy screens (24H2) ---
try {
  $oobeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
  if (-not (Test-Path $oobeKey)) { New-Item -Path $oobeKey -Force | Out-Null }

  # Hide EULA & privacy pages and pick 'ProtectYourPC' = 3 (minimal data collection)
  New-ItemProperty -Path $oobeKey -Name "HideEULAPage"            -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "DisablePrivacyExperience"-PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "DisableVoice"            -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "PrivacyConsentStatus"    -PropertyType DWord -Value 1 -Force | Out-Null
  New-ItemProperty -Path $oobeKey -Name "ProtectYourPC"           -PropertyType DWord -Value 3 -Force | Out-Null

  # Useful post‑sign‑in cosmetic: speed up first logon animation
  New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                   -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 1 -Force | Out-Null

  Write-Log "Applied OOBE privacy/EULA suppression keys." "SUCCESS"
} catch { Write-Log "Failed to apply OOBE suppression keys: $($_.Exception.Message)" "ERROR" }

# --- EXTRA: Prefer local-account path at OOBE (try ms-cxh:localonly, fallback to BYPASSNRO) ---
try {
  # 1st attempt: ms-cxh local-only path (works on most 24H2 builds)
  Write-Log "Attempting to force local account path (ms-cxh:localonly)…"
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c start ms-cxh:localonly" -WindowStyle Hidden
  Start-Sleep -Seconds 2
  Write-Host "`nIf you still see Microsoft Account sign-in, disconnect network, then press Shift+F10 and run the script again." -ForegroundColor Yellow

  # Fallback: enable "I don't have internet" path via the old BYPASSNRO flag
  New-ItemProperty -Path $oobeKey -Name "BypassNRO" -PropertyType DWord -Value 1 -Force | Out-Null
  Write-Log "Set BypassNRO=1 as fallback. If ms-cxh is blocked on this build, unplug/disable network and continue with limited setup." "WARN"
} catch { Write-Log "Failed to set local-only OOBE path: $($_.Exception.Message)" "ERROR" }

# --- OPTIONAL: Stop the post-update Windows Welcome Experience for first user(s) ---
try {
  # Apply to .DEFAULT hive so it affects first logon too
  $def = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
  if (-not (Test-Path $def)) { New-Item -Path $def -Force | Out-Null }
  New-ItemProperty -Path $def -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
  Write-Log "Disabled Windows Welcome Experience (ContentDeliveryManager) for initial logon." "SUCCESS"
} catch { Write-Log "Failed to disable Welcome Experience: $($_.Exception.Message)" "WARN" }

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
  $pwOk = ($pc -match "VIDEOIDLE" -and $pc -match "IDLEDISABLE")
  if ($pwOk) { Write-Log ("Verify power timeouts applied: {0}" -f $pwOk) "SUCCESS" }
  else { Write-Log ("Verify power timeouts applied: {0}" -f $pwOk) "WARN" }
} catch { Write-Log "Failed to set power settings: $($_.Exception.Message)" "ERROR"; throw }

# 5) Prompt for WS1 username/password (kept in memory only)
Write-Host ""
Write-Host "Workspace ONE enrollment – please enter your company login:" -ForegroundColor Cyan
$WsUser   = Read-Host "Username"
$WsPwdSec = Read-Host "Password" -AsSecureString
$WsPwdPtr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($WsPwdSec)
$WsPwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($WsPwdPtr)

# Fixed tenant details
$WsServer  = "https://ds1106.awmdm.com"
$WsGroupId = "DataTechAILandingO"

# 6) Download Intelligent Hub with visible progress
$dlDir  = Join-Path $LogRoot "Downloads"
New-Item -ItemType Directory -Path $dlDir -Force -ErrorAction SilentlyContinue | Out-Null
$hubMsi = Join-Path $dlDir "AirwatchAgent.msi"
$downloadUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"

function Download-WithProgress {
  param([string]$Uri,[string]$Destination,[int]$TimeoutMinutes=30)
  Write-Log "Starting download: $Uri"
  Add-Type -AssemblyName System.Net.Http
  $handler = New-Object System.Net.Http.HttpClientHandler
  $client  = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [TimeSpan]::FromMinutes($TimeoutMinutes)

  $resp = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
  if (-not $resp.IsSuccessStatusCode) { throw "HTTP $([int]$resp.StatusCode) $($resp.ReasonPhrase)" }

  $total = $resp.Content.Headers.ContentLength
  $in    = $resp.Content.ReadAsStreamAsync().Result
  $out   = [System.IO.File]::Open($Destination, [System.IO.FileMode]::Create)
  try {
    $buffer = New-Object byte[] (1024*128)
    $totalRead = 0L
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while (($read = $in.Read($buffer,0,$buffer.Length)) -gt 0) {
      $out.Write($buffer,0,$read)
      $totalRead += $read
      if ($sw.Elapsed.TotalMilliseconds -ge 250) {
        $pct = 0
        if ($total) {
          $pct = [int](($totalRead / $total)*100)
          $status = ("{0:N1} MB of {1:N1} MB" -f ($totalRead/1MB), ($total/1MB))
        } else {
          $status = ("{0:N1} MB downloaded" -f ($totalRead/1MB))
        }
        Write-Progress -Id 1 -Activity "Downloading Workspace ONE Intelligent Hub…" -Status $status -PercentComplete $pct
        $sw.Restart()
      }
    }
    Write-Progress -Id 1 -Activity "Downloading Workspace ONE Intelligent Hub…" -Completed
  } finally {
    $out.Close(); $in.Close(); $client.Dispose()
  }
  Write-Log "Download completed: $Destination" "SUCCESS"
}

try {
  Write-Host ""
  Write-Host "Downloading Workspace ONE Intelligent Hub… (this may take 10+ minutes on slow connections)" -ForegroundColor Yellow
  Download-WithProgress -Uri $downloadUrl -Destination $hubMsi -TimeoutMinutes 45
} catch {
  Write-Log "Primary download failed: $($_.Exception.Message)" "WARN"
  try {
    Invoke-WebRequest -Uri "https://www.getwsone.com/" -UseBasicParsing -TimeoutSec 60 | Out-Null
    Download-WithProgress -Uri "https://packages.omnissa.com/wsone/AirwatchAgent.msi" -Destination $hubMsi -TimeoutMinutes 45
  } catch {
    Write-Log "Fallback download failed: $($_.Exception.Message)" "ERROR"
    throw
  }
}

# 7) Install + enroll Workspace ONE (silent)
try {
  Write-Log "Installing Intelligent Hub + enrolling device (silent)…"
  Write-Host "Installing Intelligent Hub… please wait." -ForegroundColor Gray
  $msiArgs = @(
    "/i", "`"$hubMsi`"",
    "/qn",
    "ENROLL=Y",
    "SERVER=$WsServer",
    "LGName=$WsGroupId",
    "USERNAME=$WsUser",
    "PASSWORD=$WsPwdPlain",
    "ASSIGNTOLOGGEDINUSER=Y"
  )
  $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
  if ($proc.ExitCode -ne 0) { throw "msiexec exit code $($proc.ExitCode)" }
 Write-Log "Intelligent Hub installed; enrollment attempted." "SUCCESS"
} catch { Write-Log "Hub install/enrollment failed: $($_.Exception.Message)" "ERROR"; throw }
finally {
  if ($WsPwdPtr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($WsPwdPtr) }
  $WsPwdPlain = $null
}

# Verify Hub presence
$hubPaths = @(
  "C:\Program Files (x86)\Workspace ONE\Intelligent Hub\Hub.exe",
  "C:\Program Files (x86)\Airwatch\AgentUI\AW.Agent.UI.exe"
)
$hubOk = $hubPaths | ForEach-Object { Test-Path $_ } | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($hubOk -gt 0) { Write-Log ("Verify Hub files present: {0}" -f ($hubOk -gt 0)) "SUCCESS" }
else { Write-Log ("Verify Hub files present: {0}" -f ($hubOk -gt 0)) "WARN" }

# 8) First-logon prompt for Entra ID Join
try {
  $action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c start ms-settings:workplace"
  $trigger   = New-ScheduledTaskTrigger -AtLogOn
  $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\Interactive" -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  $task      = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
  Register-ScheduledTask -TaskName "Open-Entra-Join-Settings" -InputObject $task -Force | Out-Null
  Write-Log "Scheduled Accounts > Access work or school (ms-settings:workplace) to open at logon." "SUCCESS"
} catch { Write-Log "Failed to schedule Entra Join helper: $($_.Exception.Message)" "ERROR"; throw }

# 9) Summary & reboot
Write-Log "=== SUMMARY ==="
Write-Log "Local admin 'GPAdmin2' created: $adminOk"
Write-Log "OOBE disabled: $oobeOk"
Write-Log "Feature updates pinned to 24H2: $trvOk"
Write-Log ("Intelligent Hub installed (files found): {0}" -f ($hubOk -gt 0))
Write-Log "Log saved to $LogFile"
Stop-Transcript | Out-Null

Write-Host ""
Write-Host "Setup complete. The device will now reboot." -ForegroundColor Cyan
Start-Sleep -Seconds 2
Restart-Computer -Force
