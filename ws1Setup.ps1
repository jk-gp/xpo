<#
.SYNOPSIS
  Installs Workspace ONE Intelligent Hub for Windows, silently enrolls the device to your DS/OG,
  pins Windows to 24H2 (feature updates), restarts, and launches Hub UI after reboot.

.USER MESSAGE (VISIBLE, IMPORTANT)
  • Username must be entered as: YOUR_OHR@genpact.com
  • Password is NOT masked (visible). Double-check before pressing Enter.
  • Download can take up to ~10 minutes depending on your connection.

.NOTES
  - SERVER and LGName are preconfigured for your environment.
  - Enrollment credentials are passed to msiexec properties (plain text), as required by Hub silent enrollment.
#>

#--------------------------- Fixed values (per your environment) ---------------------------#
$ServerUrlInput = "https://ds1106.awmdm.com"   # Provided with protocol; Hub SERVER expects FQDN
$GroupId        = "DataTechAILandingO"         # Your OG Group ID
#------------------------------------------------------------------------------------------#

# Normalize SERVER argument: Hub docs call for DS FQDN; strip protocol if present
$ServerFqdn = ($ServerUrlInput -replace '^https?://','').TrimEnd('/')

# Preferred Hub MSI source (swap to your DS /agents path if desired)
$HubMsiUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"

# Ensure elevation
$currUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching with elevation..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo "powershell";
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

# =========================
# OOBE Helper Functions
# =========================

function Test-IsOOBE {
    try {
        $s = Get-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -ErrorAction Stop
        return (($s.OOBEInProgress -eq 1) -or ($s.SystemSetupInProgress -eq 1))
    } catch { return $false }
}

function Set-OOBEPrivacySkip {
    <#
      Hides privacy/consent pages and sets quiet defaults.
      Keys reflect widely-used guidance to skip OOBE privacy questions (24H2+ compatible).
    #>
    $paths = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" = @{ "DisablePrivacyExperience" = 1 }  # Don't launch privacy settings
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" = @{ 
            "DisableVoice" = 1; "HideEULAPage" = 1; "PrivacyConsentStatus" = 1; "ProtectYourPC" = 3
        }
        # Turn off consumer features/suggestions (no extra apps/recommendations)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" = @{ "DisableWindowsConsumerFeatures" = 1; "DisableTailoredExperiencesWithDiagnosticData" = 1 }
        # Turn off advertising ID
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" = @{ "DisabledByGroupPolicy" = 1 }
        # Turn off device/location at machine policy (machine-level policy hides the OOBE toggle)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" = @{ "DisableLocation" = 1; "DisableLocationScripting" = 1 }
    }
    foreach ($k in $paths.Keys) {
        New-Item -Path $k -Force | Out-Null
        foreach ($n in $paths[$k].Keys) {
            New-ItemProperty -Path $k -Name $n -Value $paths[$k][$n] -PropertyType DWord -Force | Out-Null
        }
    }
}

function Disable-WindowsHelloPrompts {
    <#
      Suppresses Windows Hello for Business enrollment during/after OOBE.
      You can re-enable WHfB later with Intune/UEM when ready.
    #>
    $pfw = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    New-Item -Path $pfw -Force | Out-Null
    # Completely disable WHfB and also disable the "post-logon provisioning" nag if enabled elsewhere
    New-ItemProperty -Path $pfw -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $pfw -Name "DisablePostLogonProvisioning" -Value 1 -PropertyType DWord -Force | Out-Null
}

function Ensure-OOBENetworkReady {
    # Start BITS (resumable download engine) just in case it's not started yet
    try { Start-Service BITS -ErrorAction SilentlyContinue } catch {}
    Write-Host "Ensure the device is connected to the network (Ethernet recommended). Press ENTER to continue..." -ForegroundColor Yellow
    [void][System.Console]::ReadLine()
    # Quick internet reachability check (HEAD)
    for ($i=1; $i -le 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "https://packages.omnissa.com" -Method Head -TimeoutSec 5
            if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { return $true }
        } catch {}
        Start-Sleep -Seconds 2
    }
    return $false
}

function Get-GeneratedComputerName {
    param(
        [Parameter(Mandatory=$false)][string]$UserInputOhrOrUpn,
        [Parameter(Mandatory=$false)][string]$Prefix = "GNPT"  # keep short to stay < 15 chars
    )
    # Try to extract OHR digits if user typed OHR or UPN (e.g., 1234567 or 1234567@genpact.com)
    $ohr = ($UserInputOhrOrUpn -replace '@.*$','') -replace '[^\d]',''
    # Fallback to last 7 of BIOS serial if no OHR found
    $serial = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
    $suffix = if ($ohr) { $ohr.Substring([Math]::Max(0,$ohr.Length-7)) } elseif ($serial) { ($serial -replace '[^\w]','').Substring([Math]::Max(0,([Math]::Min(7,($serial -replace '[^\w]','').Length)))) } else { (Get-Random -Maximum 9999999).ToString() }
    $name = "$Prefix-$suffix"
    # NetBIOS-safe, <= 15 chars
    $safe = ($name -replace '[^A-Za-z0-9\-]','')
    if ($safe.Length -gt 15) { $safe = $safe.Substring(0,15) }
    return $safe.ToUpper()
}

function Set-ComputerNameIfNeeded {
    param(
        [Parameter(Mandatory=$true)][string]$DesiredName,
        [Parameter(Mandatory=$true)][string]$ResumeScriptFullPath
    )
    if ($env:COMPUTERNAME -ieq $DesiredName) { return $false } # no rename needed
    try {
        Rename-Computer -NewName $DesiredName -Force -ErrorAction Stop
        # Persist resume of the main script after reboot
        $runOnce = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        $cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$ResumeScriptFullPath`" -ResumeAfterRename"
        New-ItemProperty -Path $runOnce -Name "WS1Resume" -Value $cmd -PropertyType String -Force | Out-Null
        Write-Host "Computer will reboot now to apply name: $DesiredName" -ForegroundColor Cyan
        Start-Sleep -Seconds 3
        Restart-Computer -Force
    } catch {
        Write-Warning "Rename failed: $($_.Exception.Message)"
    }
    return $true
}

# --------- OOBE entry point ----------
# $InOOBE = Test-IsOOBE //bypass test
$InOOBE = $true
if ($InOOBE) {
    Write-Host "OOBE detected: Applying privacy, Windows Hello, and consumer-experience suppressions..." -ForegroundColor Yellow
    Set-OOBEPrivacySkip      # privacy + consumer features + ad ID + location
    Disable-WindowsHelloPrompts
    if (-not (Ensure-OOBENetworkReady)) {
        Write-Host "No internet connectivity detected. Please connect and rerun." -ForegroundColor Red
        exit 2
    }
    # Auto-generate a compliant computer name BEFORE enrollment
    # (Use your soon-to-be-entered OHR/UPN if present in the current session variables; safe fallback otherwise)
    $CandidateUser = $WsUser  # will be $null on first pass; safe fallback occurs in function
    $Desired = Get-GeneratedComputerName -UserInputOhrOrUpn $CandidateUser
    # Copy this script to a stable path for RunOnce resume (so we can safely reboot after rename)
    $persist = Join-Path $env:ProgramData "WS1HubSetup\Install-WS1Hub-Enroll-24H2.ps1"
    try {
        New-Item -Path (Split-Path $persist) -ItemType Directory -Force | Out-Null
        if ($PSCommandPath) { Copy-Item -Path $PSCommandPath -Destination $persist -Force }
    } catch {}
    Set-ComputerNameIfNeeded -DesiredName $Desired -ResumeScriptFullPath $persist | Out-Null
}
Write-Host "OOBE Helper END"
# =========================
# End OOBE Helper
# =========================


# ---------- User Info Banner ----------
$line = ('=' * 78)
Write-Host $line -ForegroundColor Cyan
Write-Host " WORKSPACE ONE – WINDOWS ENROLLMENT" -ForegroundColor Cyan
Write-Host $line -ForegroundColor Cyan
Write-Host "READ BEFORE CONTINUING:" -ForegroundColor Yellow
Write-Host "  • Username format: YOUR_OHR@genpact.com" -ForegroundColor White
Write-Host "  • Password is NOT masked (visible). CAREFULLY verify before pressing Enter." -ForegroundColor White
Write-Host "  • Download may take up to ~10 minutes depending on your network speed." -ForegroundColor White
Write-Host $line -ForegroundColor Cyan

# Prompt for username (enforce @genpact.com) & an UNMASKED password
function Prompt-ForUsername {
    while ($true) {
        $u = Read-Host "Enter Workspace ONE username (YOUR_OHR@genpact.com)"
           }
}
$WsUser = Read-Host "Enter Workspace ONE username (Type in ONLY your OHR - just numbers, without genpact.com)"
$WsPass = Read-Host "Enter Workspace ONE password (VISIBLE as you type)"

Write-Host ""
Write-Host "Server: $ServerFqdn" -ForegroundColor DarkGray
Write-Host "Group : $GroupId" -ForegroundColor DarkGray
Write-Host "User  : $WsUser" -ForegroundColor DarkGray
Write-Host ""

# Optional one-time confirmation (user-facing safety for visible password)
$confirm = Read-Host "Proceed with installation and enrollment now? (Y/N)"
if ($confirm -notin @('Y','y')) { Write-Host "Aborted by user." -ForegroundColor Yellow; exit }

# Prepare working folder
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WorkRoot = Join-Path $env:ProgramData "WS1HubSetup"
$null = New-Item -Path $WorkRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$MsiPath = Join-Path $WorkRoot "AirwatchAgent.msi"
$LogPath = Join-Path $WorkRoot "HubInstall.log"

# --------- Robust download: BITS -> curl.exe -> Invoke-WebRequest ----------
function Download-WithBITS {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination,
        [int]$TimeoutSec = 900 # 15 minutes safety
    )
    Try {
        $job = Start-BitsTransfer -Source $Url -Destination $Destination -Asynchronous -DisplayName "WS1HubDownload" -Priority Foreground
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            Start-Sleep -Seconds 2
            $j = Get-BitsTransfer -AllUsers | Where-Object { $_.Id -eq $job.Id }
            if (-not $j) { break }
            if ($j.BytesTotal -gt 0) {
                $pct = [int](($j.BytesTransferred / $j.BytesTotal) * 100)
                Write-Progress -Activity "Downloading Hub (BITS)" -Status "$pct% complete" -PercentComplete $pct
            } else {
                Write-Progress -Activity "Downloading Hub (BITS)" -Status "Starting..." -PercentComplete 0
            }
            if ($j.JobState -eq 'Transferred') {
                Complete-BitsTransfer -BitsJob $j
                Write-Progress -Activity "Downloading Hub (BITS)" -Completed
                return $true
            } elseif ($j.JobState -eq 'Error' -or $sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
                Remove-BitsTransfer -BitsJob $j -Confirm:$false -ErrorAction SilentlyContinue
                return $false
            }
        }
        return (Test-Path $Destination)
    } Catch {
        return $false
    }
}

function Download-WithCurl {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    try {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (-not $curl) { return $false }
        Write-Host "Downloading with curl.exe..." -ForegroundColor Yellow
        # -L follow redirects, -f fail on HTTP errors, --retry for transient cases
        $args = @("-L", "-f", "--retry", "5", "--retry-delay", "2", "-o", $Destination, $Url)
        $p = Start-Process -FilePath $curl.Source -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        return ($p.ExitCode -eq 0 -and (Test-Path $Destination))
    } catch {
        return $false
    }
}

function Download-WithIWR {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    try {
        Write-Host "Downloading with Invoke-WebRequest (fallback)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 900
        return (Test-Path $Destination)
    } catch {
        return $false
    }
}

Write-Host "Starting Hub download... (may take up to ~10 minutes)" -ForegroundColor Green
$start = Get-Date
$ok = Download-WithBITS -Url $HubMsiUrl -Destination $MsiPath
if (-not $ok) { $ok = Download-WithCurl -Url $HubMsiUrl -Destination $MsiPath }
if (-not $ok) { $ok = Download-WithIWR  -Url $HubMsiUrl -Destination $MsiPath }

if (-not $ok) {
    Write-Host "Download failed via all methods. Please check connectivity or proxy settings." -ForegroundColor Red
    exit 1
}
$elapsed = (Get-Date) - $start
Write-Host ("Download completed in {0:mm\:ss}." -f $elapsed) -ForegroundColor Green

# --------- Install Hub & enroll silently (order of MSI properties matters) ----------
$msiArgs = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "/L*v", "`"$LogPath`"",
    "ENROLL=Y",
    "DOWNLOADWSBUNDLE=true",
    "SERVER=`"$ServerFqdn`"",
    "LGNAME=`"$GroupId`"",
    "USERNAME=`"$WsUser`"",
    "PASSWORD=`"$WsPass`"",
    "ASSIGNTOLOGGEDINUSER=N"
)

Write-Host "Installing Hub & enrolling device (silent)..." -ForegroundColor Green
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
if ($proc.ExitCode -ne 0) {
    Write-Host "Hub installation failed. ExitCode=$($proc.ExitCode). See: $LogPath" -ForegroundColor Red
    exit $proc.ExitCode
}

# --------- Pin Windows to 24H2 (Windows Update for Business policy) ----------
Write-Host "Pinning Windows to 24H2 (feature updates)..." -ForegroundColor Green
$WUKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
New-Item -Path $WUKey -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "ProductVersion" -PropertyType String -Value "Windows 11" -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "TargetReleaseVersion" -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "TargetReleaseVersionInfo" -PropertyType String -Value "24H2" -Force | Out-Null
try { gpupdate /target:computer /force | Out-Null } catch {}

# --------- Ensure Hub UI opens once after reboot ----------
$RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$LaunchCmd = 'powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 10; ' +
             'try { Start-Process ''ws1winhub:'' } catch {}; ' +
             'try { Start-Process ''vmwinhub:'' } catch {}"'
New-ItemProperty -Path $RunOnceKey -Name "LaunchWorkspaceONEHub" -PropertyType String -Value $LaunchCmd -Force | Out-Null

Write-Host "Setup complete. The device will restart in 10 seconds..." -ForegroundColor Cyan
Start-Sleep -Seconds 10
Restart-Computer -Force
