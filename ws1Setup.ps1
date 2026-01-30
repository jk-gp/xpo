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
        if ($u -match '^[^@]+@genpact\.com$') { return $u }
        Write-Host "Invalid format. Please use YOUR_OHR@genpact.com" -ForegroundColor Red
    }
}
$WsUser = Prompt-ForUsername
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
    "ASSIGNTOLOGGEDINUSER=Y"
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
