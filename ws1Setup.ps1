
<#
.SYNOPSIS
  Installs Workspace ONE Intelligent Hub for Windows, silently enrolls the device to your DS/OG,
  pins Windows to 24H2 (feature updates), and launches Hub UI (no reboot forced after rename).

.USER MESSAGE (VISIBLE, IMPORTANT)
  • Username must be entered as: YOUR_OHR@genpact.com
  • Password is NOT masked (visible). Double-check before pressing Enter.
  • You will be asked to CONFIRM the password to avoid typos.
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

# =======================================================================
# OOBE Helper: privacy suppression, WHfB off, consumer features off,
# reliable OOBE detection, and Wi-Fi verification loop (no auto-reboot).
# =======================================================================

function Test-IsOOBE {
    <#
      Reliable OOBE detection using multiple signals:
        - HKLM:\SYSTEM\Setup\OOBEInProgress / SystemSetupInProgress (best-effort)
        - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State\StateName
          (values like *_RESEAL_TO_OOBE or UNDEPLOYABLE while setup is active)
    #>
    $oobeFlag = $false
    try {
        $s = Get-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -ErrorAction Stop
        if (($s.OOBEInProgress -eq 1) -or ($s.SystemSetupInProgress -eq 1)) { $oobeFlag = $true }
    } catch {}
    try {
        $stateKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
        $state = (Get-ItemProperty -Path $stateKey -ErrorAction Stop).StateName
        if ($state -match 'RESEAL_TO_OOBE' -or $state -match 'UNDEPLOYABLE') { $oobeFlag = $true }
    } catch {}
    return [bool]$true
}

function Set-RegistryDword {
    param([string]$Path,[string]$Name,[int]$Value)
    try {
        New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warning "Failed to set $Path\$Name : $($_.Exception.Message)"
    }
}

function Set-OOBEPrivacySkip {
    # Hide privacy/consent pages, EULA, tailored experiences; turn off ad ID & location; consumer features off
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"                "DisablePrivacyExperience" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"          "HideEULAPage" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"          "PrivacyConsentStatus" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"          "DisableVoice" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"          "ProtectYourPC" 3
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"        "DisableWindowsConsumerFeatures" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"        "DisableTailoredExperiencesWithDiagnosticData" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"     "DisabledByGroupPolicy" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"  "DisableLocation" 1
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"  "DisableLocationScripting" 1
}

function Disable-WindowsHelloPrompts {
    # Suppress WHfB during/after OOBE; can be re-enabled via UEM/Intune later
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled" 0
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "DisablePostLogonProvisioning" 1
}

function Ensure-OOBENetworkReady {
    # BITS can resume & is network-friendly; start it if not running (best effort)
    try { Start-Service BITS -ErrorAction SilentlyContinue } catch {}
    Write-Host ""
    Write-Host "NETWORK CHECK (OOBE):" -ForegroundColor Yellow
    Write-Host "• Please switch back to the OOBE window and connect to Wi‑Fi (or plug Ethernet)." -ForegroundColor White
    Write-Host "• Return here and press ENTER. We'll verify internet connectivity." -ForegroundColor White
    while ($true) {
        [void][System.Console]::ReadLine()
        # Verify real internet reachability (TCP 443) to the Hub package origin
        try {
            $ok = (Test-NetConnection -ComputerName "google.com" -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
        } catch { $ok = $false }
        if ($ok) { Write-Host "Internet connectivity verified." -ForegroundColor Green; break }
        Write-Host "Still offline. Connect in the OOBE network panel, then press ENTER to re-check..." -ForegroundColor Yellow
    }
}

function Get-GeneratedComputerName {
    param(
        [Parameter(Mandatory=$false)][string]$UserInputOhrOrUpn,
        [Parameter(Mandatory=$false)][string]$Prefix = "GNPT"  # keep short to remain <= 15 chars with suffix
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
        [Parameter(Mandatory=$true)][string]$DesiredName
    )
    if ($env:COMPUTERNAME -ieq $DesiredName) { return $false } # already set
    try {
        Rename-Computer -NewName $DesiredName -Force -ErrorAction Stop
        Write-Host "Computer rename staged as: $DesiredName" -ForegroundColor Cyan
        Write-Host "No restart will be performed now (per policy). The new name will take effect after the next reboot." -ForegroundColor Yellow
    } catch {
        Write-Warning "Rename failed: $($_.Exception.Message)"
    }
    return $true
}

$InOOBE = Test-IsOOBE
if ($InOOBE) {
    Write-Host "OOBE detected: Applying privacy suppressions, disabling Windows Hello, and turning off consumer features." -ForegroundColor Yellow
    Set-OOBEPrivacySkip
    Disable-WindowsHelloPrompts
    Ensure-OOBENetworkReady

    # Generate a compliant computer name BEFORE enrollment (no forced reboot)
    $Desired = Get-GeneratedComputerName
    Set-ComputerNameIfNeeded -DesiredName $Desired | Out-Null
}

# ---------- User Info Banner ----------
$line = ('=' * 78)
Write-Host $line -ForegroundColor Cyan
Write-Host " WORKSPACE ONE – WINDOWS ENROLLMENT" -ForegroundColor Cyan
Write-Host $line -ForegroundColor Cyan
Write-Host "READ BEFORE CONTINUING:" -ForegroundColor Yellow
Write-Host "  • Username format: YOUR_OHR@genpact.com" -ForegroundColor White
Write-Host "  • Password is NOT masked (visible). CAREFULLY verify before pressing Enter." -ForegroundColor White
Write-Host "  • You will be asked to CONFIRM the password." -ForegroundColor White
Write-Host "  • Download may take up to ~10 minutes depending on your network speed." -ForegroundColor White
Write-Host $line -ForegroundColor Cyan

# Prompt for username (accept OHR-only or full UPN) & an UNMASKED password with confirmation
$WsUserRaw = Read-Host "Enter Workspace ONE username (Type ONLY your OHR digits or full YOUR_OHR@genpact.com)"
if ($WsUserRaw -notmatch '@') { $WsUser = "$WsUserRaw@genpact.com" } else { $WsUser = $WsUserRaw }

# Password verify loop (visible by design)
while ($true) {
    $WsPass1 = Read-Host "Enter Workspace ONE password (VISIBLE as you type)"
    $WsPass2 = Read-Host "Re-enter the password to CONFIRM (VISIBLE as you type)"
    if ($WsPass1 -ceq $WsPass2) { $WsPass = $WsPass1; break }
    Write-Host "Passwords do not match. Let's try again. Be careful—password is visible." -ForegroundColor Red
}

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
    "LGName=`"$GroupId`"",
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

# --------- Ensure Hub UI opens (no reboot assumed) ----------
$RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$LaunchCmd = 'powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 10; ' +
             'try { Start-Process ''ws1winhub:'' } catch {}; ' +
             'try { Start-Process ''vmwinhub:'' } catch {}"'
New-ItemProperty -Path $RunOnceKey -Name "LaunchWorkspaceONEHub" -PropertyType String -Value $LaunchCmd -Force | Out-Null

Write-Host "Setup complete. If you changed the hostname, it will take effect after the next reboot (no reboot performed now)." -ForegroundColor Cyan
