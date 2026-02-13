<#
This is a helper for XPO users - JK 790007415 03.02.2026
Functions:
-pin windows to 24h2
-skip oobe windows hello 
-skip oobe location questions 
-install ws1
-enroll ws1 based on user input
-restart, and run ws1 upon first login 
#>

#--------------------------- Hardcoded values  --------------------------------------------#
$ServerUrlInput = "https://ds1106.awmdm.com"
$GroupId        = "DataTechAILandingO"
#------------------------------------------------------------------------------------------#

# Check if user did with https, fix to fqdn
$ServerFqdn = ($ServerUrlInput -replace '^https?://','').TrimEnd('/')

# url for ws1 hub download from official websitre
$HubMsiUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"

# Check for admin 
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
#  This part if for detecting if we're in OOBE and if so, make sure wifi prompted and annoying choices like location share, diagnostic data sharing are disabled and not shown to user
# ISSUE: detection does not work, changed to always asssume oobe <-- musze to sprawdzic pozniej
# =======================================================================

function Test-IsOOBE {
    <#
      this does not work, changed to always assume oobe
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
    # Hide privacy/consent pages, EULA, tailored experiences; ad ID & location off; consumer features off
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
    # Suppress Windows Hello prompts, this will be set up after correct tag in AW is applied and user consent will be done.
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled" 0
    Set-RegistryDword "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "DisablePostLogonProvisioning" 1
    # Re-apply once after first logon to prevent any race with post-logon provisioning
    $RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $reapply = 'powershell -NoProfile -WindowStyle Hidden -Command "New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'' -Force | Out-Null; ' +
               'New-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'' -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null; ' +
               'New-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'' -Name DisablePostLogonProvisioning -Value 1 -PropertyType DWord -Force | Out-Null"'
    New-Item -Path $RunOnceKey -Force | Out-Null
    New-ItemProperty -Path $RunOnceKey -Name "WS1_Reapply_WHfB_Disable" -PropertyType String -Value $reapply -Force | Out-Null
}

function Ensure-OOBENetworkReady {
    try { Start-Service BITS -ErrorAction SilentlyContinue } catch {}

    Write-Host ""
    Write-Host " NETWORK SETUP (OOBE) " -ForegroundColor Yellow
    Write-Host " • We will open the Wi‑Fi selection for you. Connect to your network there." -ForegroundColor White

    # Open the “Show available networks” 
    try { Start-Process "ms-availablenetworks:" -ErrorAction SilentlyContinue } catch {}
   # Test for network <--- need to make it ask for yes, enter key is confusing test user

    Write-Host " • After connecting, return here and press ENTER. We'll verify internet connectivity..." -ForegroundColor White
    while ($true) {
        [void][System.Console]::ReadLine()
        try {
            $ok = (Test-NetConnection -ComputerName "google.com" -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
        } catch { $ok = $false }
        if ($ok) { Write-Host " Internet connectivity verified (google.com:443)." -ForegroundColor Green; break }
        Write-Host " Not online yet. We will reopen the Wi‑Fi picker..." -ForegroundColor Yellow
        try { Start-Process "ms-availablenetworks:" -ErrorAction SilentlyContinue } catch {}
        Write-Host " Connect, then press ENTER to verify again." -ForegroundColor White
    }
}

function Get-GeneratedComputerName {
    param(
        [Parameter(Mandatory=$false)][string]$OhrForSuffix,
        [Parameter(Mandatory=$false)][string]$Prefix = "GNPT"  # temporary hostname prefix
    )
    $ohr = ($OhrForSuffix -replace '[^\d]','')
    $serial = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
    $suffix = if ($ohr) { $ohr.Substring([Math]::Max(0,$ohr.Length-7)) } elseif ($serial) { ($serial -replace '[^\w]','').Substring([Math]::Max(0,([Math]::Min(7,($serial -replace '[^\w]','').Length)))) } else { (Get-Random -Maximum 9999999).ToString() }
    $name = "$Prefix-$suffix"
    $safe = ($name -replace '[^A-Za-z0-9\-]','')
    if ($safe.Length -gt 15) { $safe = $safe.Substring(0,15) }
    return $safe.ToUpper()
}

function Set-ComputerNameIfNeeded {
    param([Parameter(Mandatory=$true)][string]$DesiredName)
    if ($env:COMPUTERNAME -ieq $DesiredName) { return $false }
    try {
        Rename-Computer -NewName $DesiredName -Force -ErrorAction Stop
        Write-Host ""
        Write-Host " Computer rename staged as: $DesiredName" -ForegroundColor Cyan
        Write-Host " " -ForegroundColor Yellow
    } catch { Write-Warning "Rename failed: $($_.Exception.Message)" }
    return $true
}

$InOOBE = Test-IsOOBE
if ($InOOBE) {
    Write-Host ""
    Write-Host " OOBE detected..." -ForegroundColor Yellow
    Set-OOBEPrivacySkip
    Disable-WindowsHelloPrompts   
    Ensure-OOBENetworkReady
    $Desired = Get-GeneratedComputerName
    Set-ComputerNameIfNeeded -DesiredName $Desired | Out-Null
}

# ---------- User Info Banner ----------
$line = ('=' * 78)
Write-Host ""
Write-Host $line -ForegroundColor Cyan
Write-Host " WORKSPACE ONE – WINDOWS ENROLLMENT -- JK Script v2.1" -ForegroundColor Cyan
Write-Host $line -ForegroundColor Cyan
Write-Host " READ BEFORE CONTINUING:" -ForegroundColor Yellow
Write-Host "   • Login = OHR only (digits). Do NOT add any domain." -ForegroundColor White
Write-Host "   • Password is VISIBLE. You can review and adjust before proceeding." -ForegroundColor White
Write-Host "   • Download may take up to ~10 minutes depending on network speed." -ForegroundColor White
Write-Host $line -ForegroundColor Cyan

# -------- OHR & Password (single entry + preview; Enter = proceed) --------
Write-Host ""
$ohr = Read-Host "  Enter your OHR (digits only)"
while ($ohr -notmatch '^\d+$') {
    Write-Host "  OHR must be digits only. Please try again." -ForegroundColor Red
    $ohr = Read-Host "  Enter your OHR (digits only): "
}

Write-Host ""
$WsPass = Read-Host "  Enter Workspace ONE password: "

while ($true) {
    Write-Host ""
    Write-Host "  Review your entries:" -ForegroundColor Yellow
    Write-Host "   • OHR      : $ohr" -ForegroundColor White
    Write-Host "   • Password : $WsPass" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "  Press [Enter] to proceed, or type O (change OHR) / P (change password) / N (abort)"
    if ($choice -eq "" -or $choice -match '^[\r\n]+$') { break }
    elseif ($choice -match '^[Nn]$') { Write-Host " Aborted by user." -ForegroundColor Yellow; exit }
    elseif ($choice -match '^[Oo]$') {
        $ohr = Read-Host "  Re-enter OHR (digits only)"
        while ($ohr -notmatch '^\d+$') {
            Write-Host "  OHR must be digits only. Please try again." -ForegroundColor Red
            $ohr = Read-Host "  Re-enter OHR (digits only)"
        }
    }
    elseif ($choice -match '^[Pp]$') {
        $WsPass = Read-Host "  Re-enter password (VISIBLE as you type)"
    }
    else {
        # Any other input = proceed as well
        break
    }
}

Write-Host ""
Write-Host " Server : $ServerFqdn" -ForegroundColor DarkGray
Write-Host " Group  : $GroupId" -ForegroundColor DarkGray
Write-Host " OHR    : $ohr" -ForegroundColor DarkGray
Write-Host ""

$confirm = Read-Host "  Proceed with installation and enrollment now? (Y/N)"
if ($confirm -notin @('Y','y')) { Write-Host " Aborted by user." -ForegroundColor Yellow; exit }

# Prepare working folder
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WorkRoot = Join-Path $env:ProgramData "WS1HubSetup"
$null = New-Item -Path $WorkRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$MsiPath = Join-Path $WorkRoot "AirwatchAgent.msi"
$LogPath = Join-Path $WorkRoot "HubInstall.log"

# --------- mutiple issues with downloading via Invoke web request, AI wrote the following function > Download: BITS -> curl.exe -> Invoke-WebRequest ----------
function Download-WithBITS {
    param([string]$Url,[string]$Destination,[int]$TimeoutSec = 900)
    Try {
        $job = Start-BitsTransfer -Source $Url -Destination $Destination -Asynchronous -DisplayName "WS1HubDownload" -Priority Foreground
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            Start-Sleep -Seconds 2
            $j = Get-BitsTransfer -AllUsers | Where-Object { $_.Id -eq $job.Id }
            if (-not $j) { break }
            if ($j.BytesTotal -gt 0) {
                $pct = ($j.BytesTransferred / $j.BytesTotal * 100)
                Write-Progress -Activity "Downloading Hub (BITS)" -Status ("{0:N1}% complete" -f $pct) -PercentComplete $pct
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
    } Catch { return $false }
}

function Download-WithCurl {
    param([string]$Url,[string]$Destination)
    try {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (-not $curl) { return $false }
        Write-Host ""
        Write-Host " Downloading with curl.exe ..." -ForegroundColor Yellow
        $args = @("-L", "-f", "--retry", "5", "--retry-delay", "2", "-o", $Destination, $Url)
        $p = Start-Process -FilePath $curl.Source -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        return ($p.ExitCode -eq 0 -and (Test-Path $Destination))
    } catch { return $false }
}

function Download-WithIWR {
    param([string]$Url,[string]$Destination)
    try {
        Write-Host ""
        Write-Host " Downloading with Invoke-WebRequest (fallback) ..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 900
        return (Test-Path $Destination)
    } catch { return $false }
}
# AI end. download works. 
Write-Host ""
Write-Host " Starting Hub download... (may take up to ~10 minutes)" -ForegroundColor Green
$start = Get-Date
$ok = Download-WithBITS -Url $HubMsiUrl -Destination $MsiPath
if (-not $ok) { $ok = Download-WithCurl -Url $HubMsiUrl -Destination $MsiPath }
if (-not $ok) { $ok = Download-WithIWR  -Url $HubMsiUrl -Destination $MsiPath }

if (-not $ok) {
    Write-Host " Download failed via all methods. Please check connectivity or proxy settings." -ForegroundColor Red
    exit 1
}
$elapsed = (Get-Date) - $start
Write-Host (" Download completed in {0:mm\:ss}." -f $elapsed) -ForegroundColor Green

# --------- Install Hub & enroll silently  ----------
$msiArgs = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "/L*v", "`"$LogPath`"",
    "ENROLL=Y",
    "DOWNLOADWSBUNDLE=true",
    "SERVER=`"$ServerFqdn`"",
    "LGName=`"$GroupId`"",
    "USERNAME=`"$ohr`"",           
    "PASSWORD=`"$WsPass`"",
    "ASSIGNTOLOGGEDINUSER=N"       #not sure what it does, if true it also asks for additional signing after enrollment
)

Write-Host ""
Write-Host " Installing Hub & enrolling device (silent)..." -ForegroundColor Green
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
if ($proc.ExitCode -ne 0) {
    Write-Host " Hub installation failed. ExitCode=$($proc.ExitCode). See: $LogPath" -ForegroundColor Red
    exit $proc.ExitCode
}

# --------- Pin Windows to 24H2  ----------
Write-Host ""
Write-Host " Pinning Windows to 24H2 (feature updates)..." -ForegroundColor Green
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
             'try { Start-Process ''vmwinhub:'' } catch {}"' #this line must be removed
New-ItemProperty -Path $RunOnceKey -Name "LaunchWorkspaceONEHub" -PropertyType String -Value $LaunchCmd -Force | Out-Null

Write-Host ""
Write-Host " Setup complete. Restarting computer. " -ForegroundColor Cyan
Start-Sleep -Seconds 10
Restart-Computer -Force
