<#
.SYNOPSIS
  Installs Workspace ONE Intelligent Hub for Windows, silently enrolls the device,
  locks Windows to 24H2, restarts, and launches Hub UI after reboot.

.NOTES
  - Enrollment credentials are passed to msiexec properties (required by Hub for silent enrollment).
  - Password is intentionally UNMASKED per request (visible as you type).
#>

#--------------------------- Fixed values (per your environment) ---------------------------#
$ServerUrlInput = "https://ds1106.awmdm.com"   # You provided this with https://
$GroupId        = "DataTechAILandingO"         # Your OG Group ID
#------------------------------------------------------------------------------------------#

# Normalize SERVER argument: Hub docs call for DS FQDN; strip protocol if present
$ServerFqdn = ($ServerUrlInput -replace '^https?://','').TrimEnd('/')

# Public Hub MSI (swap to your DS /agents path if you prefer)
$HubMsiUrl = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"

# Ensure we are running elevated
$currUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching with elevation..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo "powershell";
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

# Make TLS sane for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Prompt for username & (unmasked) password
$WsUser = Read-Host "Workspace ONE username"
$WsPass = Read-Host "Workspace ONE password (visible as you type)"

# Prepare working paths
$WorkRoot = Join-Path $env:ProgramData "WS1HubSetup"
$null = New-Item -Path $WorkRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$MsiPath = Join-Path $WorkRoot "AirwatchAgent.msi"
$LogPath = Join-Path $WorkRoot "HubInstall.log"

# Download Hub MSI
try {
    Write-Host "Downloading Workspace ONE Intelligent Hub..."
    Invoke-WebRequest -Uri $HubMsiUrl -OutFile $MsiPath -UseBasicParsing
}
catch {
    Write-Warning "Download failed: $($_.Exception.Message)"
    throw
}

# Build msiexec arguments (order matters; ASSIGNTOLOGGEDINUSER last)
# Wrap values in quotes to handle special characters safely
$msiArgs = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "/L*v", "`"$LogPath`"",
    "ENROLL=Y",
    "SERVER=`"$ServerFqdn`"",
    "LGName=`"$GroupId`"",
    "USERNAME=`"$WsUser`"",
    "PASSWORD=`"$WsPass`"",
    "ASSIGNTOLOGGEDINUSER=Y"
)

Write-Host "Installing Hub & enrolling the device (silent)..."
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -WindowStyle Hidden
if ($proc.ExitCode -ne 0) {
    throw "msiexec returned exit code $($proc.ExitCode). Check $LogPath or MSI logs under %windir%\Temp."
}

# --- Pin Windows to 24H2 (Windows Update for Business TargetReleaseVersion) ---
Write-Host "Configuring Windows Update policy to stay on 24H2..."
$WUKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
New-Item -Path $WUKey -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "ProductVersion" -PropertyType String -Value "Windows 11" -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "TargetReleaseVersion" -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $WUKey -Name "TargetReleaseVersionInfo" -PropertyType String -Value "24H2" -Force | Out-Null

# Optional: refresh policies now
try { gpupdate /target:computer /force | Out-Null } catch {}

# --- Launch Hub UI after reboot (RunOnce + URI) ---
# In Hub 24.10+, 'ws1winhub:' is the new launch URI; older builds used 'vmwinhub:'.
$RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$LaunchCmd = 'powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 10; ' +
             'try { Start-Process ''ws1winhub:'' } catch {}"'
New-ItemProperty -Path $RunOnceKey -Name "LaunchWorkspaceONEHub" -PropertyType String -Value $LaunchCmd -Force | Out-Null

Write-Host "All set. Restarting in 10 seconds..."
Start-Sleep -Seconds 10
Restart-Computer -Force
