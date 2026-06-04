<#
.SYNOPSIS
    Administrator malware cleanup for indicators found by Scan-SuspiciousActivity.ps1.

.DESCRIPTION
    Targets the specific indicators of compromise found in the scan reports,
    assuming administrator rights are available. It handles both user-level and
    machine-wide cleanup:

      * Stop suspicious processes.
      * Remove HKCU and HKLM Run/RunOnce persistence.
      * Repair HKCU Winlogon Shell hijacks.
      * Quarantine suspicious Startup-folder files and known malware folders.
      * Stop and delete malicious Windows services.
      * Remove Image File Execution Options debugger hijacks.
      * Repair malicious HOSTS-file redirects.
      * Re-enable Windows Firewall.
      * Update Microsoft Defender and start a scan.

    Safety model:
      * PREVIEW BY DEFAULT. Nothing is changed unless you pass -Execute.
      * QUARANTINE, NOT DELETE. Files are moved to a quarantine folder in
        Documents with a manifest so they can be restored if needed.
      * WHITELIST RESPECTED. Whitelisted items, and anything referencing them,
        are never killed, removed, or quarantined.

.PARAMETER Execute
    Actually perform the cleanup. Without this switch the script only previews.

.PARAMETER Force
    Skip per-item confirmation prompts when used with -Execute.

.PARAMETER OfflineScan
    Run Microsoft Defender Offline scan at the end. This reboots the PC and
    scans before Windows loads. Off by default.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Clean-SuspiciousActivity.ps1
        Preview only.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Clean-SuspiciousActivity.ps1 -Execute -Force
        Perform cleanup with confirmations skipped.

.NOTES
    This is first aid, not a guaranteed cure. For info-stealer infections,
    change important passwords from a different clean device and consider a
    full Windows reinstall.
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$Force,
    [switch]$OfflineScan
)

# ===========================================================================
# Administrator check
# ===========================================================================
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as administrator. Requesting elevation..." -ForegroundColor Yellow
    $argList = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', "`"$PSCommandPath`"")
    if ($Execute)     { $argList += '-Execute' }
    if ($Force)       { $argList += '-Force' }
    if ($OfflineScan) { $argList += '-OfflineScan' }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    }
    catch {
        Write-Host "Elevation was cancelled or failed. Run this script from an elevated PowerShell window." -ForegroundColor Red
    }
    return
}

# ===========================================================================
# Whitelist - never touched
# ===========================================================================
$Whitelist = @('ovd_cfa5eebc5ee7.exe', 'pureheh', 'quake3')

function Test-Whitelisted {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $t = $Text.ToLowerInvariant()
    foreach ($w in $Whitelist) {
        if ($t.Contains($w.ToLowerInvariant())) { return $true }
    }
    return $false
}

# ===========================================================================
# Known-bad indicators
# ===========================================================================
$BadProcessNames = @(
    'start.exe', 'sys service.exe', 'spoolsvc.exe', 'fleetcore.exe',
    'xeprinter.exe', '4c6f0457.exe', 'windowsruntime.exe'
)

$BadRunValueNames = @(
    'DesktopAds', 'WindowsUpdate', 'FleetCore', 'Xerox Print Service'
)

$GoodRunValueNames = @(
    'OneDrive', 'com.squirrel.Teams.Teams', 'OfficeSyncProcess',
    'OfficeClickToRun', 'MicrosoftEdgeAutoLaunch', 'SecurityHealth'
)

$BadStartupFiles = @(
    'start.exe', 'EcoOptimize360X.lnk', 'FileSplitterTool30.lnk',
    'HoloCraft.url', 'SPDriverInstall.lnk'
)

$BadServiceNames = @(
    'AnyDesk', 'UltraViewService', 'UltraViewer'
)

$ReviewServiceNames = @('RvControlSvc')

$BadPathPatterns = @(
    '\\appdata\\local\\temp\\',
    '\\appdata\\roaming\\microsoft\\upd_[0-9]+\.exe',
    '\\appdata\\roaming\\fleetcore\\',
    '\\appdata\\roaming\\microsoft\\devicesync\\',
    '\\programdata\\chrome1\d',
    '\\program files\\system services\\',
    '\\program files\\kmspico\\',
    '\\program files \(x86\)\\anydesk\\',
    '\\program files \(x86\)\\ultraviewer\\',
    '\\westlaw classic db exporter\\xeprinter\.exe',
    '\\temp\\violent\\',
    '\\windowsruntime\.exe$',
    '^[a-f0-9]{8}\.exe$'
)

$BadHostNames = @(
    'avast', 'totalav', 'scanguard', 'totaladblock', 'pcprotect', 'mcafee',
    'bitdefender', 'norton', 'avg', 'malwarebytes', 'pandasecurity',
    'surfshark', 'avira', 'eset', 'zillya', 'kaspersky', 'dpbolvw',
    'sophos', 'adaware', 'ahnlab', 'bullguard', 'clamav', 'drweb',
    'emsisoft', 'f-secure', 'zonealarm', 'trendmicro', 'ccleaner',
    'virustotal', 'bmt-pro'
)

$Roaming = $env:APPDATA
$Local = $env:LOCALAPPDATA
$Temp = $env:TEMP
$StartupFolder = [Environment]::GetFolderPath('Startup')

$BadPathsToQuarantine = @(
    (Join-Path $Temp 'violent'),
    (Join-Path $Roaming 'FleetCore'),
    (Join-Path $StartupFolder 'start.exe'),
    'C:\Program Files\System Services',
    'C:\Program Files\KMSpico',
    'C:\ProgramData\Chrome141',
    'C:\ProgramData\start.cmd',
    'C:\Program Files (x86)\AnyDesk',
    'C:\Program Files (x86)\UltraViewer'
)

$BadTaskNames = @('spoolsvc')

# ===========================================================================
# Setup: log + quarantine folder in Documents
# ===========================================================================
$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$docs = [Environment]::GetFolderPath('MyDocuments')
if (-not $docs -or -not (Test-Path $docs)) { $docs = $env:USERPROFILE }

$QuarantineDir = Join-Path $docs ("Malware_Quarantine_ADMIN_{0}" -f $timestamp)
$LogPath = Join-Path $docs ("CleanupReport_ADMIN_{0}.txt" -f $timestamp)
$ManifestPath = Join-Path $QuarantineDir 'QUARANTINE_MANIFEST.txt'

$script:Actions = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Message = '')
    Add-Content -Path $LogPath -Value $Message -Encoding UTF8
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log ('=' * 74)
    Write-Log ("  {0}" -f $Title)
    Write-Log ('=' * 74)
}

function Record {
    param([string]$Message)
    $script:Actions.Add($Message)
    Write-Log ("  [ACTION] {0}" -f $Message)
}

function Warn {
    param([string]$Message)
    $script:Warnings.Add($Message)
    Write-Log ("  [WARN] {0}" -f $Message)
}

function Confirm-Step {
    param([string]$Prompt)
    if (-not $Execute) { return $false }
    if ($Force) { return $true }
    return ((Read-Host ("{0} [y/N]" -f $Prompt)) -match '^(y|yes)$')
}

function Ensure-Quarantine {
    if ($Execute -and -not (Test-Path $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
        Add-Content -Path $ManifestPath -Value "QUARANTINE MANIFEST - ADMIN ($timestamp)" -Encoding UTF8
        Add-Content -Path $ManifestPath -Value "Original location  ==>  quarantined name" -Encoding UTF8
        Add-Content -Path $ManifestPath -Value ('-' * 60) -Encoding UTF8
    }
}

function Quarantine-Path {
    param([string]$Path)
    if (-not $Path) { return }
    if (Test-Whitelisted $Path) {
        Write-Log ("  [SKIP - whitelisted] {0}" -f $Path)
        return
    }
    if (-not (Test-Path $Path)) { return }
    if (-not $Execute) {
        Write-Log ("  [WOULD QUARANTINE] {0}" -f $Path)
        return
    }

    Ensure-Quarantine
    $leaf = Split-Path $Path -Leaf
    $dest = Join-Path $QuarantineDir ("{0}__{1}" -f $leaf, ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    try {
        Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        Add-Content -Path $ManifestPath -Value ("{0}  ==>  {1}" -f $Path, (Split-Path $dest -Leaf)) -Encoding UTF8
        Record ("Quarantined: {0}" -f $Path)
    }
    catch {
        try {
            Rename-Item -LiteralPath $Path -NewName ((Split-Path $Path -Leaf) + '.QUARANTINED') -Force -ErrorAction Stop
            Record ("Locked; renamed to disable: {0}.QUARANTINED" -f $Path)
        }
        catch {
            Warn ("Could not quarantine or rename {0}: {1}" -f $Path, $_.Exception.Message)
        }
    }
}

function Get-ServiceBinaryPath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return '' }
    if ($PathName -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($PathName -match '^\s*(\S+\.exe)') { return $Matches[1] }
    return $PathName
}

function Test-BadPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $lp = $Path.ToLowerInvariant()
    foreach ($pat in $BadPathPatterns) {
        if ($lp -match $pat) { return $true }
    }
    return $false
}

function Remove-BadRunValues {
    param(
        [string[]]$Keys,
        [string]$ScopeName
    )

    foreach ($k in $Keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $vName = $_.Name
            $vData = [string]$_.Value
            if ($GoodRunValueNames -contains $vName) { return }
            if (Test-Whitelisted ("{0} {1}" -f $vName, $vData)) { return }

            $bad = $false
            if ($BadRunValueNames -contains $vName) { $bad = $true }
            if (Test-BadPath $vData) { $bad = $true }
            if ($vName -match '^[a-f0-9]{8,}\.exe$') { $bad = $true }
            if (-not $bad) { return }

            if (-not $Execute) {
                Write-Log ("  [WOULD REMOVE] {0}\{1} = {2}" -f $k, $vName, $vData)
                return
            }
            if (Confirm-Step ("Remove {0} Run value '{1}'?" -f $ScopeName, $vName)) {
                try {
                    Add-Content -Path $LogPath -Value ("    (removed value) {0}\{1} = {2}" -f $k, $vName, $vData) -Encoding UTF8
                    Remove-ItemProperty -Path $k -Name $vName -Force -ErrorAction Stop
                    Record ("Removed {0} Run value: {1}" -f $ScopeName, $vName)
                }
                catch {
                    Warn ("Could not remove {0}\{1}: {2}" -f $k, $vName, $_.Exception.Message)
                }
            }
        }
    }
}

# ===========================================================================
# Header
# ===========================================================================
Write-Log "MALWARE CLEANUP - ADMIN"
Write-Log ("Generated : {0}" -f (Get-Date))
Write-Log ("Computer  : {0}" -f $env:COMPUTERNAME)
Write-Log ("User      : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Log ("Whitelist : {0}  (never touched)" -f ($Whitelist -join ', '))
if ($Execute) {
    Write-Log ("MODE      : EXECUTE - quarantine folder: {0}" -f $QuarantineDir)
}
else {
    Write-Log "MODE      : PREVIEW ONLY - nothing will be changed."
    Write-Log "            Re-run with -Execute to actually clean."
}

# ===========================================================================
# 1. Stop malicious processes
# ===========================================================================
Write-Section "1. Stop malicious processes"
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$matchedProcess = $false
foreach ($p in $procs) {
    $name = ($p.Name | ForEach-Object { $_.ToLowerInvariant() })
    $path = [string]$p.ExecutablePath
    if (Test-Whitelisted ("{0} {1}" -f $name, $path)) { continue }

    $isBad = $false
    if ($BadProcessNames -contains $name) { $isBad = $true }
    if (Test-BadPath $path) { $isBad = $true }
    if (-not $isBad) { continue }

    $matchedProcess = $true
    if (-not $Execute) {
        Write-Log ("  [WOULD KILL] PID {0} {1} ({2})" -f $p.ProcessId, $p.Name, $path)
        continue
    }
    if (Confirm-Step ("Kill PID {0} {1}?" -f $p.ProcessId, $p.Name)) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            Record ("Killed PID {0} {1}" -f $p.ProcessId, $p.Name)
        }
        catch {
            Warn ("Could not kill PID {0} {1}: {2}" -f $p.ProcessId, $p.Name, $_.Exception.Message)
        }
    }
}
if (-not $matchedProcess) { Write-Log "  (no matching malicious processes currently running)" }

# ===========================================================================
# 2. Remove HKCU / HKLM Run persistence
# ===========================================================================
Write-Section "2. Remove malicious Run/RunOnce entries"
Remove-BadRunValues -ScopeName 'HKCU' -Keys @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
Remove-BadRunValues -ScopeName 'HKLM' -Keys @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)

# ===========================================================================
# 3. Repair Winlogon Shell
# ===========================================================================
Write-Section "3. Repair HKCU Winlogon Shell hijack"
$wl = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $wl) {
    $shell = (Get-ItemProperty $wl -ErrorAction SilentlyContinue).Shell
    if ($shell -and $shell -notmatch '^(?i)\s*explorer\.exe\s*,?\s*$') {
        if (Test-Whitelisted $shell) {
            Write-Log "  [SKIP - whitelisted] Winlogon Shell references whitelisted file"
        }
        elseif (-not $Execute) {
            Write-Log ("  [WOULD RESET] Winlogon Shell '{0}' -> 'explorer.exe'" -f $shell)
        }
        elseif (Confirm-Step "Reset Winlogon Shell to explorer.exe?") {
            try {
                Add-Content -Path $LogPath -Value ("    (old Shell value) {0}" -f $shell) -Encoding UTF8
                Set-ItemProperty -Path $wl -Name 'Shell' -Value 'explorer.exe' -ErrorAction Stop
                Record "Reset Winlogon Shell to explorer.exe"
            }
            catch {
                Warn ("Could not reset Winlogon Shell: {0}" -f $_.Exception.Message)
            }
        }
    }
    else {
        Write-Log "  (Winlogon Shell already normal or not set)"
    }
}

# ===========================================================================
# 4. Clean Startup folder
# ===========================================================================
Write-Section "4. Clean Startup folder"
if ($StartupFolder -and (Test-Path $StartupFolder)) {
    Get-ChildItem $StartupFolder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($BadStartupFiles -contains $_.Name) {
            Quarantine-Path $_.FullName
        }
    }
}
else {
    Write-Log "  (startup folder not found)"
}

# ===========================================================================
# 5. Remove malicious scheduled tasks
# ===========================================================================
Write-Section "5. Remove malicious scheduled tasks"
foreach ($t in $BadTaskNames) {
    if (-not $Execute) {
        Write-Log ("  [WOULD DELETE TASK] {0}" -f $t)
        continue
    }
    if (Confirm-Step ("Delete scheduled task '{0}'?" -f $t)) {
        $out = schtasks /delete /tn $t /f 2>&1
        if ($LASTEXITCODE -eq 0) {
            Record ("Deleted scheduled task: {0}" -f $t)
        }
        else {
            Warn ("Could not delete task '{0}': {1}" -f $t, ($out -join ' '))
        }
    }
}

try {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $task = $_
        foreach ($action in $task.Actions) {
            $exe = [string]$action.Execute
            if (-not $exe) { continue }
            if ((Test-BadPath $exe) -and -not (Test-Whitelisted $exe)) {
                if (-not $Execute) {
                    Write-Log ("  [WOULD DELETE TASK] {0}{1} -> {2}" -f $task.TaskPath, $task.TaskName, $exe)
                    break
                }
                if (Confirm-Step ("Delete scheduled task '{0}'?" -f $task.TaskName)) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                    Record ("Deleted scheduled task: {0}{1}" -f $task.TaskPath, $task.TaskName)
                }
                break
            }
        }
    }
}
catch {
    Warn ("Scheduled task enumeration unavailable: {0}" -f $_.Exception.Message)
}

# ===========================================================================
# 6. Stop and delete malicious services
# ===========================================================================
Write-Section "6. Stop and delete malicious services"
$svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
foreach ($s in $svcs) {
    $sName = $s.Name
    $sPath = [string]$s.PathName
    if (Test-Whitelisted ("{0} {1}" -f $sName, $sPath)) { continue }

    $bin = Get-ServiceBinaryPath $sPath
    $lbin = $bin.ToLowerInvariant()

    $isBad = $false
    if ($BadServiceNames -contains $sName) { $isBad = $true }
    if (Test-BadPath $bin) { $isBad = $true }
    if (($ReviewServiceNames -contains $sName) -and ($lbin -match '\\appdata\\' -or $lbin -match '\\temp\\')) { $isBad = $true }
    if (-not $isBad) { continue }

    if (-not $Execute) {
        Write-Log ("  [WOULD STOP+DELETE SERVICE] {0} ({1})" -f $sName, $sPath)
        continue
    }
    if (Confirm-Step ("Stop and delete service '{0}'?" -f $sName)) {
        & sc.exe stop $sName | Out-Null
        Start-Sleep -Seconds 1
        $out = & sc.exe delete $sName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Record ("Deleted service: {0}" -f $sName)
        }
        else {
            Warn ("Could not delete service {0}: {1}" -f $sName, ($out -join ' '))
        }
    }
}

# ===========================================================================
# 7. Quarantine malware files/folders
# ===========================================================================
Write-Section "7. Quarantine malware files"
foreach ($bp in $BadPathsToQuarantine) { Quarantine-Path $bp }

if (Test-Path $Temp) {
    Get-ChildItem $Temp -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9]{8,}$' -or $_.Name -match '^[a-f0-9]{8}$' } |
        ForEach-Object {
            $hasExe = Get-ChildItem $_.FullName -Filter *.exe -Force -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hasExe -and -not (Test-Whitelisted $_.FullName)) { Quarantine-Path $_.FullName }
        }
}

$looseRoots = @(
    @{ Root = $Temp; Pattern = '^[A-Fa-f0-9]{8}\.exe$' },
    @{ Root = (Join-Path $Roaming 'Microsoft'); Pattern = '^upd_[0-9]+\.exe$' }
)
foreach ($lr in $looseRoots) {
    if (-not (Test-Path $lr.Root)) { continue }
    Get-ChildItem $lr.Root -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $lr.Pattern } |
        ForEach-Object { if (-not (Test-Whitelisted $_.FullName)) { Quarantine-Path $_.FullName } }
}

foreach ($root in @('C:\ProgramData', (Join-Path $Local 'Microsoft\Windows'))) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -Filter 'windowsruntime.exe' -ErrorAction SilentlyContinue -Force |
            ForEach-Object { Quarantine-Path $_.FullName }
    }
}

# ===========================================================================
# 8. Remove IFEO debugger hijacks
# ===========================================================================
Write-Section "8. Remove Image File Execution Options debugger hijacks"
$ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeo) {
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg -and -not (Test-Whitelisted $dbg) -and (Test-BadPath $dbg)) {
            if (-not $Execute) {
                Write-Log ("  [WOULD REMOVE IFEO] {0} -> {1}" -f $_.PSChildName, $dbg)
                return
            }
            if (Confirm-Step ("Remove IFEO debugger on '{0}'?" -f $_.PSChildName)) {
                Remove-ItemProperty -Path $_.PSPath -Name 'Debugger' -Force -ErrorAction SilentlyContinue
                Record ("Removed IFEO debugger: {0}" -f $_.PSChildName)
            }
        }
    }
}
else {
    Write-Log "  (IFEO registry path not found)"
}

# ===========================================================================
# 9. Repair HOSTS file
# ===========================================================================
Write-Section "9. Repair HOSTS file"
$hosts = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
if (Test-Path $hosts) {
    $lines = Get-Content $hosts -ErrorAction SilentlyContinue
    $removed = @()
    $kept = foreach ($line in $lines) {
        $l = $line.Trim()
        if ($l -and -not $l.StartsWith('#') -and ($l -match '^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)')) {
            $hostName = $Matches[2].ToLowerInvariant()
            $isBad = $false
            foreach ($bh in $BadHostNames) {
                if ($hostName -like ("*{0}*" -f $bh)) {
                    $isBad = $true
                    break
                }
            }
            if ($hostName -eq 'localhost') { $isBad = $false }
            if ($isBad) {
                $removed += $line
                continue
            }
        }
        $line
    }

    if ($removed.Count -gt 0) {
        Write-Log ("  Found {0} malicious redirect line(s)." -f $removed.Count)
        $removed | Select-Object -First 10 | ForEach-Object { Write-Log ("    - {0}" -f $_) }
        if ($removed.Count -gt 10) { Write-Log ("    ... and {0} more" -f ($removed.Count - 10)) }

        if (-not $Execute) {
            Write-Log "  [WOULD REPAIR] hosts file (backup + remove the lines above)"
        }
        elseif (Confirm-Step "Repair the hosts file? A backup is saved first.") {
            Ensure-Quarantine
            Copy-Item $hosts (Join-Path $QuarantineDir 'hosts.backup') -Force -ErrorAction SilentlyContinue
            try {
                Set-Content -Path $hosts -Value $kept -Encoding ASCII -Force -ErrorAction Stop
                Record ("Repaired hosts file ({0} bad lines removed; backup in quarantine)" -f $removed.Count)
            }
            catch {
                Warn ("Could not write hosts file: {0}" -f $_.Exception.Message)
            }
        }
    }
    else {
        Write-Log "  (no malicious hosts entries found)"
    }
}
else {
    Write-Log "  (hosts file not found)"
}

# ===========================================================================
# 10. Re-enable Windows Firewall
# ===========================================================================
Write-Section "10. Windows Firewall"
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($pf in $profiles) {
        if (-not $pf.Enabled) {
            if (-not $Execute) {
                Write-Log ("  [WOULD ENABLE] firewall profile '{0}'" -f $pf.Name)
            }
            elseif (Confirm-Step ("Enable firewall profile '{0}'?" -f $pf.Name)) {
                Set-NetFirewallProfile -Name $pf.Name -Enabled True -ErrorAction Stop
                Record ("Enabled firewall profile: {0}" -f $pf.Name)
            }
        }
        else {
            Write-Log ("  Profile '{0}' already enabled." -f $pf.Name)
        }
    }
}
catch {
    Warn ("Firewall control unavailable: {0}" -f $_.Exception.Message)
}

# ===========================================================================
# 11. Microsoft Defender
# ===========================================================================
Write-Section "11. Microsoft Defender"
if (-not $Execute) {
    Write-Log "  [WOULD] update signatures and start a Defender full scan"
    if ($OfflineScan) { Write-Log "  [WOULD] run Defender Offline scan (reboots the PC)" }
}
else {
    try {
        Write-Log "  Updating Defender signatures..."
        Update-MpSignature -ErrorAction SilentlyContinue
        if ($OfflineScan) {
            Write-Log "  Starting Defender Offline scan - the PC will reboot and scan before Windows loads."
            if ($Force -or (Confirm-Step "Run offline scan now? This reboots the PC.")) {
                Record "Triggered Defender Offline scan"
                Start-MpWDOScan -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-Log "  Starting Defender full scan in the background..."
            Start-MpScan -ScanType FullScan -ErrorAction SilentlyContinue
            Record "Started Defender full scan"
        }
    }
    catch {
        Warn ("Defender control unavailable: {0}" -f $_.Exception.Message)
    }
}

# ===========================================================================
# Summary
# ===========================================================================
Write-Section "SUMMARY"
if (-not $Execute) {
    Write-Log "This was a PREVIEW. No changes were made."
    Write-Log "To actually clean, run:"
    Write-Log "    powershell -ExecutionPolicy Bypass -File .\Clean-SuspiciousActivity.ps1 -Execute"
    Write-Log "Add -Force to skip prompts. Add -OfflineScan to run a pre-boot Defender scan."
}
else {
    Write-Log ("Actions performed : {0}" -f $script:Actions.Count)
    Write-Log ("Warnings          : {0}" -f $script:Warnings.Count)
    Write-Log ("Quarantine folder : {0}" -f $QuarantineDir)
    Write-Log "Files were MOVED, not deleted. Restore from quarantine if needed."
}

Write-Log ''
Write-Log "FINAL REMINDERS:"
Write-Log "  * Change important passwords from a different clean device and enable 2FA."
Write-Log "  * Re-run Scan-SuspiciousActivity.ps1 to confirm what remains."
Write-Log "  * A full Windows reinstall is still the only way to be 100% certain."
Write-Log "  * Avoid cracked/pirated software; that is how infections like this usually arrive."

Write-Host ""
Write-Host "==================================================================="
Get-Content -Path $LogPath -Encoding UTF8 | Out-Host
Write-Host "==================================================================="
Write-Host ("  Cleanup report saved to: {0}" -f $LogPath)
if ($Execute) { Write-Host ("  Quarantine folder      : {0}" -f $QuarantineDir) }
Write-Host "==================================================================="
$LogPath
