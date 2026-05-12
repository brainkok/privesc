#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Privilege Escalation Checker - Advanced
.DESCRIPTION
    Performs comprehensive privilege escalation checks on a Windows system.
    Intended for security audits, penetration testing, and system hardening.
.NOTES
    Use only on systems you are authorized to test.
    Run as a low-privilege user for the most realistic results.
    Run as Administrator to unlock additional checks.
#>

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# OUTPUT HELPERS
# ============================================================

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Check {
    param([string]$Name)
    Write-Host "`n[*] $Name" -ForegroundColor Yellow
}

function Write-Finding {
    param([string]$Message, [string]$Severity = "INFO")
    switch ($Severity) {
        "HIGH"   { Write-Host "  [!!!] $Message" -ForegroundColor Red }
        "MEDIUM" { Write-Host "  [!!]  $Message" -ForegroundColor Magenta }
        "LOW"    { Write-Host "  [!]   $Message" -ForegroundColor Yellow }
        default  { Write-Host "  [+]   $Message" -ForegroundColor Green }
    }
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [-]   $Message" -ForegroundColor Gray
}

# ============================================================
# FINDINGS COLLECTOR
# ============================================================

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param([string]$Category, [string]$Title, [string]$Detail, [string]$Severity)
    $findings.Add([PSCustomObject]@{
        Category = $Category
        Title    = $Title
        Detail   = $Detail
        Severity = $Severity
        Time     = (Get-Date -Format "HH:mm:ss")
    })
    Write-Finding -Message "$Title - $Detail" -Severity $Severity
}

# ============================================================
# HELPER: Check if ACL allows write for low-priv users
# ============================================================

function Test-Writable {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $acl = Get-Acl $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return $false }
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users|BUILTIN\\Usuarios" -and
        $_.FileSystemRights  -match "Write|FullControl|Modify"
    }
    return [bool]$writable
}

function Test-RegistryWritable {
    param([string]$Path)
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            ($Path -replace "HKLM:\\", ""), $true)
        if ($key) { $key.Close(); return $true }
    } catch {}
    return $false
}

# ============================================================
# START
# ============================================================

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin     = ([System.Security.Principal.WindowsPrincipal]$currentUser).IsInRole(
                   [System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host "  Windows Privilege Escalation Checker - Advanced" -ForegroundColor DarkCyan
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkCyan
Write-Host "  User    : $($currentUser.Name)" -ForegroundColor DarkCyan
Write-Host "  Admin   : $isAdmin" -ForegroundColor DarkCyan
Write-Host ("=" * 70) -ForegroundColor DarkCyan

# ============================================================
Write-Header "SYSTEM INFORMATION"
# ============================================================

Write-Check "OS version and patch level"
$os = Get-CimInstance Win32_OperatingSystem
Write-Info "OS        : $($os.Caption) (Build $($os.BuildNumber)) $($os.OSArchitecture)"
Write-Info "Version   : $($os.Version)"
Write-Info "Last boot : $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Info "Hostname  : $($env:COMPUTERNAME)"
Write-Info "Domain    : $($env:USERDOMAIN)"

$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
Write-Info "Latest patches:"
$hotfixes | ForEach-Object { Write-Info "  KB$($_.HotFixID) installed $($_.InstalledOn)" }

if ($hotfixes.Count -lt 3) {
    Add-Finding -Category "Patching" -Title "Very few patches installed" `
        -Detail "Only $($hotfixes.Count) hotfixes found - system may be unpatched" -Severity "HIGH"
}

Write-Check "PowerShell version"
$psv = $PSVersionTable.PSVersion
Write-Info "PowerShell version: $($psv.Major).$($psv.Minor)"
if ($psv.Major -le 2) {
    Add-Finding -Category "PowerShell" -Title "Old PowerShell version" `
        -Detail "PS $($psv.Major).$($psv.Minor) - Script Block Logging not available, v2 downgrade possible" -Severity "HIGH"
}

# Check if PS v2 engine is still installed (downgrade attack)
$ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
if ($ps2 -and $ps2.State -eq "Enabled") {
    Add-Finding -Category "PowerShell" -Title "PowerShell v2 engine enabled" `
        -Detail "Attacker can downgrade to bypass logging: powershell -v 2 -c whoami" -Severity "MEDIUM"
}

Write-Check "PowerShell security settings"
$psLogging  = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$psAMSI     = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ErrorAction SilentlyContinue
$langMode   = $ExecutionContext.SessionState.LanguageMode
Write-Info "Language mode      : $langMode"
Write-Info "Script block logging enabled: $($psLogging.EnableScriptBlockLogging)"
if (-not $psLogging -or $psLogging.EnableScriptBlockLogging -ne 1) {
    Add-Finding -Category "PowerShell" -Title "Script Block Logging disabled" `
        -Detail "Malicious PS commands will not be logged" -Severity "LOW"
}
if ($langMode -eq "FullLanguage") {
    Add-Finding -Category "PowerShell" -Title "PowerShell in FullLanguage mode" `
        -Detail "No AppLocker/WDAC constraint on PowerShell" -Severity "LOW"
}

# ============================================================
Write-Header "CURRENT USER AND TOKEN"
# ============================================================

Write-Check "Current user context"
Write-Info "User     : $($currentUser.Name)"
Write-Info "Is Admin : $isAdmin"
$groups = $currentUser.Groups | ForEach-Object {
    try { $_.Translate([System.Security.Principal.NTAccount]).Value } catch { $_.Value }
}
Write-Info "Groups:"
$groups | ForEach-Object { Write-Info "  $_" }

if ($isAdmin) {
    Add-Finding -Category "User" -Title "Running as administrator" `
        -Detail "Script has full admin rights - full system access" -Severity "INFO"
}
if ($groups -match "Domain Admins") {
    Add-Finding -Category "User" -Title "Member of Domain Admins" `
        -Detail $currentUser.Name -Severity "HIGH"
}
if ($groups -match "Backup Operators") {
    Add-Finding -Category "User" -Title "Member of Backup Operators" `
        -Detail "Can read any file including SAM/SYSTEM hives" -Severity "HIGH"
}

Write-Check "Token privileges"
$tokenOutput = (& whoami /priv 2>&1)
$dangerousPrivs = @{
    "SeImpersonatePrivilege"      = "Potato attacks (PrintSpoofer, GodPotato)"
    "SeAssignPrimaryTokenPrivilege" = "Token swapping for SYSTEM"
    "SeTcbPrivilege"              = "Act as part of OS"
    "SeBackupPrivilege"           = "Read any file including SAM"
    "SeRestorePrivilege"          = "Write any file"
    "SeCreateTokenPrivilege"      = "Create arbitrary tokens"
    "SeLoadDriverPrivilege"       = "Load malicious kernel driver"
    "SeTakeOwnershipPrivilege"    = "Take ownership of any object"
    "SeDebugPrivilege"            = "Inject into any process (LSASS)"
    "SeManageVolumePrivilege"     = "Manage volume - write anywhere"
    "SeRelabelPrivilege"          = "Modify object integrity levels"
    "SeCreateSymbolicLinkPrivilege" = "Create symlinks for file redirects"
}
foreach ($priv in $dangerousPrivs.Keys) {
    if ($tokenOutput -match $priv) {
        $line = ($tokenOutput | Where-Object { $_ -match $priv }) -join ""
        if ($line -match "Enabled") {
            Add-Finding -Category "Token" -Title "Dangerous privilege ENABLED" `
                -Detail "$priv ($($dangerousPrivs[$priv]))" -Severity "HIGH"
        } else {
            Write-Info "$priv - present but disabled"
        }
    }
}

# ============================================================
Write-Header "UAC CONFIGURATION"
# ============================================================

Write-Check "UAC registry settings"
$uacKey        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacEnabled    = (Get-ItemProperty $uacKey -ErrorAction SilentlyContinue).EnableLUA
$consentPrompt = (Get-ItemProperty $uacKey -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$secureDesktop = (Get-ItemProperty $uacKey -ErrorAction SilentlyContinue).PromptOnSecureDesktop
$localAcctFilter = (Get-ItemProperty $uacKey -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy

Write-Info "EnableLUA                  : $uacEnabled"
Write-Info "ConsentPromptBehaviorAdmin : $consentPrompt"
Write-Info "PromptOnSecureDesktop      : $secureDesktop"
Write-Info "LocalAccountTokenFilterPolicy: $localAcctFilter"

if ($uacEnabled -eq 0) {
    Add-Finding -Category "UAC" -Title "UAC completely disabled" `
        -Detail "EnableLUA = 0" -Severity "HIGH"
}
if ($consentPrompt -eq 0) {
    Add-Finding -Category "UAC" -Title "No UAC prompt for admins" `
        -Detail "ConsentPromptBehaviorAdmin = 0 - auto-elevate without prompt" -Severity "HIGH"
}
if ($consentPrompt -eq 5) {
    Add-Finding -Category "UAC" -Title "UAC set to lowest prompt level" `
        -Detail "ConsentPromptBehaviorAdmin = 5 - no password required for elevation" -Severity "LOW"
}
if ($secureDesktop -eq 0) {
    Add-Finding -Category "UAC" -Title "Secure Desktop disabled" `
        -Detail "UIAccess relay attack possible" -Severity "MEDIUM"
}
if ($localAcctFilter -eq 1) {
    Add-Finding -Category "UAC" -Title "LocalAccountTokenFilterPolicy enabled" `
        -Detail "Remote admin shares accessible with local admin credentials (PtH)" -Severity "HIGH"
}

# ============================================================
Write-Header "SERVICES - UNQUOTED PATHS"
# ============================================================

Write-Check "Services with unquoted executable paths"
$unquotedSvcs = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^C:\\Windows\\'
}

foreach ($svc in $unquotedSvcs) {
    $path    = $svc.PathName
    $parts   = $path.Split(' ')
    $build   = ""
    $wasHigh = $false
    foreach ($part in $parts) {
        $build += $part
        $dir    = Split-Path $build -Parent
        if ($dir -and (Test-Path $dir)) {
            if (Test-Writable $dir) {
                Add-Finding -Category "Service" -Title "Unquoted path - writable intermediate directory" `
                    -Detail "$($svc.Name) | $path" -Severity "HIGH"
                $wasHigh = $true
                break
            }
        }
        $build += " "
    }
    if (-not $wasHigh) {
        Add-Finding -Category "Service" -Title "Unquoted service path" `
            -Detail "$($svc.Name) | $path" -Severity "MEDIUM"
    }
}

if (-not $unquotedSvcs) { Write-Info "No unquoted service paths found." }

# ============================================================
Write-Header "SERVICES - WEAK PERMISSIONS"
# ============================================================

Write-Check "Writable service executables"
$allSvcs = Get-CimInstance Win32_Service | Where-Object { $_.PathName }
foreach ($svc in $allSvcs) {
    $exe = $svc.PathName -replace '"','' -replace ' .*',''
    if (-not $exe -or -not (Test-Path $exe)) { continue }
    if (Test-Writable $exe) {
        Add-Finding -Category "Service" -Title "Writable service executable" `
            -Detail "$($svc.Name) | $exe" -Severity "HIGH"
    }
}

Write-Check "Writable service binary directories"
foreach ($svc in $allSvcs) {
    $exe = $svc.PathName -replace '"','' -replace ' .*',''
    if (-not $exe) { continue }
    $dir = Split-Path $exe -Parent
    if ($dir -and (Test-Path $dir) -and (Test-Writable $dir)) {
        Add-Finding -Category "Service" -Title "Writable directory of service executable" `
            -Detail "$($svc.Name) | $dir" -Severity "HIGH"
    }
}

Write-Check "Service ACLs (sc sdshow)"
$svcNames = Get-Service | Select-Object -ExpandProperty Name
foreach ($name in $svcNames) {
    $sd = (& sc.exe sdshow $name 2>&1) | Where-Object { $_ -match "D:" }
    if ($sd -match "A;;[A-Z]*W[A-Z]*;;;WD|A;;[A-Z]*W[A-Z]*;;;BU|A;;GA;;;WD") {
        Add-Finding -Category "Service" -Title "Service ACL allows user modification" `
            -Detail "Service: $name - low-privilege users can change config" -Severity "HIGH"
    }
}

Write-Check "Services running as SYSTEM with non-standard paths"
foreach ($svc in ($allSvcs | Where-Object { $_.StartName -match "LocalSystem|SYSTEM" })) {
    $exe = $svc.PathName -replace '"','' -replace ' .*',''
    if ($exe -and $exe -notmatch '^C:\\Windows\\' -and (Test-Path $exe)) {
        Write-Info "SYSTEM service outside Windows dir: $($svc.Name) | $exe"
    }
}

# ============================================================
Write-Header "REGISTRY - AUTORUN AND PERSISTENCE"
# ============================================================

Write-Check "AutoRun registry keys"
$autorunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
)
foreach ($key in $autorunKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $val  = $_.Value
        $name = $_.Name
        Write-Info "$key -> $name : $val"
        $exe = $val -replace '"','' -replace ' .*',''
        if ($exe -and (Test-Path $exe) -and (Test-Writable $exe)) {
            Add-Finding -Category "AutoRun" -Title "Writable AutoRun executable" `
                -Detail "$name | $exe" -Severity "HIGH"
        }
    }
}

Write-Check "AlwaysInstallElevated"
$aie1 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aie2 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aie1 -eq 1 -and $aie2 -eq 1) {
    Add-Finding -Category "Registry" -Title "AlwaysInstallElevated enabled" `
        -Detail "Any MSI can be installed as SYSTEM - create malicious MSI" -Severity "HIGH"
} else {
    Write-Info "AlwaysInstallElevated: not set"
}

Write-Check "WDigest plaintext credential caching"
$wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
Write-Info "WDigest UseLogonCredential: $wdigest"
if ($wdigest -eq 1) {
    Add-Finding -Category "Registry" -Title "WDigest enabled - plaintext passwords in LSASS" `
        -Detail "UseLogonCredential = 1 - mimikatz can dump cleartext creds" -Severity "HIGH"
}

Write-Check "LSASS protection (PPL)"
$lsaPPL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
$lsaCFG = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags
Write-Info "RunAsPPL   : $lsaPPL"
Write-Info "LsaCfgFlags: $lsaCFG"
if ($lsaPPL -ne 1) {
    Add-Finding -Category "Registry" -Title "LSASS not running as Protected Process" `
        -Detail "RunAsPPL = $lsaPPL - LSASS memory can be dumped directly" -Severity "MEDIUM"
}

Write-Check "Credential Guard"
$credGuard = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
Write-Info "Credential Guard (VBS): $credGuard"
if ($credGuard -ne 1) {
    Add-Finding -Category "Registry" -Title "Credential Guard not enabled" `
        -Detail "NTLM hashes may be extractable from LSASS" -Severity "LOW"
}

Write-Check "Cached domain logons"
$cachedLogons = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue).CachedLogonsCount
Write-Info "Cached domain logons: $cachedLogons"
if ([int]$cachedLogons -gt 0) {
    Add-Finding -Category "Registry" -Title "Domain credentials cached locally" `
        -Detail "CachedLogonsCount = $cachedLogons - offline cracking possible" -Severity "LOW"
}

# ============================================================
Write-Header "SCHEDULED TASKS"
# ============================================================

Write-Check "Enabled tasks with writable executables"
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
foreach ($task in $tasks) {
    foreach ($act in ($task.Actions | Where-Object { $_.Execute })) {
        $exe = $act.Execute -replace '"',''
        if (-not $exe -or -not (Test-Path $exe)) { continue }
        if (Test-Writable $exe) {
            Add-Finding -Category "ScheduledTask" -Title "Writable task executable" `
                -Detail "$($task.TaskName) | $exe" -Severity "HIGH"
        }
        $dir = Split-Path $exe -Parent
        if ($dir -and (Test-Writable $dir)) {
            Add-Finding -Category "ScheduledTask" -Title "Writable directory of task executable" `
                -Detail "$($task.TaskName) | $dir" -Severity "HIGH"
        }
    }
}

Write-Check "SYSTEM tasks with non-system executables"
foreach ($task in $tasks) {
    $p = $task.Principal
    if ($p.UserId -match "SYSTEM|S-1-5-18" -or $p.RunLevel -eq "Highest") {
        foreach ($act in ($task.Actions | Where-Object { $_.Execute })) {
            $exe = $act.Execute -replace '"',''
            if ($exe -and $exe -notmatch '^C:\\Windows\\' -and (Test-Path $exe)) {
                Write-Info "SYSTEM task outside Windows: $($task.TaskName) | $exe"
                if (Test-Writable $exe) {
                    Add-Finding -Category "ScheduledTask" -Title "SYSTEM task with writable executable" `
                        -Detail "$($task.TaskName) | $exe" -Severity "HIGH"
                }
            }
        }
    }
}

# ============================================================
Write-Header "PATH HIJACKING"
# ============================================================

Write-Check "Writable directories in system PATH"
$pathDirs = $env:PATH.Split(';') | Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $pathDirs) {
    if (-not (Test-Path $dir)) { Write-Info "Missing: $dir"; continue }
    if (Test-Writable $dir) {
        Add-Finding -Category "PATH" -Title "Writable PATH directory" `
            -Detail $dir -Severity "HIGH"
    } else {
        Write-Info "OK: $dir"
    }
}

Write-Check "Startup folder write access"
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $startupDirs) {
    if (Test-Writable $dir) {
        Add-Finding -Category "Startup" -Title "Writable startup folder" `
            -Detail $dir -Severity "HIGH"
    } else {
        Write-Info "OK: $dir"
    }
}

# ============================================================
Write-Header "DLL HIJACKING"
# ============================================================

Write-Check "Writable subdirectories under Program Files"
$programDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
foreach ($base in $programDirs) {
    if (-not $base -or -not (Test-Path $base)) { continue }
    Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-Writable $_.FullName) {
            Add-Finding -Category "DLL Hijack" -Title "Writable program directory" `
                -Detail $_.FullName -Severity "MEDIUM"
        }
    }
}

Write-Check "Missing DLLs in writable PATH locations (common targets)"
$knownMissingDLLs = @("wlbsctrl.dll","cscapi.dll","ntvdm64.dll","wow64log.dll","WindowsCoreDeviceInfo.dll")
foreach ($dll in $knownMissingDLLs) {
    foreach ($dir in $pathDirs) {
        if ((Test-Path $dir) -and -not (Test-Path "$dir\$dll") -and (Test-Writable $dir)) {
            Add-Finding -Category "DLL Hijack" -Title "Writable PATH dir missing known DLL" `
                -Detail "$dir\$dll - drop malicious DLL here" -Severity "MEDIUM"
        }
    }
}

# ============================================================
Write-Header "STORED CREDENTIALS"
# ============================================================

Write-Check "Windows Credential Manager"
$creds = (& cmdkey /list 2>&1)
if ($creds -match "Target:") {
    $credDetail = ($creds | Where-Object { $_ -match "Target:|User:|Type:" } | Out-String).Trim()
    Add-Finding -Category "Credentials" -Title "Stored credentials in Credential Manager" `
        -Detail $credDetail -Severity "MEDIUM"
} else {
    Write-Info "No stored credentials in Credential Manager."
}

Write-Check "Autologon credentials in registry"
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.DefaultPassword) {
    Add-Finding -Category "Credentials" -Title "Autologon plaintext password in registry" `
        -Detail "User: $($winlogon.DefaultUserName) Pass: $($winlogon.DefaultPassword)" -Severity "HIGH"
} else {
    Write-Info "No autologon password found."
}

Write-Check "Sensitive environment variables"
$envVars = [System.Environment]::GetEnvironmentVariables()
$sensitiveKeys = @("pass","pwd","password","secret","key","token","cred","api","auth","hash")
foreach ($k in $envVars.Keys) {
    foreach ($pat in $sensitiveKeys) {
        if ($k -imatch $pat) {
            Add-Finding -Category "Credentials" -Title "Sensitive environment variable" `
                -Detail "$k = $($envVars[$k])" -Severity "MEDIUM"
        }
    }
}

Write-Check "Unattend.xml and Sysprep files"
$installFiles = @(
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattended.xml",
    "C:\Windows\Panther\unattend\Unattend.xml",
    "C:\Windows\System32\sysprep\sysprep.xml",
    "C:\Windows\System32\sysprep\Panther\Unattend.xml",
    "C:\unattend.xml",
    "C:\autounattend.xml"
)
foreach ($f in $installFiles) {
    if (Test-Path $f) {
        Add-Finding -Category "Credentials" -Title "Installation answer file found" `
            -Detail $f -Severity "HIGH"
        $fc = Get-Content $f -Raw -ErrorAction SilentlyContinue
        if ($fc -match "<Password>|<AdministratorPassword>|<UserAccounts>") {
            Add-Finding -Category "Credentials" -Title "Password field in answer file" `
                -Detail $f -Severity "HIGH"
        }
    }
}

Write-Check "Group Policy Preferences (GPP) password files"
$gppPaths = @(
    "C:\ProgramData\Microsoft\Group Policy",
    "$env:SYSVOL"
)
foreach ($base in $gppPaths) {
    if (-not $base -or -not (Test-Path $base)) { continue }
    Get-ChildItem $base -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue | ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "cpassword") {
            Add-Finding -Category "Credentials" -Title "GPP cpassword found" `
                -Detail $_.FullName -Severity "HIGH"
        }
    }
}

Write-Check "WLAN saved credentials"
$wlanProfiles = (& netsh wlan show profiles 2>&1)
if ($wlanProfiles -match "All User Profile") {
    $profileNames = ($wlanProfiles | Select-String "All User Profile\s*:\s*(.+)") | ForEach-Object {
        $_.Matches.Groups[1].Value.Trim()
    }
    foreach ($profile in $profileNames) {
        $details = (& netsh wlan show profile name="$profile" key=clear 2>&1)
        if ($details -match "Key Content\s+:\s+(.+)") {
            $key = ($details | Select-String "Key Content\s+:\s+(.+)").Matches.Groups[1].Value
            Add-Finding -Category "Credentials" -Title "WLAN plaintext password found" `
                -Detail "SSID: $profile | Key: $key" -Severity "HIGH"
        }
    }
    Write-Info "Found $($profileNames.Count) WLAN profile(s)"
}

Write-Check "SAM and SYSTEM backup copies"
$hiveCopies = @(
    "C:\Windows\Repair\SAM",
    "C:\Windows\Repair\SYSTEM",
    "C:\Windows\System32\config\RegBack\SAM",
    "C:\Windows\System32\config\RegBack\SYSTEM",
    "C:\Windows\System32\config\RegBack\SECURITY"
)
foreach ($f in $hiveCopies) {
    if (Test-Path $f) {
        $size = (Get-Item $f).Length
        if ($size -gt 0) {
            Add-Finding -Category "Credentials" -Title "Registry hive backup accessible" `
                -Detail "$f ($size bytes) - dump with secretsdump" -Severity "HIGH"
        }
    }
}

Write-Check "Files containing passwords (common locations)"
$searchPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "C:\Users\Public"
)
$credFilePatterns = @("*pass*","*cred*","*secret*","*vnc*","*.kdbx","*.pfx","*.pem","*.key","id_rsa","id_dsa")
foreach ($base in $searchPaths) {
    if (-not (Test-Path $base)) { continue }
    foreach ($pat in $credFilePatterns) {
        Get-ChildItem $base -Filter $pat -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Category "Credentials" -Title "Suspicious file found" `
                -Detail $_.FullName -Severity "MEDIUM"
        }
    }
}

# ============================================================
Write-Header "NETWORK AND SHARES"
# ============================================================

Write-Check "Local shared folders"
$shares = Get-CimInstance Win32_Share | Where-Object { $_.Type -le 1 }
foreach ($share in $shares) {
    $label = if ($share.Type -eq 0) { "Disk" } else { "Admin" }
    Write-Info "[$label] $($share.Name) -> $($share.Path)"
    if ($share.Path -and (Test-Writable $share.Path)) {
        Add-Finding -Category "Share" -Title "Writable share" `
            -Detail "$($share.Name) -> $($share.Path)" -Severity "MEDIUM"
    }
}

Write-Check "Firewall status"
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in $fwProfiles) {
    Write-Info "Firewall [$($p.Name)]: Enabled=$($p.Enabled) DefaultInbound=$($p.DefaultInboundAction)"
    if (-not $p.Enabled) {
        Add-Finding -Category "Network" -Title "Firewall profile disabled" `
            -Detail "Profile: $($p.Name)" -Severity "MEDIUM"
    }
}

Write-Check "IPv6 enabled (relay attack surface)"
$ipv6 = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
if ($ipv6) {
    Write-Info "IPv6 enabled on: $($ipv6.Name -join ', ')"
    Add-Finding -Category "Network" -Title "IPv6 enabled" `
        -Detail "Possible mitm6 / DHCPv6 relay attack" -Severity "LOW"
}

Write-Check "Listening services"
$listeners = (& netstat -ano 2>&1) | Select-String "LISTENING"
Write-Info "Listening ports:"
$listeners | ForEach-Object { Write-Info "  $($_.Line.Trim())" }

Write-Check "SMB signing"
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig) {
    Write-Info "SMB Signing Required: $($smbConfig.RequireSecuritySignature)"
    if (-not $smbConfig.RequireSecuritySignature) {
        Add-Finding -Category "Network" -Title "SMB signing not required" `
            -Detail "SMB relay attacks possible (Responder, ntlmrelayx)" -Severity "MEDIUM"
    }
}

# ============================================================
Write-Header "LOCAL USERS AND GROUPS"
# ============================================================

Write-Check "Local Administrators group members"
$admins = (& net localgroup Administrators 2>&1)
Write-Info "Administrators:"
$admins | Select-String "^(?!--|Alias|Members|Comment|The command|$)" | ForEach-Object {
    Write-Info "  $($_.Line.Trim())"
}

Write-Check "All local user accounts"
$users = Get-LocalUser
foreach ($user in $users) {
    $status   = if ($user.Enabled) { "Active" } else { "Disabled" }
    $pwExpiry = if ($user.PasswordExpires) { $user.PasswordExpires.ToString() } else { "Never" }
    $pwReq    = if ($user.PasswordRequired) { "Yes" } else { "NO" }
    Write-Info "$($user.Name) [$status] PwExpires:$pwExpiry PwRequired:$pwReq"
    if ($user.Enabled -and -not $user.PasswordRequired) {
        Add-Finding -Category "User" -Title "Enabled account with no password required" `
            -Detail $user.Name -Severity "HIGH"
    }
    if ($user.Enabled -and $user.PasswordNeverExpires) {
        Add-Finding -Category "User" -Title "Password never expires" `
            -Detail $user.Name -Severity "LOW"
    }
}

Write-Check "Guest account status"
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    Add-Finding -Category "User" -Title "Guest account is enabled" `
        -Detail "Guest account allows unauthenticated local access" -Severity "HIGH"
} else {
    Write-Info "Guest account disabled."
}

# ============================================================
Write-Header "ANTIVIRUS AND DEFENDER"
# ============================================================

Write-Check "Windows Defender status"
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Info "RealTimeProtection : $($defender.RealTimeProtectionEnabled)"
    Write-Info "AV Signature Age   : $($defender.AntivirusSignatureAge) days"
    Write-Info "AM Enabled         : $($defender.AMServiceEnabled)"
    if (-not $defender.RealTimeProtectionEnabled) {
        Add-Finding -Category "Defender" -Title "Windows Defender real-time protection disabled" `
            -Detail "Malicious executables will not be blocked" -Severity "HIGH"
    }
    if ($defender.AntivirusSignatureAge -gt 7) {
        Add-Finding -Category "Defender" -Title "Defender signatures outdated" `
            -Detail "Signature age: $($defender.AntivirusSignatureAge) days" -Severity "LOW"
    }
} else {
    Add-Finding -Category "Defender" -Title "Could not query Defender status" `
        -Detail "Defender may be disabled or replaced" -Severity "MEDIUM"
}

Write-Check "Defender exclusions"
$exclusions = Get-MpPreference -ErrorAction SilentlyContinue
if ($exclusions) {
    if ($exclusions.ExclusionPath) {
        foreach ($excl in $exclusions.ExclusionPath) {
            Add-Finding -Category "Defender" -Title "Defender path exclusion" `
                -Detail $excl -Severity "MEDIUM"
        }
    }
    if ($exclusions.ExclusionProcess) {
        foreach ($excl in $exclusions.ExclusionProcess) {
            Add-Finding -Category "Defender" -Title "Defender process exclusion" `
                -Detail $excl -Severity "MEDIUM"
        }
    }
    if (-not $exclusions.ExclusionPath -and -not $exclusions.ExclusionProcess) {
        Write-Info "No Defender exclusions configured."
    }
}

# ============================================================
Write-Header "APPLOCKER AND APPLICATION CONTROL"
# ============================================================

Write-Check "AppLocker policy"
$applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
if ($applockerPolicy) {
    $rules = $applockerPolicy.RuleCollections | ForEach-Object { $_ }
    if ($rules) {
        Write-Info "AppLocker rules found:"
        $rules | ForEach-Object { Write-Info "  RuleCollection: $($_.RuleCollectionType) ($($_.Count) rules)" }
    } else {
        Add-Finding -Category "AppLocker" -Title "AppLocker has no effective rules" `
            -Detail "Any executable can run" -Severity "LOW"
    }
} else {
    Add-Finding -Category "AppLocker" -Title "AppLocker not configured" `
        -Detail "No application whitelisting in place" -Severity "LOW"
}

Write-Check "Writable directories inside AppLocker allowed paths"
$commonBypassDirs = @(
    "C:\Windows\Tasks",
    "C:\Windows\Temp",
    "C:\Windows\tracing",
    "C:\Windows\Registration\CRMLog",
    "C:\Windows\System32\FxsTmp",
    "C:\Windows\System32\com\dmp",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\System32\spool\PRINTERS",
    "C:\Windows\System32\spool\SERVERS",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\SysWOW64\FxsTmp",
    "C:\Windows\SysWOW64\com\dmp"
)
foreach ($dir in $commonBypassDirs) {
    if ((Test-Path $dir) -and (Test-Writable $dir)) {
        Add-Finding -Category "AppLocker" -Title "Writable AppLocker bypass directory" `
            -Detail $dir -Severity "MEDIUM"
    }
}

# ============================================================
Write-Header "INSTALLED SOFTWARE"
# ============================================================

Write-Check "All installed software (32-bit and 64-bit)"
$softKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installed = $softKeys | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher |
    Sort-Object DisplayName -Unique

Write-Info "Total installed: $($installed.Count) products"
$installed | ForEach-Object {
    Write-Info "  $($_.DisplayName) v$($_.DisplayVersion) [$($_.Publisher)]"
}

# Flag known vulnerable software
$knownVuln = @("VNC","TeamViewer","PuTTY","WinSCP","FileZilla","mRemoteNG","TightVNC")
foreach ($app in $installed) {
    foreach ($vuln in $knownVuln) {
        if ($app.DisplayName -match $vuln) {
            Add-Finding -Category "Software" -Title "Credential-storing application found" `
                -Detail "$($app.DisplayName) v$($app.DisplayVersion) - may store saved credentials" -Severity "LOW"
        }
    }
}

# ============================================================
Write-Header "SUMMARY"
# ============================================================

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor White
Write-Host "  FINDINGS OVERVIEW" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor White

foreach ($sev in @("HIGH","MEDIUM","LOW","INFO")) {
    $group = $findings | Where-Object { $_.Severity -eq $sev }
    if (-not $group) { continue }
    $color = switch ($sev) {
        "HIGH"   { "Red" }
        "MEDIUM" { "Magenta" }
        "LOW"    { "Yellow" }
        default  { "Green" }
    }
    Write-Host "`n  [$sev] $($group.Count) finding(s):" -ForegroundColor $color
    $group | ForEach-Object {
        Write-Host "    [>] [$($_.Category)] $($_.Title)" -ForegroundColor $color
        Write-Host "        $($_.Detail)" -ForegroundColor Gray
    }
}

Write-Host ""
$high   = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medium = ($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$low    = ($findings | Where-Object { $_.Severity -eq "LOW" }).Count
Write-Host ("=" * 70) -ForegroundColor White
Write-Host "  HIGH   : $high" -ForegroundColor Red
Write-Host "  MEDIUM : $medium" -ForegroundColor Magenta
Write-Host "  LOW    : $low" -ForegroundColor Yellow
Write-Host "  Total  : $($findings.Count)" -ForegroundColor White
Write-Host "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor White

# Export report
$csv  = "$env:TEMP\PrivEsc_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$html = "$env:TEMP\PrivEsc_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

$findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

# HTML report
$rows = $findings | ForEach-Object {
    $bg = switch ($_.Severity) {
        "HIGH"   { "#ff4c4c" }
        "MEDIUM" { "#cc66ff" }
        "LOW"    { "#ffcc00" }
        default  { "#66cc66" }
    }
    "<tr style='background:$bg'><td>$($_.Time)</td><td>$($_.Severity)</td><td>$($_.Category)</td><td>$($_.Title)</td><td>$($_.Detail)</td></tr>"
}
$htmlContent = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>PrivEsc Report</title>
<style>body{font-family:Consolas,monospace;background:#1e1e1e;color:#ddd}
table{width:100%;border-collapse:collapse}th{background:#333;padding:8px;text-align:left}
td{padding:6px;border-bottom:1px solid #333;color:#000}h1{color:#00bfff}</style></head>
<body><h1>Windows Privilege Escalation Report</h1>
<p>Generated: $(Get-Date) | User: $($currentUser.Name) | Host: $env:COMPUTERNAME</p>
<table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th></tr>
$($rows -join "`n")
</table></body></html>
"@
[System.IO.File]::WriteAllText($html, $htmlContent, [System.Text.UTF8Encoding]::new($false))

Write-Host "  CSV  saved : $csv" -ForegroundColor Cyan
Write-Host "  HTML saved : $html" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor White
