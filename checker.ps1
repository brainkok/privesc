#Requires -Version 3.0
<#
.SYNOPSIS
    Windows Privilege Escalation Checker
.DESCRIPTION
    Performs comprehensive privilege escalation checks on a Windows system.
    Intended for security audits, penetration testing, and system hardening.
.NOTES
    Use only on systems you are authorized to test.
#>

$ErrorActionPreference = "SilentlyContinue"

function Write-Header {
    param([string]$Title)
    Write-Host "`n" -NoNewline
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

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param([string]$Category, [string]$Title, [string]$Detail, [string]$Severity)
    $findings.Add([PSCustomObject]@{
        Category = $Category
        Title    = $Title
        Detail   = $Detail
        Severity = $Severity
    })
    Write-Finding -Message "$Title — $Detail" -Severity $Severity
}

# ============================================================
Write-Header "SYSTEM INFORMATION"
# ============================================================

Write-Check "OS version & patch level"
$os = Get-WmiObject Win32_OperatingSystem
Write-Info "OS: $($os.Caption) $($os.Version) (Build $($os.BuildNumber))"
Write-Info "Architecture: $($os.OSArchitecture)"
Write-Info "Last boot: $($os.LastBootUpTime)"

$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
Write-Info "Last 5 patches:"
$hotfixes | ForEach-Object { Write-Info "  KB$($_.HotFixID) — $($_.InstalledOn)" }

Write-Check "Current user & privileges"
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([System.Security.Principal.WindowsPrincipal]$currentUser).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Info "User: $($currentUser.Name)"
Write-Info "Is Administrator: $isAdmin"

if ($isAdmin) {
    Add-Finding -Category "User" -Title "Already admin" -Detail "Script is running as administrator" -Severity "INFO"
}

Write-Check "Token privileges"
$tokenPrivs = whoami /priv 2>$null
$dangerousPrivs = @(
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeCreateTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeDebugPrivilege"
)
foreach ($priv in $dangerousPrivs) {
    if ($tokenPrivs -match $priv) {
        $line = $tokenPrivs | Where-Object { $_ -match $priv }
        if ($line -match "Enabled") {
            Add-Finding -Category "Token" -Title "Dangerous privilege enabled" -Detail $priv -Severity "HIGH"
        } else {
            Write-Info "$priv present but disabled"
        }
    }
}

# ============================================================
Write-Header "UAC CONFIGURATION"
# ============================================================

Write-Check "UAC settings"
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacEnabled    = (Get-ItemProperty $uacKey).EnableLUA
$consentPrompt = (Get-ItemProperty $uacKey).ConsentPromptBehaviorAdmin
$secureDesktop = (Get-ItemProperty $uacKey).PromptOnSecureDesktop

Write-Info "EnableLUA: $uacEnabled"
Write-Info "ConsentPromptBehaviorAdmin: $consentPrompt"
Write-Info "PromptOnSecureDesktop: $secureDesktop"

if ($uacEnabled -eq 0) {
    Add-Finding -Category "UAC" -Title "UAC disabled" -Detail "EnableLUA = 0" -Severity "HIGH"
}
if ($consentPrompt -eq 0) {
    Add-Finding -Category "UAC" -Title "UAC prompt disabled for admins" -Detail "ConsentPromptBehaviorAdmin = 0" -Severity "HIGH"
}
if ($secureDesktop -eq 0) {
    Add-Finding -Category "UAC" -Title "Secure Desktop disabled" -Detail "PromptOnSecureDesktop = 0 — relay attack possible" -Severity "MEDIUM"
}

# ============================================================
Write-Header "SERVICES — UNQUOTED PATHS"
# ============================================================

Write-Check "Services with unquoted service paths"
$services = Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^C:\\Windows\\'
}

foreach ($svc in $services) {
    $path = $svc.PathName
    $parts = $path.Split(' ')
    $buildPath = ""
    $writable = $null
    foreach ($part in $parts) {
        $buildPath += $part
        $dir = Split-Path $buildPath -Parent
        if ($dir -and (Test-Path $dir)) {
            $acl = Get-Acl $dir
            $writable = $acl.Access | Where-Object {
                $_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users" -and
                $_.FileSystemRights -match "Write|FullControl|Modify"
            }
            if ($writable) {
                Add-Finding -Category "Service" -Title "Unquoted path + writable directory" `
                    -Detail "$($svc.Name): $path" -Severity "HIGH"
                break
            }
        }
        $buildPath += " "
    }
    if (-not $writable) {
        Add-Finding -Category "Service" -Title "Unquoted service path" `
            -Detail "$($svc.Name): $path" -Severity "MEDIUM"
    }
}

if (-not $services) { Write-Info "No unquoted service paths found." }

# ============================================================
Write-Header "SERVICES — WEAK PERMISSIONS"
# ============================================================

Write-Check "Writable service executables"
$allServices = Get-WmiObject Win32_Service | Where-Object { $_.PathName }
foreach ($svc in $allServices) {
    $exe = $svc.PathName -replace '"', '' -replace ' .*', ''
    if (-not $exe -or -not (Test-Path $exe)) { continue }

    $acl = Get-Acl $exe
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
        $_.FileSystemRights -match "Write|FullControl|Modify"
    }
    if ($writable) {
        Add-Finding -Category "Service" -Title "Writable service executable" `
            -Detail "$($svc.Name): $exe" -Severity "HIGH"
    }
}

Write-Check "Weak service configuration permissions (sc sdshow)"
$svcNames = Get-Service | Select-Object -ExpandProperty Name
foreach ($name in $svcNames) {
    $sd = sc.exe sdshow $name 2>$null
    if ($sd -match "A;;RPWP.*WD|A;;RPWP.*BU|A;;GA.*WD") {
        Add-Finding -Category "Service" -Title "Weak service ACL" `
            -Detail "Service '$name' has write permissions for low-privilege users" -Severity "HIGH"
    }
}

# ============================================================
Write-Header "REGISTRY — AUTORUN & WEAK PERMISSIONS"
# ============================================================

Write-Check "AutoRun locations"
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $autorunPaths) {
    if (Test-Path $path) {
        $entries = Get-ItemProperty $path
        $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Info "$path -> $($_.Name): $($_.Value)"
            $exePath = $_.Value -replace '"', '' -replace ' .*', ''
            if ($exePath -and (Test-Path $exePath)) {
                $acl = Get-Acl $exePath
                $writable = $acl.Access | Where-Object {
                    $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
                    $_.FileSystemRights -match "Write|FullControl|Modify"
                }
                if ($writable) {
                    Add-Finding -Category "AutoRun" -Title "Writable AutoRun executable" `
                        -Detail "$($_.Name): $exePath" -Severity "HIGH"
                }
            }
        }
    }
}

Write-Check "AlwaysInstallElevated"
$aie1 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated).AlwaysInstallElevated
$aie2 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated).AlwaysInstallElevated
if ($aie1 -eq 1 -and $aie2 -eq 1) {
    Add-Finding -Category "Registry" -Title "AlwaysInstallElevated enabled" `
        -Detail "MSI files are always installed as SYSTEM" -Severity "HIGH"
} else {
    Write-Info "AlwaysInstallElevated not enabled."
}

# ============================================================
Write-Header "SCHEDULED TASKS"
# ============================================================

Write-Check "Scheduled tasks with writable executables"
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
foreach ($task in $tasks) {
    $action = $task.Actions | Where-Object { $_.Execute }
    foreach ($act in $action) {
        $exe = $act.Execute -replace '"', ''
        if (-not $exe -or -not (Test-Path $exe)) { continue }

        $acl = Get-Acl $exe
        $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
            $_.FileSystemRights -match "Write|FullControl|Modify"
        }
        if ($writable) {
            Add-Finding -Category "ScheduledTask" -Title "Writable task executable" `
                -Detail "$($task.TaskName): $exe" -Severity "HIGH"
        }
    }
}

Write-Check "Tasks running as SYSTEM"
foreach ($task in $tasks) {
    $principal = $task.Principal
    if ($principal.UserId -match "SYSTEM|S-1-5-18" -or $principal.RunLevel -eq "Highest") {
        $action = $task.Actions | Where-Object { $_.Execute }
        foreach ($act in $action) {
            $exe = $act.Execute -replace '"', ''
            if ($exe -and (Test-Path $exe)) {
                $acl = Get-Acl $exe
                $writable = $acl.Access | Where-Object {
                    $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
                    $_.FileSystemRights -match "Write|FullControl|Modify"
                }
                if ($writable) {
                    Add-Finding -Category "ScheduledTask" -Title "SYSTEM task with writable executable" `
                        -Detail "$($task.TaskName): $exe" -Severity "HIGH"
                }
            }
        }
    }
}

# ============================================================
Write-Header "PATH HIJACKING"
# ============================================================

Write-Check "Writable directories in system PATH"
$pathDirs = $env:PATH.Split(';') | Where-Object { $_ -ne "" } | Sort-Object -Unique
foreach ($dir in $pathDirs) {
    if (-not (Test-Path $dir)) { continue }
    $acl = Get-Acl $dir
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
        $_.FileSystemRights -match "Write|FullControl|Modify"
    }
    if ($writable) {
        Add-Finding -Category "PATH" -Title "Writable PATH directory" `
            -Detail $dir -Severity "HIGH"
    } else {
        Write-Info "OK: $dir"
    }
}

# ============================================================
Write-Header "STORED CREDENTIALS"
# ============================================================

Write-Check "Windows Credential Manager"
$credOutput = cmdkey /list 2>$null
if ($credOutput -match "Target:") {
    Add-Finding -Category "Credentials" -Title "Stored credentials found" `
        -Detail ($credOutput | Where-Object { $_ -match "Target:|User:" } | Out-String).Trim() -Severity "MEDIUM"
} else {
    Write-Info "No stored credentials in Credential Manager."
}

Write-Check "Passwords in registry (autologon)"
$autoLogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ($autoLogon.DefaultPassword) {
    Add-Finding -Category "Credentials" -Title "Autologon password in registry" `
        -Detail "User: $($autoLogon.DefaultUserName) / Password: $($autoLogon.DefaultPassword)" -Severity "HIGH"
} else {
    Write-Info "No autologon password found."
}

Write-Check "Passwords in environment variables"
$envVars = [System.Environment]::GetEnvironmentVariables()
$sensitivePatterns = @("pass", "pwd", "password", "secret", "key", "token", "cred")
foreach ($key in $envVars.Keys) {
    foreach ($pat in $sensitivePatterns) {
        if ($key -match $pat) {
            Add-Finding -Category "Credentials" -Title "Sensitive environment variable" `
                -Detail "$key = $($envVars[$key])" -Severity "MEDIUM"
        }
    }
}

Write-Check "Unattend.xml / Sysprep files"
$sensitiveFiles = @(
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattended.xml",
    "C:\Windows\System32\sysprep\sysprep.xml",
    "C:\Windows\System32\sysprep\Panther\Unattend.xml",
    "C:\unattend.xml",
    "C:\autounattend.xml"
)
foreach ($f in $sensitiveFiles) {
    if (Test-Path $f) {
        Add-Finding -Category "Credentials" -Title "Sensitive installation file found" `
            -Detail $f -Severity "HIGH"
        $content = Get-Content $f -Raw
        if ($content -match "<Password>|<AdministratorPassword>") {
            Add-Finding -Category "Credentials" -Title "Password found in $f" `
                -Detail "File contains password fields" -Severity "HIGH"
        }
    }
}

# ============================================================
Write-Header "NETWORK & SHARES"
# ============================================================

Write-Check "Local shared folders"
$shares = Get-WmiObject Win32_Share | Where-Object { $_.Type -eq 0 }
foreach ($share in $shares) {
    Write-Info "Share: $($share.Name) -> $($share.Path)"
    if ($share.Path -and (Test-Path $share.Path)) {
        $acl = Get-Acl $share.Path
        $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
            $_.FileSystemRights -match "Write|FullControl|Modify"
        }
        if ($writable) {
            Add-Finding -Category "Share" -Title "Writable share" `
                -Detail "$($share.Name) -> $($share.Path)" -Severity "MEDIUM"
        }
    }
}

Write-Check "Active network connections (listening ports)"
$listeners = netstat -ano | Select-String "LISTENING"
Write-Info "Listening services:"
$listeners | ForEach-Object { Write-Info "  $_" }

# ============================================================
Write-Header "DLL HIJACKING OPPORTUNITIES"
# ============================================================

Write-Check "Writable directories for installed software"
$programDirs = @(
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData
)
foreach ($baseDir in $programDirs) {
    if (-not $baseDir -or -not (Test-Path $baseDir)) { continue }
    Get-ChildItem $baseDir -Directory | ForEach-Object {
        $acl = Get-Acl $_.FullName
        $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
            $_.FileSystemRights -match "Write|FullControl|Modify"
        }
        if ($writable) {
            Add-Finding -Category "DLL Hijack" -Title "Writable program directory" `
                -Detail $_.FullName -Severity "MEDIUM"
        }
    }
}

# ============================================================
Write-Header "LOCAL USERS & GROUPS"
# ============================================================

Write-Check "Local Administrators"
$admins = net localgroup Administrators 2>$null
Write-Info "Members of Administrators:"
$admins | Select-String -Pattern "^(?!--|Alias|Members|Comment|The command|$)" | ForEach-Object {
    Write-Info "  $($_.Line.Trim())"
}

Write-Check "All local users"
$users = Get-LocalUser
foreach ($user in $users) {
    $status   = if ($user.Enabled) { "Active" } else { "Disabled" }
    $pwExpiry = if ($user.PasswordExpires) { $user.PasswordExpires.ToString() } else { "Never" }
    Write-Info "$($user.Name) [$status] — Password expires: $pwExpiry"
    if ($user.Enabled -and -not $user.PasswordRequired) {
        Add-Finding -Category "User" -Title "User with no password required" `
            -Detail $user.Name -Severity "HIGH"
    }
}

# ============================================================
Write-Header "INSTALLED SOFTWARE (potentially vulnerable)"
# ============================================================

Write-Check "32-bit & 64-bit software"
$softwareKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installed = $softwareKeys | ForEach-Object { Get-ItemProperty $_ } |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher |
    Sort-Object DisplayName -Unique

Write-Info "Total installed: $($installed.Count) products"
$installed | ForEach-Object {
    Write-Info "$($_.DisplayName) v$($_.DisplayVersion) ($($_.Publisher))"
}

# ============================================================
Write-Header "SUMMARY"
# ============================================================

Write-Host "`n"
Write-Host ("=" * 70) -ForegroundColor White
Write-Host "  FINDINGS OVERVIEW" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor White

$grouped = $findings | Group-Object Severity
foreach ($group in @("HIGH","MEDIUM","LOW","INFO")) {
    $g = $grouped | Where-Object { $_.Name -eq $group }
    if ($g) {
        $color = switch ($group) {
            "HIGH"   { "Red" }
            "MEDIUM" { "Magenta" }
            "LOW"    { "Yellow" }
            default  { "Green" }
        }
        Write-Host "`n  [$group] — $($g.Count) finding(s):" -ForegroundColor $color
        $g.Group | ForEach-Object {
            Write-Host "    • [$($_.Category)] $($_.Title)" -ForegroundColor $color
            Write-Host "      $($_.Detail)" -ForegroundColor Gray
        }
    }
}

Write-Host "`n"
$highCount   = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$mediumCount = ($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
Write-Host "  Total HIGH:   $highCount" -ForegroundColor Red
Write-Host "  Total MEDIUM: $mediumCount" -ForegroundColor Magenta
Write-Host "  Total other:  $(($findings | Where-Object { $_.Severity -notin 'HIGH','MEDIUM' }).Count)" -ForegroundColor Yellow
Write-Host "`n  Script completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

$exportPath = "$env:TEMP\PrivEscFindings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$findings | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
Write-Host "  Report saved to: $exportPath" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor White
