@ECHO OFF & SETLOCAL EnableDelayedExpansion
TITLE PrivEscCheck - Windows Privilege Escalation Checker
COLOR 0F
CALL :SetOnce

REM ============================================================
REM  PrivEscCheck.bat - Windows Privilege Escalation Checker
REM  Use only on systems you are authorized to test.
REM ============================================================

:Splash
ECHO.
CALL :ColorLine "%E%96m  =====================================================================%E%97m"
CALL :ColorLine "%E%96m   ____       _       _____          ____  _               _"
CALL :ColorLine "%E%96m  |  _ \ _ __(_)_   _| ____|___  ___|  _ \| |__   ___  ___| | __"
CALL :ColorLine "%E%96m  | |_) | '__| \ \ / /  _| / __|/ __| |_) | '_ \ / _ \/ __| |/ /"
CALL :ColorLine "%E%96m  |  __/| |  | |\ V /| |___\__ \ (__|  __/| | | |  __/ (__|   <"
CALL :ColorLine "%E%96m  |_|   |_|  |_| \_/ |_____|___/\___|_|   |_| |_|\___|\___|_|\_\"
CALL :ColorLine "%E%96m  =====================================================================%E%97m"
ECHO.
CALL :ColorLine "  %E%33mWindows Privilege Escalation Checker%E%97m"
CALL :ColorLine "  %E%33mUse only on systems you are authorized to test.%E%97m"
ECHO.
CALL :ColorLine "  %E%41m[!] Advisory: Use only on authorized systems. Misuse is your own responsibility.%E%40;97m"
ECHO.

REM Check for spaces in path
SET "CurrentFolder=%~dp0"
IF "!CurrentFolder!" NEQ "!CurrentFolder: =!" (
    CALL :ColorLine "  %E%91m[ERROR] Path contains spaces - some checks may fail.%E%97m"
    ECHO.
)

REM ============================================================
:SysInfo
REM ============================================================
CALL :T_Progress 0
CALL :SectionHeader "SYSTEM INFORMATION"

CALL :SubHeader "OS VERSION AND PATCH LEVEL"
ECHO.   [i] Check OS version against known local privilege escalation exploits
systeminfo | findstr /i "OS Name OS Version System Type Hotfix"
ECHO.
CALL :T_Progress 2

CALL :SubHeader "INSTALLED HOTFIXES"
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    wmic qfe get HotFixID,InstalledOn,Description 2>nul
) else (
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Update\InstalledUpdates" 2>nul
)
ECHO.

REM Check for unpatched exploitable OS versions
SET expl=no
for /f "tokens=3-9" %%a in ('systeminfo 2^>nul') do (
    ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i "2000 XP 2003 2008 vista" >nul 2>&1 && SET expl=yes
    ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i /C:"windows 7" >nul 2>&1 && SET expl=yes
)
IF "!expl!" == "yes" (
    CALL :ColorLine "  %E%91m[!!!] Legacy OS detected - likely vulnerable to known local exploits!%E%97m"
    wmic qfe get HotFixID 2>nul | findstr /C:"KB3143141" >nul || CALL :ColorLine "  %E%91m[!!!] MS16-032 NOT patched (secondary logon - 2K8/Vista/7)%E%97m"
    wmic qfe get HotFixID 2>nul | findstr /C:"KB2592799" >nul || CALL :ColorLine "  %E%91m[!!!] MS11-080 NOT patched (afd.sys - XP/2K3)%E%97m"
    wmic qfe get HotFixID 2>nul | findstr /C:"KB977165"  >nul || CALL :ColorLine "  %E%91m[!!!] MS10-015 NOT patched (User Mode to Ring)%E%97m"
    wmic qfe get HotFixID 2>nul | findstr /C:"KB2870008" >nul || CALL :ColorLine "  %E%91m[!!!] MS13-081 NOT patched (track_popup_menu - 7SP0/SP1 x86)%E%97m"
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "DATE AND TIME"
date /T & time /T
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ENVIRONMENT VARIABLES"
ECHO.   [i] Look for passwords, tokens, API keys or interesting paths
set
ECHO.
CALL :T_Progress 1

CALL :SubHeader "POWERSHELL VERSIONS"
ECHO.   [i] PS v2 engine can be used to downgrade and bypass logging
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion 2>nul
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" /v PowerShellVersion 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" 2>nul
ECHO.   [i] PS history file:
IF EXIST "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
    CALL :ColorLine "  %E%93m[!!]  PS history found: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt%E%97m"
    type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
) ELSE (
    ECHO.   [-]   Not found.
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:UserInfo
REM ============================================================
CALL :SectionHeader "CURRENT USER AND TOKEN"

CALL :SubHeader "CURRENT USER CONTEXT"
whoami /all
ECHO.
CALL :T_Progress 2

CALL :SubHeader "TOKEN PRIVILEGES - DANGEROUS PRIVILEGES"
ECHO.   [i] SeImpersonatePrivilege  -> Potato attacks (PrintSpoofer / GodPotato)
ECHO.   [i] SeBackupPrivilege       -> Read any file including SAM/SYSTEM
ECHO.   [i] SeRestorePrivilege      -> Write any file
ECHO.   [i] SeDebugPrivilege        -> Inject into any process (LSASS dump)
ECHO.   [i] SeLoadDriverPrivilege   -> Load malicious kernel driver
ECHO.   [i] SeTakeOwnershipPrivilege-> Take ownership of any object
ECHO.   [i] SeAssignPrimaryTokenPrivilege -> Token swapping for SYSTEM
ECHO.
whoami /priv 2>nul | findstr /i "Enabled"
ECHO.
whoami /priv 2>nul | findstr /i "SeImpersonatePrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeLoadDriverPrivilege SeTakeOwnershipPrivilege SeAssignPrimaryTokenPrivilege SeCreateTokenPrivilege SeTcbPrivilege SeManageVolumePrivilege" | findstr /i "Enabled" && (
    CALL :ColorLine "  %E%91m[!!!] Dangerous privilege is ENABLED - check above output!%E%97m"
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "ALL LOCAL USERS"
net user
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ADMINISTRATORS GROUP"
net localgroup Administrators 2>nul
net localgroup Administradores 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ALL LOCAL GROUPS"
net localgroup
ECHO.
CALL :T_Progress 1

CALL :SubHeader "CURRENTLY LOGGED ON USERS"
quser 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "KERBEROS TICKETS"
klist 2>nul
ECHO.
CALL :T_Progress 1

REM ============================================================
:UACConfig
REM ============================================================
CALL :SectionHeader "UAC CONFIGURATION"

CALL :SubHeader "UAC REGISTRY SETTINGS"
ECHO.   [i] EnableLUA=0 means UAC is fully disabled
ECHO.   [i] ConsentPromptBehaviorAdmin=0 means no prompt for admins (auto-elevate)
ECHO.   [i] LocalAccountTokenFilterPolicy=1 means PtH with local admin accounts works
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control.html
ECHO.
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy 2>nul
ECHO.

FOR /F "tokens=3" %%a IN ('REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2^>nul ^| findstr EnableLUA') DO (
    IF "%%a"=="0x0" CALL :ColorLine "  %E%91m[!!!] UAC is DISABLED (EnableLUA = 0)%E%97m"
)
FOR /F "tokens=3" %%a IN ('REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2^>nul ^| findstr ConsentPromptBehaviorAdmin') DO (
    IF "%%a"=="0x0" CALL :ColorLine "  %E%91m[!!!] No UAC prompt for admins (auto-elevate without consent)%E%97m"
)
FOR /F "tokens=3" %%a IN ('REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy 2^>nul ^| findstr LocalAccountTokenFilterPolicy') DO (
    IF "%%a"=="0x1" CALL :ColorLine "  %E%91m[!!!] LocalAccountTokenFilterPolicy=1 - PtH with local admins possible%E%97m"
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "LSASS PROTECTION (PPL)"
ECHO.   [i] RunAsPPL=1 means LSASS is a Protected Process - harder to dump
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "CREDENTIAL GUARD"
ECHO.   [i] Active if LsaCfgFlags is 1 or 2
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "WDIGEST PLAINTEXT CACHING"
ECHO.   [i] UseLogonCredential=1 means plaintext passwords are cached in LSASS memory
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>nul
FOR /F "tokens=3" %%a IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2^>nul ^| findstr UseLogonCredential') DO (
    IF "%%a"=="0x1" CALL :ColorLine "  %E%91m[!!!] WDigest enabled - mimikatz can dump cleartext passwords from LSASS!%E%97m"
)
ECHO.
CALL :T_Progress 1

CALL :SubHeader "CACHED DOMAIN LOGONS"
ECHO.   [i] Cached credentials can be cracked offline if you have SYSTEM access
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "LAPS (LOCAL ADMIN PASSWORD SOLUTION)"
REG QUERY "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul && (
    CALL :ColorLine "  %E%93m[!!]  Legacy LAPS is installed%E%97m"
)
REG QUERY "HKLM\Software\Microsoft\Policies\LAPS" /v BackupDirectory 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" /v BackupDirectory 2>nul
ECHO.
CALL :T_Progress 1

REM ============================================================
:Services
REM ============================================================
CALL :SectionHeader "SERVICES - UNQUOTED PATHS"

CALL :SubHeader "SERVICES WITH UNQUOTED EXECUTABLE PATHS"
ECHO.   [i] Windows resolves 'C:\Program Files\App\service.exe' as:
ECHO.   [i]   1. C:\Program.exe  2. C:\Program Files\App.exe  3. full path
ECHO.   [i] Drop a binary at an earlier resolved path to hijack execution
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services
ECHO.
for /f "tokens=2" %%n in ('sc query state^= all ^| findstr SERVICE_NAME') do (
    for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" 2^>nul ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
        ECHO.%%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (
            CALL :ColorLine "  %E%93m[!!]  Unquoted: %%n%E%97m"
            ECHO.         Path: %%~s
            icacls "%%~s" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
                CALL :ColorLine "  %E%91m[!!!] Writable path segment found above!%E%97m"
            )
            ECHO.
        )
    )
)
CALL :T_Progress 3

REM ============================================================
:ServicePerms
REM ============================================================
CALL :SectionHeader "SERVICES - WEAK PERMISSIONS"

CALL :SubHeader "WRITABLE SERVICE EXECUTABLES"
ECHO.   [i] If you can write the binary a service runs, replace it with your payload
ECHO.
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2 delims='='" %%a in ('wmic service list full ^| findstr /i "pathname" ^| findstr /i /v "system32"') do (
        for /f eol^=^"^ delims^=^" %%b in ("%%a") do (
            icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
                CALL :ColorLine "  %E%91m[!!!] Writable service binary: %%b%E%97m"
                ECHO.
            )
        )
    )
) else (
    ECHO.   [-]   wmic not available - skipping binary permission check
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "SERVICE REGISTRY KEY PERMISSIONS"
ECHO.   [i] If you can modify a service registry key you can change its binary path
ECHO.
for /f %%a in ('reg query hklm\system\currentcontrolset\services 2^>nul') do (
    del %TEMP%\reg_test.hiv >nul 2>&1
    reg save %%a %TEMP%\reg_test.hiv >nul 2>&1 && reg restore %%a %TEMP%\reg_test.hiv >nul 2>&1 && (
        CALL :ColorLine "  %E%91m[!!!] You can modify registry key: %%a%E%97m"
    )
)
del %TEMP%\reg_test.hiv >nul 2>&1
ECHO.
CALL :T_Progress 2

CALL :SubHeader "SERVICES RUNNING AS SYSTEM"
ECHO.   [i] SYSTEM services with non-Windows binaries are high-value targets
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    wmic service get name,startname,pathname 2>nul | findstr /i "LocalSystem" | findstr /i /v "System32"
) else (
    sc query state= all 2>nul | findstr SERVICE_NAME
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:AutoRun
REM ============================================================
CALL :SectionHeader "REGISTRY - AUTORUN AND PERSISTENCE"

CALL :SubHeader "AUTORUN REGISTRY KEYS"
ECHO.   [i] Binaries listed here run on startup - check if any are writable
ECHO.
CALL :ColorLine "  %E%33m[-] HKLM\...\Run%E%97m"
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
CALL :ColorLine "  %E%33m[-] HKLM\...\RunOnce%E%97m"
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
CALL :ColorLine "  %E%33m[-] HKCU\...\Run%E%97m"
REG QUERY "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
CALL :ColorLine "  %E%33m[-] HKCU\...\RunOnce%E%97m"
REG QUERY "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
CALL :ColorLine "  %E%33m[-] Wow6432Node Run%E%97m"
REG QUERY "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" 2>nul
ECHO.
CALL :T_Progress 2

CALL :SubHeader "STARTUP FOLDER PERMISSIONS"
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
    CALL :ColorLine "  %E%91m[!!!] All-users startup folder is writable!%E%97m"
)
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
    CALL :ColorLine "  %E%91m[!!!] User startup folder is writable!%E%97m"
)
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ALWAYSINSTALLELEVATED"
ECHO.   [i] If both keys are 1, any .msi runs as SYSTEM - generate with msfvenom
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated-1
REG QUERY "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul
FOR /F "tokens=3" %%a IN ('REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2^>nul ^| findstr AlwaysInstallElevated') DO (
    IF "%%a"=="0x1" CALL :ColorLine "  %E%91m[!!!] AlwaysInstallElevated is ENABLED on HKLM!%E%97m"
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "AUDIT AND LOGGING SETTINGS"
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" 2>nul
ECHO.
CALL :T_Progress 1

REM ============================================================
:SchedTasks
REM ============================================================
CALL :SectionHeader "SCHEDULED TASKS"

CALL :SubHeader "ALL ENABLED SCHEDULED TASKS"
ECHO.   [i] Look for tasks running as SYSTEM with writable binary paths
schtasks /query /fo LIST /v 2>nul | findstr /i "TaskName Status Run As Task To Run" | findstr /v "N/A"
ECHO.
CALL :T_Progress 2

CALL :SubHeader "SCHEDULED TASK BINARY PERMISSIONS"
ECHO.   [i] Checking if task executables are writable...
for /f "tokens=*" %%t in ('schtasks /query /fo CSV /nh 2^>nul') do (
    for /f "tokens=2 delims=," %%s in ("%%t") do (
        SET "taskbin=%%~s"
        IF EXIST "!taskbin!" (
            icacls "!taskbin!" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
                CALL :ColorLine "  %E%91m[!!!] Writable task binary: !taskbin!%E%97m"
            )
        )
    )
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:PathHijack
REM ============================================================
CALL :SectionHeader "PATH HIJACKING"

CALL :SubHeader "WRITABLE DIRECTORIES IN SYSTEM PATH"
ECHO.   [i] Drop a malicious binary with the same name as a legitimate one in a writable PATH dir
ECHO.
for %%A in ("%path:;=";"%") do (
    icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
        CALL :ColorLine "  %E%91m[!!!] Writable PATH directory: %%~A%E%97m"
        ECHO.
    )
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:DLLHijack
REM ============================================================
CALL :SectionHeader "DLL HIJACKING"

CALL :SubHeader "WRITABLE APPLOCKER BYPASS DIRECTORIES"
ECHO.   [i] These directories are often in allowed AppLocker paths and may be writable
for %%D in (
    "C:\Windows\Tasks"
    "C:\Windows\Temp"
    "C:\Windows\tracing"
    "C:\Windows\System32\FxsTmp"
    "C:\Windows\System32\com\dmp"
    "C:\Windows\System32\spool\PRINTERS"
    "C:\Windows\System32\spool\drivers\color"
    "C:\Windows\SysWOW64\FxsTmp"
    "C:\Windows\SysWOW64\com\dmp"
) do (
    icacls %%D 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
        CALL :ColorLine "  %E%93m[!!]  Writable bypass dir: %%~D%E%97m"
    )
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "WRITABLE PROGRAM DIRECTORIES"
ECHO.   [i] Writable app directories may allow DLL planting
for /f "tokens=*" %%d in ('dir /b "C:\Program Files" 2^>nul') do (
    icacls "C:\Program Files\%%d" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
        CALL :ColorLine "  %E%93m[!!]  Writable: C:\Program Files\%%d%E%97m"
    )
)
for /f "tokens=*" %%d in ('dir /b "C:\Program Files (x86)" 2^>nul') do (
    icacls "C:\Program Files (x86)\%%d" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
        CALL :ColorLine "  %E%93m[!!]  Writable: C:\Program Files (x86)\%%d%E%97m"
    )
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:Credentials
REM ============================================================
CALL :SectionHeader "STORED CREDENTIALS"

CALL :SubHeader "WINDOWS CREDENTIAL MANAGER"
ECHO.   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault
cmdkey /list
ECHO.
CALL :T_Progress 1

CALL :SubHeader "AUTOLOGON CREDENTIALS IN REGISTRY"
ECHO.   [i] Plaintext password may be stored for automatic login
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultPassword LastUsedUsername"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "UNATTEND.XML AND SYSPREP FILES"
ECHO.   [i] These files may contain plaintext administrator passwords
IF EXIST "%WINDIR%\sysprep\sysprep.xml"                          CALL :ColorLine "  %E%91m[!!!] %WINDIR%\sysprep\sysprep.xml%E%97m"
IF EXIST "%WINDIR%\sysprep\sysprep.inf"                          CALL :ColorLine "  %E%91m[!!!] %WINDIR%\sysprep\sysprep.inf%E%97m"
IF EXIST "%WINDIR%\Panther\Unattended.xml"                       CALL :ColorLine "  %E%91m[!!!] %WINDIR%\Panther\Unattended.xml%E%97m"
IF EXIST "%WINDIR%\Panther\Unattend.xml"                         CALL :ColorLine "  %E%91m[!!!] %WINDIR%\Panther\Unattend.xml%E%97m"
IF EXIST "%WINDIR%\Panther\Unattend\Unattend.xml"                CALL :ColorLine "  %E%91m[!!!] %WINDIR%\Panther\Unattend\Unattend.xml%E%97m"
IF EXIST "%WINDIR%\System32\Sysprep\unattend.xml"                CALL :ColorLine "  %E%91m[!!!] %WINDIR%\System32\Sysprep\unattend.xml%E%97m"
IF EXIST "C:\unattend.xml"                                        CALL :ColorLine "  %E%91m[!!!] C:\unattend.xml%E%97m"
IF EXIST "C:\autounattend.xml"                                    CALL :ColorLine "  %E%91m[!!!] C:\autounattend.xml%E%97m"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "SAM AND SYSTEM BACKUP COPIES"
ECHO.   [i] Backup hives can be dumped offline with impacket-secretsdump
IF EXIST "%WINDIR%\repair\SAM"                          CALL :ColorLine "  %E%91m[!!!] %WINDIR%\repair\SAM exists!%E%97m"
IF EXIST "%WINDIR%\repair\SYSTEM"                       CALL :ColorLine "  %E%91m[!!!] %WINDIR%\repair\SYSTEM exists!%E%97m"
IF EXIST "%WINDIR%\System32\config\RegBack\SAM"         CALL :ColorLine "  %E%91m[!!!] %WINDIR%\System32\config\RegBack\SAM exists!%E%97m"
IF EXIST "%WINDIR%\System32\config\RegBack\SYSTEM"      CALL :ColorLine "  %E%91m[!!!] %WINDIR%\System32\config\RegBack\SYSTEM exists!%E%97m"
IF EXIST "%WINDIR%\System32\config\RegBack\SECURITY"    CALL :ColorLine "  %E%91m[!!!] %WINDIR%\System32\config\RegBack\SECURITY exists!%E%97m"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "GPP CPASSWORD FILES"
ECHO.   [i] Group Policy Preferences stored passwords are AES encrypted with a known public key
dir /s/b "%SystemDrive%\Microsoft\Group Policy\history\Groups.xml" 2>nul && CALL :ColorLine "  %E%91m[!!!] Groups.xml found - check for cpassword attribute!%E%97m"
dir /s/b Groups.xml Services.xml Scheduledtasks.xml DataSources.xml Printers.xml Drives.xml 2>nul | findstr /v "\\WinSxS\\"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "REGISTRY CREDENTIALS (VNC, PUTTY, WINLOGON)"
ECHO.Looking inside HKCU\Software\ORL\WinVNC3
REG QUERY "HKCU\Software\ORL\WinVNC3\Password" 2>nul
ECHO.Looking inside HKLM\SOFTWARE\RealVNC\WinVNC4
REG QUERY "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul
ECHO.Looking inside HKCU\Software\TightVNC\Server
REG QUERY "HKCU\Software\TightVNC\Server" 2>nul
ECHO.Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
REG QUERY "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul
ECHO.Looking inside HKCU\Software\OpenSSH\Agent\Keys
REG QUERY "HKCU\Software\OpenSSH\Agent\Keys" /s 2>nul
ECHO.Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s 2>nul
ECHO.
CALL :T_Progress 2

CALL :SubHeader "DPAPI MASTER KEYS"
ECHO.   [i] Use mimikatz dpapi::masterkey /rpc to decrypt
dir /b/a "%APPDATA%\Microsoft\Protect\" 2>nul
dir /b/a "%LOCALAPPDATA%\Microsoft\Protect\" 2>nul
ECHO.Credential blobs:
dir /b/a "%APPDATA%\Microsoft\Credentials\" 2>nul
dir /b/a "%LOCALAPPDATA%\Microsoft\Credentials\" 2>nul
ECHO.
CALL :T_Progress 2

CALL :SubHeader "INTERESTING FILES"
ECHO.   [i] Searching for credential files on common locations
dir /s/b /A:-D "%USERPROFILE%\Desktop\*pass*" "%USERPROFILE%\Desktop\*cred*" 2>nul
dir /s/b /A:-D "%USERPROFILE%\Documents\*pass*" "%USERPROFILE%\Documents\*cred*" 2>nul
dir /s/b /A:-D "C:\Users\Public\*pass*" "C:\Users\Public\*cred*" 2>nul
dir /s/b /A:-D RDCMan.settings *.rdg *.kdbx *.pfx *.pem id_rsa id_dsa *.ovpn 2>nul | findstr /v "\\WinSxS\\"
ECHO.
CALL :T_Progress 2

CALL :SubHeader "CLOUD CREDENTIALS"
cd "%SystemDrive%\Users" 2>nul
dir /s/b .aws credentials gcloud credentials.db access_tokens.db .azure accessTokens.json azureProfile.json 2>nul
ECHO.
CALL :T_Progress 1

REM ============================================================
:Network
REM ============================================================
CALL :SectionHeader "NETWORK AND SHARES"

CALL :SubHeader "CURRENT NETWORK SHARES"
net share
ECHO.
CALL :T_Progress 1

CALL :SubHeader "NETWORK INTERFACES"
ipconfig /all
ECHO.
CALL :T_Progress 1

CALL :SubHeader "LISTENING PORTS"
ECHO.   [i] Internal services may be accessible from localhost only
netstat -ano | findstr /i "LISTENING"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ARP TABLE"
arp -A
ECHO.
CALL :T_Progress 1

CALL :SubHeader "ROUTING TABLE"
route print
ECHO.
CALL :T_Progress 1

CALL :SubHeader "FIREWALL CONFIGURATION"
netsh firewall show state 2>nul
netsh advfirewall show allprofiles 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "HOSTS FILE"
type "%WINDIR%\System32\drivers\etc\hosts" 2>nul | findstr /v "^#"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "DNS CACHE"
ipconfig /displaydns 2>nul | findstr "Record" | findstr "Name Host"
ECHO.
CALL :T_Progress 1

CALL :SubHeader "WLAN SAVED CREDENTIALS"
ECHO.   [i] Retrieving plaintext WLAN keys...
for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles 2^>nul ^| findstr "Profile "') do (
    netsh wlan show profiles name="%%a" key=clear 2>nul | findstr /i "SSID Cipher Content" | findstr /v "Number" && ECHO.
)
ECHO.
CALL :T_Progress 2

CALL :SubHeader "WSUS MISCONFIGURATION"
ECHO.   [i] HTTP WSUS (non-SSL) can be abused with WSUXploit
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" 2>nul | findstr /i "wuserver" | findstr /i "http://" && (
    CALL :ColorLine "  %E%91m[!!!] WSUS configured over HTTP - possible WSUS injection attack!%E%97m"
)
ECHO.
CALL :T_Progress 1

REM ============================================================
:Processes
REM ============================================================
CALL :SectionHeader "RUNNING PROCESSES"

CALL :SubHeader "ALL RUNNING PROCESSES"
ECHO.   [i] Look for custom/unusual software, non-standard service hosts
tasklist /SVC
ECHO.
CALL :T_Progress 2

CALL :SubHeader "WRITABLE PROCESS BINARIES"
ECHO.   [i] If you can replace a running process binary it may be re-used by an admin
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2 delims='='" %%x in ('wmic process list full ^| findstr /i "executablepath" ^| findstr /i /v "system32" ^| findstr ":"') do (
        for /f eol^=^"^ delims^=^" %%z in ('ECHO.%%x') do (
            icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && (
                CALL :ColorLine "  %E%91m[!!!] Writable process binary: %%z%E%97m"
                ECHO.
            )
        )
    )
)
ECHO.
CALL :T_Progress 2

REM ============================================================
:AVCheck
REM ============================================================
CALL :SectionHeader "ANTIVIRUS AND DEFENDER"

CALL :SubHeader "REGISTERED ANTIVIRUS PRODUCTS"
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState /Format:List 2>nul
) else (
    ECHO.   [-]   wmic not available - check Task Manager for AV
)
ECHO.
CALL :T_Progress 1

CALL :SubHeader "WINDOWS DEFENDER EXCLUSIONS"
ECHO.   [i] Exclusion paths are safe zones to drop payloads
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 2>nul && (
    CALL :ColorLine "  %E%93m[!!]  Defender path exclusions found - use as payload drop location!%E%97m"
)
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" 2>nul
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" 2>nul
ECHO.
CALL :T_Progress 1

CALL :SubHeader "APPLOCKER POLICY"
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" 2>nul | findstr /i "Exe Msi Script Dll Appx" && (
    CALL :ColorLine "  %E%93m[!!]  AppLocker rules exist - check bypass dirs above%E%97m"
) || (
    CALL :ColorLine "  %E%92m[+]   No AppLocker policy found - all executables allowed%E%97m"
)
ECHO.
CALL :T_Progress 1

REM ============================================================
:Software
REM ============================================================
CALL :SectionHeader "INSTALLED SOFTWARE"

CALL :SubHeader "INSTALLED APPLICATIONS"
ECHO.   [i] Look for outdated or unusual software with known CVEs
dir /b "C:\Program Files" "C:\Program Files (x86)" 2>nul | sort
ECHO.
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /i "DisplayName DisplayVersion" | findstr /v "(Default)"
ECHO.
IF EXIST "C:\Windows\CCM\SCClient.exe" CALL :ColorLine "  %E%93m[!!]  SCCM is installed - installers run as SYSTEM, check for DLL sideloading!%E%97m"
IF EXIST "%systemroot%\system32\inetsrv\appcmd.exe" CALL :ColorLine "  %E%93m[!!]  appcmd.exe found - may contain IIS credentials%E%97m"
IF EXIST "%LOCALAPPDATA%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" CALL :ColorLine "  %E%91m[!!!] RDCMan settings found - check .rdg files for credentials%E%97m"
ECHO.
CALL :T_Progress 2

CALL :SubHeader "MOUNTED DRIVES"
where wmic >nul 2>&1
if %ERRORLEVEL% equ 0 (
    wmic logicaldisk get caption,description,filesystem,freespace,size 2>nul
) else (
    fsutil fsinfo drives 2>nul
)
ECHO.
CALL :T_Progress 1

CALL :SubHeader "CLIPBOARD CONTENTS"
ECHO.   [i] Any passwords in clipboard?
REM Native clipboard access without powershell via clip trick
ECHO. | clip 2>nul
REG QUERY "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" 2>nul
ECHO.
CALL :T_Progress 1

REM ============================================================
:Done
REM ============================================================
CALL :SectionHeader "SCAN COMPLETE"
CALL :ColorLine "%E%96m  Check %TEMP% for any output files you may have saved.%E%97m"
CALL :ColorLine "%E%96m  Review all [!!!] HIGH and [!!] MEDIUM findings above.%E%97m"
ECHO.
CALL :ColorLine "  %E%92m[+] PrivEscCheck.bat finished at: %DATE% %TIME%%E%97m"
ECHO.
ECHO.---
PAUSE >NUL
EXIT /B

REM ============================================================
REM  SUBROUTINES
REM ============================================================

:SetOnce
for /F %%a in ('echo prompt $E ^| cmd') do SET "ESC=%%a"
SET "E=%ESC%["
SET "PercentageTrack=0"
EXIT /B

:T_Progress
SET "Percentage=%~1"
SET /A "PercentageTrack=PercentageTrack+Percentage"
TITLE PrivEscCheck - Scanning... !PercentageTrack!%%
EXIT /B

:SectionHeader
ECHO.
CALL :ColorLine "%E%96m======================================================================%E%97m"
CALL :ColorLine "%E%96m  [*] %~1%E%97m"
CALL :ColorLine "%E%96m======================================================================%E%97m"
EXIT /B

:SubHeader
ECHO.
CALL :ColorLine " %E%33m[+] %~1%E%97m"
EXIT /B

:ColorLine
SET "CurrentLine=%~1"
ECHO.!CurrentLine!
EXIT /B
