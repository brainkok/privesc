# Check for members of the local Administrators group
function Check-LocalAdmins {
    Write-Output "Checking local Administrators group members..."
    Get-LocalGroupMember -Group "Administrators"
}

# Check for weak permissions on sensitive files
function Check-WeakPermissions {
    $filesToCheck = @("C:\Windows\System32\config\SAM", "C:\Windows\System32\config\SYSTEM")
    foreach ($file in $filesToCheck) {
        Write-Output "Checking permissions on $file..."
        Get-Acl $file | Format-List
    }
}

# Check for unquoted service paths
function Check-UnquotedServicePaths {
    Write-Output "Checking for unquoted service paths..."
    $services = Get-WmiObject win32_service | Where-Object { $_.StartMode -eq "Auto" }
    foreach ($service in $services) {
        if ($service.PathName -match '^[^"]+\s+[^"]+') {
            Write-Output "Unquoted service path found: $($service.DisplayName) - $($service.PathName)"
        }
    }
}

# Check for services with weak permissions
function Check-WeakServicePermissions {
    Write-Output "Checking for services with weak permissions..."
    $services = Get-WmiObject win32_service
    foreach ($service in $services) {
        $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $acl.Access | Where-Object { $_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" }
    }
}

# Check for weak registry permissions
function Check-WeakRegistryPermissions {
    $registryPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
    foreach ($path in $registryPaths) {
        Write-Output "Checking registry permissions on $path..."
        $acl = Get-Acl $path
        $acl.Access | Where-Object { $_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -notlike "BUILTIN\Administrators" }
    }
}

# Check User Account Control (UAC) settings
function Check-UACSettings {
    Write-Output "Checking UAC settings..."
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -Property ConsentPromptBehaviorAdmin, EnableLUA, PromptOnSecureDesktop
}

# Check for scheduled tasks with weak permissions
function Check-ScheduledTasks {
    Write-Output "Checking scheduled tasks with weak permissions..."
    schtasks /query /fo LIST /v | Select-String "TaskName","Run As User","Scheduled Task State","Task To Run"
}

# Check for always installed elevated applications
function Check-AlwaysInstalledElevated {
    Write-Output "Checking for AlwaysInstalledElevated applications..."
    $paths = @("HKCU:\Software\Policies\Microsoft\Windows\Installer", "HKLM:\Software\Policies\Microsoft\Windows\Installer")
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path | Select-Object -Property AlwaysInstallElevated
    }
}

# Execute checks
Check-LocalAdmins
Check-WeakPermissions
Check-UnquotedServicePaths
Check-WeakServicePermissions
Check-WeakRegistryPermissions
Check-UACSettings
Check-ScheduledTasks
Check-AlwaysInstalledElevated
