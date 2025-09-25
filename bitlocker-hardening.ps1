<#
BitLocker hardening script
Run in 64-bit PowerShell as Administrator.

- Ensures a recovery protector is present and backed up.
- Enables BitLocker.
- Adds TPM+PIN and can remove TPM-only protectors afterwards.
#>

param(
    [Alias('d')][string]$MountPoint = "C:",
    [int[]]$PCRsToEnable = @(0,2,4,7,11),
    [int]$MinPinLength = 8,
    [bool]$RequireADBackup = $false,
    [string]$BackupFolder = "C:\ProgramData\BitLocker_Backup",
    [int]$EncryptionStartTimeoutMinutes = 10,
    [bool]$RequireTpmPin = $true,
    [string]$ChoiceFileName = "bitlocker_choice.json"
)

# Prompt helper: ask a yes/no question, return $true for 'y'
function Ask-YesNo {
    param(
        [string]$Prompt,
        [ValidateSet('y','n')][string]$Default = 'y'
    )
    $display = if ($Default -eq 'y') { 'Y/n' } else { 'y/N' }
    $resp = Read-Host "$Prompt ($display)"
    if ($resp -eq '') { $resp = $Default }
    return ($resp.Trim().ToLower() -eq 'y')
}

# Ensure the backup folder exists
function Ensure-BackupFolder {
    param($folder)
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
}

# Save text to a file (returns $true on success)
function Save-TextToFile {
    param($text, $path)
    try {
        $text | Out-File -FilePath $path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning ("Failed to write to {0}: {1}" -f $path, $_.Exception.Message)
        return $false
    }
}

# Save manage-bde protectors output to a timestamped file and return file path and text
function Save-ManageBdeProtectorsText {
    param($MountPoint)
    try {
        Ensure-BackupFolder -folder $BackupFolder | Out-Null
        $text = & manage-bde.exe -protectors -get $MountPoint 2>&1
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $file = Join-Path -Path $BackupFolder -ChildPath ("ManageBDE_Protectors_$stamp.txt")
        Save-TextToFile -text $text -path $file | Out-Null
        return $file, $text
    } catch {
        Log ("Failed to capture manage-bde protectors text: {0}" -f $_.Exception.Message)
        return $null, $null
    }
}

# Extract a 48-digit recovery password (formatted with dashes) from text
function Extract-RecoveryPasswordFromText {
    param($text)
    if (-not $text) { return $null }
    $m = [regex]::Match($text, '\b(\d{6}(?:-\d{6}){7})\b')
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

# Simple logger that writes timestamped messages to a logfile in the backup folder
function Log {
    param([string]$m)
    try {
        if (-not (Test-Path $BackupFolder)) { Ensure-BackupFolder -folder $BackupFolder | Out-Null }
        if (-not $global:LogFile) { $global:LogFile = Join-Path $BackupFolder ("bitlocker_script_$(Get-Date -Format yyyyMMdd_HHmmss).log") }
        $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$t - $m" | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
    } catch { }
}

# Poll the BitLocker volume until encryption or active protection is detected, or timeout
function Wait-ForEncryptionStart {
    param(
        [string]$MountPoint = "C:",
        [int]$TimeoutMinutes = 10
    )
    $end = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $end) {
        try {
            $vol = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
            if ($null -eq $vol) { Start-Sleep -Seconds 3; continue }
            if ($vol.ProtectionStatus -eq 1 -or ($vol.EncryptionPercentage -ne $null -and $vol.EncryptionPercentage -gt 0)) {
                return $true
            }
            if ($vol.VolumeStatus -and ($vol.VolumeStatus -match 'Encryption' -or $vol.VolumeStatus -match 'Encrypt')) {
                return $true
            }
        } catch { }
        Start-Sleep -Seconds 6
    }
    return $false
}

# Heuristic check for hardware encryption support using manage-bde output
function Test-HardwareEncryptionSupported {
    param([string]$MountPoint = "C:")
    try {
        $out = & manage-bde.exe -status $MountPoint 2>&1
        if (-not $out) { return $false }
        $joined = $out -join "`n"
        if ($joined -match 'Hardware encryption' -or $joined -match 'HardwareEncrypted' -or $joined -match 'Hardware encryption:\s*Yes') {
            return $true
        }
        if ($joined -match 'Hardware encryption:\s*No' -or $joined -match 'Not hardware') {
            return $false
        }
        if ($joined -match 'Hardware' -and $joined -match 'encryption') {
            return $true
        }
        return $false
    } catch {
        Log ("Test-HardwareEncryptionSupported failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

# ---------- Start ----------
Write-Host "`nIMPORTANT: This script changes BitLocker protectors and policies and can affect access to your data." -ForegroundColor Red
Write-Host "Make a copy of the recovery password and store it offline (USB, printed, or an offline password manager) before rebooting or removing protectors." -ForegroundColor Red
Write-Host "Flow: 1) create/save recovery protector  2) enable BitLocker  3) after encryption finishes re-run to add TPM+PIN." -ForegroundColor Yellow

$consent = Read-Host "Do you understand and accept the risk? Type 'y' to continue"
if ($consent -ne 'y') {
    Write-Host "Aborting. No changes were made." -ForegroundColor Cyan
    return
}

# Basic environment checks
Write-Host "`n== Sanity checks ==" -ForegroundColor Cyan
Write-Host "PROCESSOR_ARCHITECTURE = $($env:PROCESSOR_ARCHITECTURE)"
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") { Write-Warning "Please run 64-bit PowerShell as Administrator." }
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You are not running as Administrator. Re-run elevated."
}

# Check Secure Boot state (if available)
try {
    $sb = & { Confirm-SecureBootUEFI } 2>$null
    if ($null -ne $sb) { Write-Output "Secure Boot enabled: $($sb.ToString())" }
} catch { }

# Prepare backup folder and restrict access
Ensure-BackupFolder -folder $BackupFolder | Out-Null
try {
    $acl = Get-Acl -Path $BackupFolder
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    [void]$acl.AddAccessRule($rule1)
    [void]$acl.AddAccessRule($rule2)
    Set-Acl -Path $BackupFolder -AclObject $acl | Out-Null
    Log ("Backup folder ensured and ACL restricted: {0}" -f $BackupFolder)
    Write-Output "Backup folder ensured and ACL restricted: $BackupFolder"
} catch {
    Write-Warning ("Failed to set strict ACL on {0}: {1}" -f $BackupFolder, $_.Exception.Message)
    Log ("Warning: could not set ACL on {0}" -f $BackupFolder)
}

# Load saved encryption preference if present
$choiceFile = Join-Path -Path $BackupFolder -ChildPath $ChoiceFileName
$useSoftware = $null
if (Test-Path $choiceFile) {
    try {
        $json = Get-Content -Path $choiceFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        if ($json -and $json.useSoftware -ne $null) {
            $useSoftware = [bool]$json.useSoftware
            Write-Output "Using previously saved encryption preference."
        }
    } catch {
        Write-Warning "Failed to read saved choice file; will prompt for encryption preference." -ForegroundColor Yellow
        $useSoftware = $null
    }
}

# TPM readiness check
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm) {
        if (-not $tpm.TpmReady) {
            Write-Warning "TPM detected but not ready/activated. Ensure TPM is enabled and activated in firmware."
            Log "TPM present but not ready."
        } else {
            Write-Output "TPM present."
            Log "TPM ready."
        }
    }
} catch {
    Write-Warning ("Get-Tpm unavailable or no TPM present: {0}" -f $_.Exception.Message)
    Log ("No TPM or Get-Tpm failed: {0}" -f $_.Exception.Message)
}

# Prompt for encryption preference if no saved choice
if ($useSoftware -eq $null) {
    Write-Host "`nBy default this script will prefer software encryption (recommended for compatibility)." -ForegroundColor Cyan
    Write-Host "Hardware encryption can offer benefits, but not all drives or firmware expose it reliably." -ForegroundColor Yellow
    $ans = Ask-YesNo "Do you want to prefer software encryption?" -Default 'y'
    $useSoftware = $ans

    # If user chose hardware, validate capability
    if (-not $useSoftware) {
        $hwSupported = Test-HardwareEncryptionSupported -MountPoint $MountPoint
        if (-not $hwSupported) {
            Write-Host "`nThis drive does not appear to support hardware-based encryption (or the capability could not be detected)." -ForegroundColor Yellow
            $hwChoice = Ask-YesNo "Switch to software encryption instead? (Choose 'n' to cancel the run)" -Default 'y'
            if ($hwChoice) {
                $useSoftware = $true
                Write-Host "Switching to software encryption as requested." -ForegroundColor Cyan
            } else {
                Write-Host "User cancelled due to lack of hardware encryption support. Exiting." -ForegroundColor Cyan
                return
            }
        } else {
            Write-Host "Drive appears to support hardware encryption. Saving preference." -ForegroundColor Cyan
        }
    }

    try {
        @{ useSoftware = $useSoftware } | ConvertTo-Json | Set-Content -Path $choiceFile -Encoding UTF8 -Force
        Write-Host "Saved encryption preference to choice file." -ForegroundColor Cyan
    } catch {
        Write-Warning ("Failed to save choice file: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Output "`nSkipping encryption preference prompt (already set)."
}
$forceSoftware = $useSoftware

# Policy registry keys
Write-Host "`n== Ensuring local BitLocker policy registry keys ==" -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

$policyChanged = $false
function Ensure-RegDword {
    param($path, $name, $desired)
    try {
        $prop = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        $current = $null
        if ($prop -and $prop.PSObject.Properties.Name -contains $name) { $current = $prop."$name" }
    } catch { $current = $null }
    if ($current -ne $desired) {
        Set-ItemProperty -Path $path -Name $name -Value $desired -Type DWord -Force | Out-Null
        $script:policyChanged = $true
        Write-Host "Set $name = $desired" -ForegroundColor Green
    } else {
        Write-Host "Registry $name already = $desired, skipping." -ForegroundColor Cyan
    }
}

Ensure-RegDword -path $regPath -name "UseEnhancedPin" -desired 1
Ensure-RegDword -path $regPath -name "MinimumPIN" -desired $MinPinLength
Ensure-RegDword -path $regPath -name "UseAdvancedStartup" -desired 1

if ($forceSoftware) {
    Ensure-RegDword -path $regPath -name "OSHardwareEncryption" -desired 0
    Ensure-RegDword -path $regPath -name "OSAllowSoftwareEncryptionFailover" -desired 1
} else {
    Ensure-RegDword -path $regPath -name "OSHardwareEncryption" -desired 1
}

if ($RequireADBackup) {
    Ensure-RegDword -path $regPath -name "OSRequireActiveDirectoryBackup" -desired 1
}

if ($policyChanged) {
    Write-Host "`nApplying policies with gpupdate /force ..." -ForegroundColor Cyan
    gpupdate /force | Out-Null
    Start-Sleep -Seconds 2
} else {
    Write-Host "No policy changes needed. Skipping gpupdate." -ForegroundColor Cyan
}

# UEFI PCR profile settings
Write-Host "`n== UEFI PCR profile ==" -ForegroundColor Cyan
$pvKey = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI"
if (-not (Test-Path $pvKey)) { New-Item -Path $pvKey -Force | Out-Null }

$pvChanged = $false
try {
    $prop = Get-ItemProperty -Path $pvKey -ErrorAction SilentlyContinue
    $enabledCurr = $null
    if ($prop -and $prop.PSObject.Properties.Name -contains "Enabled") { $enabledCurr = $prop.Enabled }
} catch { $enabledCurr = $null }

if ($enabledCurr -ne 1) { Set-ItemProperty -Path $pvKey -Name "Enabled" -Value 1 -Type DWord -Force | Out-Null; $pvChanged = $true }

for ($i = 0; $i -le 23; $i++) {
    $desired = [int]($PCRsToEnable -contains $i)
    try {
        $prop = Get-ItemProperty -Path $pvKey -ErrorAction SilentlyContinue
        $curr = $null
        if ($prop -and $prop.PSObject.Properties.Name -contains ("$i")) { $curr = $prop."$i" }
    } catch { $curr = $null }
    if ($curr -ne $desired) {
        Set-ItemProperty -Path $pvKey -Name ("{0}" -f $i) -Value $desired -Type DWord -Force | Out-Null
        $pvChanged = $true
    }
}

if ($pvChanged) {
    Write-Host "UEFI PCR profile written/updated." -ForegroundColor Green
} else {
    Write-Host "UEFI PCR profile already matches desired values. Skipping rewrite." -ForegroundColor Cyan
}

# Show current BitLocker status for the specified mount point
Write-Host "`n== Current BitLocker status ==" -ForegroundColor Cyan
$blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
if (-not $blv) {
    Write-Host "Could not query BitLocker volume for $MountPoint. Ensure BitLocker feature is available and run elevated." -ForegroundColor Red
    return
}
$blv | Select-Object ComputerName,MountPoint,EncryptionMethod,VolumeStatus,ProtectionStatus,EncryptionPercentage,KeyProtector | Format-List *

# Recovery protector handling
Write-Host "`n== Recovery protector ==" -ForegroundColor Cyan
$kp = $blv.KeyProtector
$hasRecovery = $false
$hasTPM = $false
if ($kp) {
    $hasRecovery = $kp | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    $hasTPM = $kp | Where-Object { $_.KeyProtectorType -match 'Tpm' }
}

if (-not $hasRecovery) {
    try {
        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
        $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
        $pwd = Extract-RecoveryPasswordFromText -text $text

        Ensure-BackupFolder -folder $BackupFolder | Out-Null
        $recFile = Join-Path -Path $BackupFolder -ChildPath ("RecoveryPassword_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
        if ($pwd) {
            $recText = "Recovery password for $MountPoint`r`n`r`n$pwd`r`n`r`nCOPY THIS PASSWORD TO AN EXTERNAL DEVICE BEFORE REBOOTING."
        } else {
            $recText = "Recovery password for $MountPoint`r`n`r`n(see manage-bde output in backup folder)`r`n`r`nCOPY THIS PASSWORD TO AN EXTERNAL DEVICE BEFORE REBOOTING."
        }
        Save-TextToFile -text $recText -path $recFile | Out-Null

        if ($file) {
            Write-Host "`nRecovery password created and saved to $file" -ForegroundColor Green
        } else {
            Write-Host "`nRecovery password created and saved to backup folder." -ForegroundColor Green
        }
    } catch {
        Write-Warning ("Failed to create recovery protector: {0}" -f $_.Exception.Message)
        Log ("Add-BitLockerKeyProtector (Recovery) failed: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Host "Recovery protector already present." -ForegroundColor Cyan
    $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
    $pwd = Extract-RecoveryPasswordFromText -text $text
    if ($pwd) {
        Write-Host "`nFound recovery password in saved manage-bde output. Ensure you have it backed up." -ForegroundColor Red
    } else {
        if ($file) { Log ("manage-bde protector text saved to: {0}" -f $file) }
    }
}

# TPM protector handling
Write-Host "`n== TPM protector ==" -ForegroundColor Cyan
if (-not $hasTPM) {
    try {
        Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector -ErrorAction Stop | Out-Null
        Write-Host "TPM protector added." -ForegroundColor Green
    } catch {
        Write-Warning ("Failed to add TPM protector (may already exist or TPM unavailable): {0}" -f $_.Exception.Message)
    }
} else {
    Write-Host "TPM protector already present." -ForegroundColor Cyan
}

# Refresh and detect existing TPM+PIN protector
$blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
$kp = $blv.KeyProtector
$existingTpmPin = $null
if ($kp) {
    $existingTpmPin = $kp | Where-Object {
        ($_.KeyProtectorType -eq 'TpmAndPin') -or ( ($_.KeyProtectorType -match 'Tpm') -and ($_.KeyProtectorType -match 'Pin') )
    }
}
if ($existingTpmPin -and ($blv.ProtectionStatus -ne 1 -or $blv.EncryptionMethod -eq $null -or $blv.EncryptionMethod -eq "None")) {
    Write-Host "`nTPM+PIN protector is present but BitLocker protection is not active." -ForegroundColor Yellow
    $doEnable = Ask-YesNo "Do you want to proceed to enable BitLocker/encryption now?" -Default 'y'
    if (-not $doEnable) { Write-Host "User chose not to enable encryption now. Exiting." -ForegroundColor Cyan; return } else { Write-Host "Proceeding to enable BitLocker/encryption." -ForegroundColor Cyan }
}

# Enable BitLocker if not already enabled
Write-Host "`n== Encryption enablement ==" -ForegroundColor Cyan
if ($blv.ProtectionStatus -eq 0 -or $blv.EncryptionMethod -eq $null -or $blv.EncryptionMethod -eq "None") {
    Write-Host "Detected unprotected OS volume. Enabling BitLocker now..." -ForegroundColor Cyan

    $enabled = $false
    $requiresRebootForHardwareTest = $false
    $manageBdeOutput = $null
    $manageBdeFailed = $false

    # Try manage-bde first
    try {
        $manageBdeOutput = & manage-bde.exe -on $MountPoint 2>&1
        if ($manageBdeOutput) {
            Ensure-BackupFolder -folder $BackupFolder | Out-Null
            $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
            $mFile = Join-Path -Path $BackupFolder -ChildPath ("ManageBDE_Enable_$stamp.txt")
            Save-TextToFile -text $manageBdeOutput -path $mFile | Out-Null
            Log ("manage-bde enable output saved to {0}" -f $mFile)
        }

        if ($manageBdeOutput -match "Restart the computer" -or $manageBdeOutput -match "hardware test" -or $manageBdeOutput -match "ACTIONS REQUIRED") {
            $enabled = $true
            if ($manageBdeOutput -match "Restart the computer" -or $manageBdeOutput -match "hardware test") {
                $requiresRebootForHardwareTest = $true
            }
        } else {
            $tmpVol = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
            if ($tmpVol -and ($tmpVol.ProtectionStatus -eq 1 -or ($tmpVol.EncryptionPercentage -ne $null -and $tmpVol.EncryptionPercentage -gt 0))) {
                $enabled = $true
            } else {
                $manageBdeFailed = $true
            }
        }
    } catch {
        $manageBdeFailed = $true
        Log ("manage-bde -on failed: {0}" -f $_.Exception.Message)
    }

    # Fallback to Enable-BitLocker if manage-bde did not enable
    if (-not $enabled -and $manageBdeFailed) {
        Write-Host "Attempting Enable-BitLocker cmdlet as fallback..." -ForegroundColor Cyan
        try {
            if ($forceSoftware) { Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -ErrorAction Stop } else { Enable-BitLocker -MountPoint $MountPoint -UsedSpaceOnly -ErrorAction Stop }
            $enabled = $true
        } catch {
            Write-Warning ("Enable-BitLocker failed: {0}" -f $_.Exception.Message)
            Log ("Enable-BitLocker failed after manage-bde fallback: {0}" -f $_.Exception.Message)
            $enabled = $false
        }
    }

    if ($enabled) {
        if ($requiresRebootForHardwareTest) {
            Write-Host "`nA hardware test is required to begin encryption. The system must restart to run the test." -ForegroundColor Yellow

            Write-Host "`nIMPORTANT NEXT STEPS (after this first run):" -ForegroundColor Cyan
            Write-Host "  1) Reboot now to run the hardware test and start encryption: shutdown /r /t 0" -ForegroundColor Yellow
            Write-Host "  2) After that reboot, LET BITLOCKER FINISH ENCRYPTION COMPLETELY (monitor with Get-BitLockerVolume or manage-bde -status)." -ForegroundColor Yellow
            Write-Host "  3) Once encryption is fully finished and ProtectionStatus = 1, REBOOT AGAIN." -ForegroundColor Yellow
            Write-Host "  4) Then re-run this script (elevated, 64-bit PowerShell) to add TPM+PIN and optionally remove TPM-only protectors." -ForegroundColor Yellow
            Write-Host ""

            if (Ask-YesNo "Do you want to restart now to run the hardware test and start encryption?" -Default 'y') {
                Write-Host "Restarting now to run the hardware test and start encryption. Save your work." -ForegroundColor Cyan
                shutdown /r /t 0 /c "Restarting to complete BitLocker hardware test and start encryption."
                return
            } else {
                Write-Host "Skipped reboot." -ForegroundColor Yellow
                Write-Host "`nThe script will exit now; re-run it after following the steps above." -ForegroundColor Cyan
                return
            }
        } else {
            Write-Host "Enable operation invoked. Waiting briefly for status..." -ForegroundColor Cyan
            $started = Wait-ForEncryptionStart -MountPoint $MountPoint -TimeoutMinutes $EncryptionStartTimeoutMinutes
            if (-not $started) { Write-Warning "Encryption/protection did not show active within timeout. Check status after reboot if needed." } else {
                $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
                if ($blv -and ($blv.ProtectionStatus -ne 1 -or ($blv.EncryptionPercentage -ne $null -and $blv.EncryptionPercentage -lt 100))) {
                    Write-Host "`nProtection enabled or encryption started." -ForegroundColor Green
                    Write-Host "`nIMPORTANT NEXT STEPS (after this first run):" -ForegroundColor Cyan
                    Write-Host "  1) Let BitLocker finish encryption completely (monitor with Get-BitLockerVolume -MountPoint $MountPoint)." -ForegroundColor Yellow
                    Write-Host "  2) When encryption shows as complete (EncryptionPercentage = 100 and ProtectionStatus = 1), REBOOT the system." -ForegroundColor Yellow
                    Write-Host "  3) After that reboot, re-run this script (elevated, 64-bit PowerShell) to add TPM+PIN and optionally remove TPM-only protectors." -ForegroundColor Yellow
                    Write-Host "`nThe script will exit now; re-run it after following the steps above." -ForegroundColor Cyan
                    return
                } else {
                    Write-Host "Protection enabled and appears complete. Continuing..." -ForegroundColor Green
                }
            }
        }
    } else {
        Write-Host "Enable step failed (both manage-bde and Enable-BitLocker). Collecting diagnostics..." -ForegroundColor Red
        manage-bde -status $MountPoint
        manage-bde -protectors -get $MountPoint
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-BitLocker-Driver'} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) { $events | Select-Object TimeCreated, Id, @{n='Message';e={$_.Message}} | Format-List } else { Write-Host "No BitLocker events found." -ForegroundColor Yellow }
        Write-Host "Aborting further changes." -ForegroundColor Red
        return
    }
} else {
    Write-Host "BitLocker already enabled or in progress. Skipping enable step." -ForegroundColor Cyan
}

# TPM+PIN management
Write-Host "`n== TPM+PIN management ==" -ForegroundColor Cyan
$kp = (Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue).KeyProtector
$existingTpmPin = $null
if ($kp) {
    $existingTpmPin = $kp | Where-Object {
        ($_.KeyProtectorType -eq 'TpmAndPin') -or ( ($_.KeyProtectorType -match 'Tpm') -and ($_.KeyProtectorType -match 'Pin') )
    }
}

if ($RequireTpmPin) {
    if ($existingTpmPin) {
        Write-Host "`nTPM+PIN protector already present. Protector list:" -ForegroundColor Yellow
        $existingTpmPin | Format-Table KeyProtectorId, KeyProtectorType -AutoSize
        $addedTpmPin = $true
    } else {
        $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
        if ($blv.ProtectionStatus -ne 1 -and ($blv.VolumeStatus -match "FullyDecrypted|FullyDecryption|FullyDecrypted")) {
            Write-Host "`nWarning: BitLocker protection does not appear active yet. Re-run this script after encryption/protection is active." -ForegroundColor Yellow
            return
        }

        Write-Host "Adding TPM+PIN protector..." -ForegroundColor Cyan

        # PIN prompt with confirmation
        while ($true) {
            $securePin1 = Read-Host -Prompt "Enter startup PIN (will not echo)" -AsSecureString
            $ptr1 = $null; $plain1 = $null
            try { $ptr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin1); $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr1) } finally { if ($ptr1) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr1); $ptr1 = $null } }

            $securePin2 = Read-Host -Prompt "Enter startup PIN again (will not echo)" -AsSecureString
            $ptr2 = $null; $plain2 = $null
            try { $ptr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin2); $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr2) } finally { if ($ptr2) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr2); $ptr2 = $null } }

            if ($plain1 -ne $plain2) {
                Write-Host "PIN entries do not match. Please try again." -ForegroundColor Yellow
                $securePin1 = $null; $securePin2 = $null; $plain1 = $null; $plain2 = $null
                continue
            }
            if ($plain1.Length -lt $MinPinLength) {
                Write-Host "PIN too short. Minimum length is $MinPinLength." -ForegroundColor Yellow
                $securePin1 = $null; $securePin2 = $null; $plain1 = $null; $plain2 = $null
                continue
            }
            $plainPin = $plain1
            $securePin1 = $null; $securePin2 = $null; $plain1 = $null; $plain2 = $null
            break
        }

        # Locate Win32_EncryptableVolume and attempt TPM+PIN via CIM, fallback to cmdlet
        Write-Host "`nLocating Win32_EncryptableVolume..." -ForegroundColor Cyan
        $cimNs = 'Root\CIMV2\Security\MicrosoftVolumeEncryption'
        try { $vols = Get-CimInstance -Namespace $cimNs -ClassName Win32_EncryptableVolume -ErrorAction Stop } catch { $vols = $null }

        $vol = $null
        if ($vols) {
            $vol = $vols | Where-Object { ($_.DriveLetter -eq $MountPoint) -or ($_.DriveLetter -eq $MountPoint.TrimEnd(':')) } | Select-Object -First 1
            if (-not $vol) { $vol = $vols | Select-Object -First 1 }
        }

        $addedTpmPin = $false
        if ($vol) {
            [byte[]]$pcrArray = [byte[]]($PCRsToEnable | ForEach-Object {[byte]$_})
            try {
                $out = Invoke-CimMethod -InputObject $vol -MethodName ProtectKeyWithTPMAndPIN -Arguments @{ FriendlyName = "TPM+PIN"; PlatformValidationProfile = $pcrArray; PIN = $plainPin } -ErrorAction Stop
                if ($null -ne $out -and $out.ReturnValue -eq 0) {
                    Write-Host "ProtectKeyWithTPMAndPIN succeeded. New protector ID: $($out.VolumeKeyProtectorID)" -ForegroundColor Green
                    $addedTpmPin = $true
                }
            } catch {
                Write-Warning ("ProtectKeyWithTPMAndPIN failed or not supported: {0}" -f $_.Exception.Message)
                Log ("ProtectKeyWithTPMAndPIN failed: {0}" -f $_.Exception.Message)
            }
        }

        if (-not $addedTpmPin) {
            try {
                $ss = ConvertTo-SecureString -String $plainPin -AsPlainText -Force
                Add-BitLockerKeyProtector -MountPoint $MountPoint -Pin $ss -TpmAndPinProtector -ErrorAction Stop | Out-Null
                Write-Host "Added TPM+PIN via Add-BitLockerKeyProtector (fallback)." -ForegroundColor Green
                $addedTpmPin = $true
            } catch {
                Write-Warning ("Failed to add TPM+PIN via cmdlet: {0}" -f $_.Exception.Message)
                Log ("Add-BitLockerKeyProtector (TPM+PIN) failed: {0}" -f $_.Exception.Message)
            }
        }

        $plainPin = $null

        if ($addedTpmPin) {
            $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
            if ($file) { Write-Host "Protectors saved to backup folder." -ForegroundColor Green }

            $kp = (Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue).KeyProtector
            $tpmOnly = $kp | Where-Object { $_.KeyProtectorType -eq 'Tpm' }
            if ($tpmOnly) {
                Write-Host "`nFound TPM-only protector(s):" -ForegroundColor Cyan
                $tpmOnly | Format-Table KeyProtectorId, KeyProtectorType -AutoSize
                Write-Host "Removing TPM-only protectors will force the system to require TPM+PIN at pre-boot and is irreversible without the recovery key." -ForegroundColor Yellow
                Write-Host "Ensure you have the recovery key saved before deleting TPM-only protectors." -ForegroundColor Yellow

                $confirm = Read-Host "Type DELETE to permanently remove TPM-only protectors (or press Enter to skip)"
                if ($confirm -eq 'DELETE') {
                    foreach ($prot in $tpmOnly) {
                        try {
                            Write-Host "Removing protector ID $($prot.KeyProtectorId) ..." -ForegroundColor Cyan
                            manage-bde -protectors -delete $MountPoint -id "$($prot.KeyProtectorId)" | Out-Null
                            Write-Host "Removed $($prot.KeyProtectorId)" -ForegroundColor Green
                        } catch { Write-Warning ("Failed to remove protector {0}: {1}" -f $prot.KeyProtectorId, $_.Exception.Message) }
                    }
                } else {
                    Write-Host "Skipping TPM-only protector deletion." -ForegroundColor Cyan
                }
            } else {
                Write-Host "No TPM-only protectors found." -ForegroundColor Cyan
            }
        } else {
            Write-Warning "TPM+PIN was not added successfully. Do NOT remove TPM-only protectors. Investigate and retry."
        }
    }
} else {
    Write-Host "TPM+PIN enforcement disabled by configuration. Skipping automatic creation." -ForegroundColor Cyan
}

# Final verification output
Write-Host "`n== Verification ==" -ForegroundColor Cyan
manage-bde -protectors -get $MountPoint | Out-Host
Get-BitLockerVolume -MountPoint $MountPoint | Format-List *

Write-Host "`n== Done. ==" -ForegroundColor Green
Write-Host "`nLAST WARNING: BACKUP YOUR RECOVERY KEY NOW. If something goes wrong and you do NOT have this key, you will be locked out of your machine!" -ForegroundColor Red