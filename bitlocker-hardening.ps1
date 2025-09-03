<#
BitLocker hardening script
Run in 64-bit PowerShell as Administrator.

- Ensures a recovery protector is present and backed up.
- Enables BitLocker (software by default for compatibility).
- Adds TPM+PIN and can remove TPM-only protectors afterwards.
#>

param(
    [string]$MountPoint = "C:",
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

# Save text to a file
function Save-TextToFile {
    param($text, $path)
    try {
        $text | Out-File -FilePath $path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning "Failed to write to ${path}: $($_.Exception.Message)"
        return $false
    }
}

# Save key protectors to a readable file for auditing/backup
function Backup-ProtectorsToFile {
    param($MountPoint)
    try {
        Ensure-BackupFolder -folder $BackupFolder
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $outFile = Join-Path -Path $BackupFolder -ChildPath ("BitLocker_Protectors_$timestamp.txt")
        $kp = (Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue).KeyProtector
        if ($kp) {
            $kp | Format-List * | Out-File -FilePath $outFile -Encoding UTF8
            Log "Protectors written to $outFile"
        } else {
            "No KeyProtectors found for $MountPoint" | Out-File -FilePath $outFile -Encoding UTF8
            Log "No protectors found. Empty file created at $outFile"
        }
        return $outFile
    } catch {
        Write-Warning "Failed to backup protectors: $($_.Exception.Message)"
        return $null
    }
}

# Capture manage-bde protectors output (this often contains the recovery password text)
function Save-ManageBdeProtectorsText {
    param($MountPoint)
    try {
        Ensure-BackupFolder -folder $BackupFolder
        $text = & manage-bde.exe -protectors -get $MountPoint 2>&1
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $file = Join-Path -Path $BackupFolder -ChildPath ("ManageBDE_Protectors_$stamp.txt")
        Save-TextToFile -text $text -path $file | Out-Null
        Log "manage-bde protector text saved to $file"
        return $file, $text
    } catch {
        Write-Warning "Failed to capture manage-bde protectors text: $($_.Exception.Message)"
        return $null, $null
    }
}

# Try to extract the 48-digit recovery password from manage-bde text
function Extract-RecoveryPasswordFromText {
    param($text)
    if (-not $text) { return $null }
    $m = [regex]::Match($text, '\b(\d{6}(?:-\d{6}){7})\b')
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

# Make manage-bde output slightly more readable for display
function Pretty-PrintManageBdeOutput {
    param($text)
    if (-not $text) { return }
    $pretty = $text -replace 'ACTIONS REQUIRED:', "`nACTIONS REQUIRED:`n"
    $pretty = $pretty -replace 'To prevent data loss,', "`nTo prevent data loss,"
    Write-Host $pretty
}

# Simple logger that writes to a file in the backup folder
function Log {
    param([string]$m)
    try {
        if (-not (Test-Path $BackupFolder)) { Ensure-BackupFolder -folder $BackupFolder }
        if (-not $global:LogFile) { $global:LogFile = Join-Path $BackupFolder ("bitlocker_script_$(Get-Date -Format yyyyMMdd_HHmmss).log") }
        $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$t - $m" | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
        Write-Host $m
    } catch {
        Write-Host $m
    }
}

# Poll the volume until encryption/protection shows activity or timeout
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

# ---------- Start ----------
Write-Host "`nIMPORTANT: This script changes BitLocker protectors and policies and can affect access to your data." -ForegroundColor Red
Write-Host "Make a copy of the recovery password and store it offline (USB, printed, or an offline password manager) before rebooting or removing protectors." -ForegroundColor Red
Write-Host "Flow: 1) create/save recovery protector  2) enable BitLocker (software by default)  3) after encryption finishes re-run to add TPM+PIN." -ForegroundColor Yellow

$consent = Read-Host "Do you understand and accept the risk? Type 'y' to continue"
if ($consent -ne 'y') {
    Write-Host "Aborting. No changes were made." -ForegroundColor Cyan
    return
}

# Basic environment checks
Write-Host "`n== Sanity checks ==" -ForegroundColor Cyan
Write-Host "PROCESSOR_ARCHITECTURE = $($env:PROCESSOR_ARCHITECTURE)"
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    Write-Warning "Please run 64-bit PowerShell as Administrator."
}
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You are not running as Administrator. Re-run elevated."
}

try {
    $sb = Confirm-SecureBootUEFI
    Write-Host "Secure Boot enabled: $sb" -ForegroundColor Cyan
} catch {
    Write-Host "Secure Boot check not available on this platform or requires admin." -ForegroundColor Yellow
}

# Prepare backup folder and restrict access
Ensure-BackupFolder -folder $BackupFolder

try {
    $acl = Get-Acl -Path $BackupFolder
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule1)
    $acl.AddAccessRule($rule2)
    Set-Acl -Path $BackupFolder -AclObject $acl
    Log "Backup folder ensured and ACL restricted: $BackupFolder"
} catch {
    Write-Warning "Failed to set strict ACL on ${BackupFolder}: $($_.Exception.Message)"
    Log "Warning: could not set ACL on $BackupFolder"
}

$choiceFile = Join-Path -Path $BackupFolder -ChildPath $ChoiceFileName
$useSoftware = $null
if (Test-Path $choiceFile) {
    try {
        $json = Get-Content -Path $choiceFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        if ($json -and $json.useSoftware -ne $null) {
            $useSoftware = [bool]$json.useSoftware
            Write-Host "Using previously saved encryption preference: useSoftware = $useSoftware" -ForegroundColor Cyan
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
            Write-Host "TPM present. Manufacturer: $($tpm.ManufacturerId)  SpecVersion: $($tpm.SpecVersion)" -ForegroundColor Cyan
            Log "TPM ready."
        }
    }
} catch {
    Write-Warning "Get-Tpm unavailable or no TPM present: $($_.Exception.Message)"
    Log "No TPM or Get-Tpm failed."
}

# Encryption preference prompt (software is the default now)
if ($useSoftware -eq $null) {
    Write-Host "`nBy default this script will prefer software encryption (recommended for compatibility)." -ForegroundColor Cyan
    Write-Host "Hardware encryption can offer benefits, but not all drives or firmware expose it reliably." -ForegroundColor Yellow
    $ans = Ask-YesNo "Do you want to prefer software encryption?" -Default 'y'
    $useSoftware = $ans
    try {
        @{ useSoftware = $useSoftware } | ConvertTo-Json | Set-Content -Path $choiceFile -Encoding UTF8 -Force
        Write-Host "Saved encryption preference to $choiceFile" -ForegroundColor Cyan
    } catch {
        Write-Warning "Failed to save choice file: $($_.Exception.Message)"
    }
} else {
    Write-Host "`nSkipping encryption preference prompt (already set)." -ForegroundColor Cyan
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
        Set-ItemProperty -Path $path -Name $name -Value $desired -Type DWord -Force
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

# UEFI PCR profile
Write-Host "`nEnsuring UEFI PCR profile..." -ForegroundColor Cyan
$pvKey = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI"
if (-not (Test-Path $pvKey)) { New-Item -Path $pvKey -Force | Out-Null }

$pvChanged = $false
try {
    $prop = Get-ItemProperty -Path $pvKey -ErrorAction SilentlyContinue
    $enabledCurr = $null
    if ($prop -and $prop.PSObject.Properties.Name -contains "Enabled") { $enabledCurr = $prop.Enabled }
} catch { $enabledCurr = $null }

if ($enabledCurr -ne 1) { Set-ItemProperty -Path $pvKey -Name "Enabled" -Value 1 -Type DWord -Force; $pvChanged = $true }

for ($i = 0; $i -le 23; $i++) {
    $desired = [int]($PCRsToEnable -contains $i)
    try {
        $prop = Get-ItemProperty -Path $pvKey -ErrorAction SilentlyContinue
        $curr = $null
        if ($prop -and $prop.PSObject.Properties.Name -contains ("$i")) { $curr = $prop."$i" }
    } catch { $curr = $null }
    if ($curr -ne $desired) {
        Set-ItemProperty -Path $pvKey -Name ("{0}" -f $i) -Value $desired -Type DWord -Force
        $pvChanged = $true
    }
}

if ($pvChanged) {
    Write-Host "UEFI PCR profile written/updated." -ForegroundColor Green
} else {
    Write-Host "UEFI PCR profile already matches desired values. Skipping rewrite." -ForegroundColor Cyan
}
Write-Host "Note: If managed by Group Policy or MDM, local changes may be overridden." -ForegroundColor Yellow

# Show current status
Write-Host "`nCurrent BitLocker status and protectors:" -ForegroundColor Cyan
$blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue
if (-not $blv) {
    Write-Host "Could not query BitLocker volume for $MountPoint. Ensure BitLocker feature is available and run elevated." -ForegroundColor Red
    return
}
$blv | Format-List *
Write-Host "`nEncryptionMethod property above shows whether the drive currently uses hardware or software encryption." -ForegroundColor Cyan

$encMethod = $blv.EncryptionMethod
if ($encMethod -match "Hardware|HardwareEncryption") {
    $currentIsHardware = $true
    Write-Host "Drive appears to be using hardware encryption." -ForegroundColor Yellow
} else {
    $currentIsHardware = $false
    Write-Host "Drive appears to be using software encryption or standard BitLocker cipher." -ForegroundColor Cyan
}

# Ensure recovery protector exists and back it up
$kp = $blv.KeyProtector
$hasRecovery = $false
$hasTPM = $false
if ($kp) {
    $hasRecovery = $kp | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    $hasTPM = $kp | Where-Object { $_.KeyProtectorType -match 'Tpm' }
}

if (-not $hasRecovery) {
    Write-Host "`nNo recovery password protector found. Creating one now..." -ForegroundColor Yellow
    try {
        $newRec = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -ErrorAction Stop
        $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
        $pwd = Extract-RecoveryPasswordFromText -text $text
        if ($pwd) {
            Ensure-BackupFolder -folder $BackupFolder
            $recFile = Join-Path -Path $BackupFolder -ChildPath ("RecoveryPassword_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
            $recText = "Recovery password for $MountPoint`r`n`r`n$pwd`r`n`r`nCOPY THIS PASSWORD TO AN EXTERNAL DEVICE BEFORE REBOOTING."
            Save-TextToFile -text $recText -path $recFile | Out-Null
            Write-Host "`nA new recovery password was created and saved to: $recFile" -ForegroundColor Green
            Write-Host "`nIMPORTANT: COPY THE FOLLOWING RECOVERY PASSWORD TO AN EXTERNAL DEVICE (USB / printed / offline password manager):" -ForegroundColor Red
            Write-Host "`n$pwd`n" -ForegroundColor Green
        } else {
            if ($newRec -and $newRec.RecoveryPassword) {
                $pwd2 = $newRec.RecoveryPassword
                Ensure-BackupFolder -folder $BackupFolder
                $recFile = Join-Path -Path $BackupFolder -ChildPath ("RecoveryPassword_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
                $recText = "Recovery password for $MountPoint`r`n`r`n$pwd2`r`n`r`nCOPY THIS PASSWORD TO AN EXTERNAL DEVICE BEFORE REBOOTING."
                Save-TextToFile -text $recText -path $recFile | Out-Null
                Write-Host "`nRecovery password saved to: $recFile" -ForegroundColor Green
                Write-Host "`n$pwd2`n" -ForegroundColor Green
            } else {
                Write-Host "Recovery password protector created but the script could not automatically extract the displayed password." -ForegroundColor Yellow
                Write-Host "Run 'manage-bde -protectors -get $MountPoint' to view and save it manually." -ForegroundColor Yellow
                if ($file) { Pretty-PrintManageBdeOutput -text $text }
            }
        }
    } catch {
        Write-Warning "Failed to create recovery protector: $($_.Exception.Message)"
    }
} else {
    Write-Host "Recovery protector already present." -ForegroundColor Cyan
    $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
    $pwd = Extract-RecoveryPasswordFromText -text $text
    if ($pwd) {
        Write-Host "`nFound recovery password in saved manage-bde output. IMPORTANT: copy it to an external device before rebooting." -ForegroundColor Red
        Write-Host "`n$pwd`n" -ForegroundColor Green
    }
}

# Ensure TPM protector exists
if (-not $hasTPM) {
    Write-Host "`nAdding TPM protector (if supported)..." -ForegroundColor Cyan
    try {
        Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector -ErrorAction Stop | Out-Null
        Write-Host "TPM protector added." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to add TPM protector (may already exist or TPM unavailable): $($_.Exception.Message)"
    }
} else {
    Write-Host "TPM protector already present." -ForegroundColor Cyan
}

# Refresh BitLocker object and detect existing TPM+PIN protector
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
    if (-not $doEnable) {
        Write-Host "User chose not to enable encryption now. Exiting." -ForegroundColor Cyan
        return
    } else {
        Write-Host "Proceeding to enable BitLocker/encryption." -ForegroundColor Cyan
    }
}

# Enable BitLocker if not already enabled
if ($blv.ProtectionStatus -eq 0 -or $blv.EncryptionMethod -eq $null -or $blv.EncryptionMethod -eq "None") {
    Write-Host "`nDetected unprotected OS volume. Enabling BitLocker now..." -ForegroundColor Cyan
    $enabled = $false
    $requiresRebootForHardwareTest = $false
    $fallbackOutput = $null

    try {
        if ($forceSoftware) {
            Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -ErrorAction Stop
        } else {
            Enable-BitLocker -MountPoint $MountPoint -UsedSpaceOnly -ErrorAction Stop
        }
        $enabled = $true
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'Parameter set cannot be resolved') {
            Write-Host "Enable-BitLocker cmdlet failed due to parameter/driver environment. Falling back to manage-bde.exe." -ForegroundColor Yellow
        } else {
            Write-Warning "Enable-BitLocker failed: $msg"
        }

        Write-Host "Attempting fallback using manage-bde.exe -on $MountPoint ..." -ForegroundColor Yellow
        try {
            $fallbackOutput = & manage-bde.exe -on $MountPoint 2>&1
            Pretty-PrintManageBdeOutput -text $fallbackOutput
            if ($fallbackOutput -match "Restart the computer" -or $fallbackOutput -match "hardware test" -or $fallbackOutput -match "Restart to run a hardware test" -or $fallbackOutput -match "ACTIONS REQUIRED") {
                $enabled = $true
                if ($fallbackOutput -match "Restart the computer" -or $fallbackOutput -match "hardware test") {
                    $requiresRebootForHardwareTest = $true
                }
            }
        } catch {
            Write-Warning "manage-bde fallback failed: $($_.Exception.Message)"
            try {
                $fallbackOutput = & manage-bde.exe -on $MountPoint -usedspaceonly 2>&1
                Pretty-PrintManageBdeOutput -text $fallbackOutput
                if ($fallbackOutput -match "Restart the computer" -or $fallbackOutput -match "hardware test" -or $fallbackOutput -match "ACTIONS REQUIRED") {
                    $enabled = $true
                    if ($fallbackOutput -match "Restart the computer" -or $fallbackOutput -match "hardware test") {
                        $requiresRebootForHardwareTest = $true
                    }
                }
            } catch {
                Write-Warning "manage-bde -usedspaceonly fallback failed: $($_.Exception.Message)"
            }
        }
    }

    if ($enabled) {
        if ($requiresRebootForHardwareTest) {
            Write-Host "`nA hardware test is required to begin encryption. The system must restart to run the test." -ForegroundColor Yellow
            Write-Host "Recovery key information was saved to the backup folder. Confirm you have the file before rebooting." -ForegroundColor Yellow

            $protectFiles = Get-ChildItem -Path $BackupFolder -Filter "ManageBDE_Protectors_*.txt" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if ($protectFiles -and $protectFiles[0]) {
                Write-Host "Newest protectors file: $($protectFiles[0].FullName)" -ForegroundColor Green
            } else {
                Write-Host "No manage-bde protectors file found in ${BackupFolder}. Attempting to capture now." -ForegroundColor Yellow
                $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
            }

            # show next steps before asking to restart so user always sees guidance
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
            if (-not $started) {
                Write-Warning "Encryption/protection did not show active within timeout. Check status after reboot if needed."
            } else {
                # refresh status
                $blv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue

                # If user explicitly requested hardware but device fell back to software, warn them
                if (-not $forceSoftware) {
                    $encNow = $blv.EncryptionMethod
                    if (-not ($encNow -match "Hardware|HardwareEncryption")) {
                        Write-Warning ""
                        Write-Warning "Notice: although hardware encryption was requested, BitLocker is using software encryption on this drive."
                        Write-Warning "Not all drives or firmware expose hardware encryption to Windows reliably; some vendors require special preparation (e.g. secure erase / PSID revert) to enable self-encrypting-drive features."
                        Write-Warning "If you expected hardware encryption, check your drive vendor documentation (for example Samsung drives sometimes require a PSID revert) and re-run the script after preparing the drive."
                        Write-Warning ""
                        Log "Hardware encryption requested but software encryption in use."
                    } else {
                        Write-Host "Drive is using hardware encryption as requested." -ForegroundColor Green
                    }
                }

                if ($blv -and ($blv.ProtectionStatus -ne 1 -or ($blv.EncryptionPercentage -ne $null -and $blv.EncryptionPercentage -lt 100))) {
                    Write-Host "Protection enabled or encryption started." -ForegroundColor Green
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
        Write-Host "Enable step failed. Collecting diagnostics..." -ForegroundColor Red
        manage-bde -status $MountPoint
        manage-bde -protectors -get $MountPoint
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-BitLocker-Driver'} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $events | Select-Object TimeCreated, Id, @{n='Message';e={$_.Message}} | Format-List
        } else {
            Write-Host "No BitLocker events found." -ForegroundColor Yellow
        }
        Write-Host "Aborting further changes." -ForegroundColor Red
        return
    }
} else {
    Write-Host "`nBitLocker already enabled or in progress. Skipping enable step." -ForegroundColor Cyan
}

# Add TPM+PIN if required
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

        Write-Host "`nAdding TPM+PIN protector..." -ForegroundColor Cyan

        while ($true) {
            $securePin = Read-Host -Prompt "Enter startup PIN (will not echo)" -AsSecureString
            $ptr = $null
            try {
                $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin)
                $plainPinCheck = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
            } finally {
                if ($ptr) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $ptr = $null }
            }
            if ($plainPinCheck.Length -ge $MinPinLength) { break }
            Write-Host "PIN too short. Minimum length is $MinPinLength." -ForegroundColor Yellow
        }

        Write-Host "`nLocating Win32_EncryptableVolume..." -ForegroundColor Cyan
        $cimNs = 'Root\CIMV2\Security\MicrosoftVolumeEncryption'
        try { $vols = Get-CimInstance -Namespace $cimNs -ClassName Win32_EncryptableVolume -ErrorAction Stop } catch { $vols = $null }

        $vol = $null
        if ($vols) {
            $vol = $vols | Where-Object { ($_.DriveLetter -eq $MountPoint) -or ($_.DriveLetter -eq $MountPoint.TrimEnd(':')) } | Select-Object -First 1
            if (-not $vol) { $vol = $vols | Select-Object -First 1 }
        }

        $ptr = $null
        $plainPin = $null
        try {
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin)
            $plainPin = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        } finally {
            if ($ptr) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $ptr = $null }
        }

        $addedTpmPin = $false
        if ($vol) {
            [byte[]]$pcrArray = [byte[]]($PCRsToEnable | ForEach-Object {[byte]$_})
            try {
                $out = Invoke-CimMethod -InputObject $vol -MethodName ProtectKeyWithTPMAndPIN `
                    -Arguments @{ FriendlyName = "TPM+PIN"; PlatformValidationProfile = $pcrArray; PIN = $plainPin } -ErrorAction Stop
                if ($null -ne $out -and $out.ReturnValue -eq 0) {
                    Write-Host "ProtectKeyWithTPMAndPIN succeeded. New protector ID: $($out.VolumeKeyProtectorID)" -ForegroundColor Green
                    $addedTpmPin = $true
                }
            } catch {
                Write-Warning "ProtectKeyWithTPMAndPIN failed or not supported: $($_.Exception.Message)"
                Log "ProtectKeyWithTPMAndPIN failed: $($_.Exception.Message)"
            }
        }

        if (-not $addedTpmPin) {
            try {
                $ss = ConvertTo-SecureString -String $plainPin -AsPlainText -Force
                Add-BitLockerKeyProtector -MountPoint $MountPoint -Pin $ss -TpmAndPinProtector -ErrorAction Stop | Out-Null
                Write-Host "Added TPM+PIN via Add-BitLockerKeyProtector (fallback)." -ForegroundColor Green
                $addedTpmPin = $true
            } catch {
                Write-Warning "Failed to add TPM+PIN via cmdlet: $($_.Exception.Message)"
                Log "Add-BitLockerKeyProtector (TPM+PIN) failed: $($_.Exception.Message)"
            }
        }

        $plainPin = $null
        $securePin = $null

        if ($addedTpmPin) {
            $file, $text = Save-ManageBdeProtectorsText -MountPoint $MountPoint
            if ($file) { Write-Host "Protectors saved to $file" -ForegroundColor Green }

            $kp = (Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction SilentlyContinue).KeyProtector
            $tpmOnly = $kp | Where-Object { $_.KeyProtectorType -eq 'Tpm' }
            if ($tpmOnly) {
                Write-Host "`nFound TPM-only protector(s):" -ForegroundColor Cyan
                $tpmOnly | Format-Table KeyProtectorId, KeyProtectorType -AutoSize
                Write-Host "Removing TPM-only protectors will force the system to require TPM+PIN at pre-boot and is irreversible without the recovery key." -ForegroundColor Yellow
                Write-Host "The recovery protector has been saved to the backup folder. Confirm you have it before deleting TPM-only protectors." -ForegroundColor Yellow

                $confirm = Read-Host "Type DELETE to permanently remove TPM-only protectors (or press Enter to skip)"
                if ($confirm -eq 'DELETE') {
                    foreach ($prot in $tpmOnly) {
                        try {
                            Write-Host "Removing protector ID $($prot.KeyProtectorId) ..." -ForegroundColor Cyan
                            manage-bde -protectors -delete $MountPoint -id "$($prot.KeyProtectorId)" | Out-Null
                            Write-Host "Removed $($prot.KeyProtectorId)" -ForegroundColor Green
                        } catch {
                            Write-Warning "Failed to remove protector $($prot.KeyProtectorId): $($_.Exception.Message)"
                        }
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
    Write-Host "`nTPM+PIN enforcement disabled by configuration. Skipping automatic creation." -ForegroundColor Cyan
}

# Final verification
Write-Host "`n== Verification ==" -ForegroundColor Cyan
manage-bde -protectors -get $MountPoint
Get-BitLockerVolume -MountPoint $MountPoint | Format-List *

Write-Host "`n== Done. ==" -ForegroundColor Green

# Final strong warning
Write-Host "`nLAST WARNING: BACKUP YOUR RECOVERY KEY NOW. If something goes wrong and you do NOT have this key, you will be locked out of your machine!" -ForegroundColor Red