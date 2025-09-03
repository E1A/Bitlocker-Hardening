# BitLocker hardening

## What it does

* Ensures an OS-volume recovery password protector exists and saves it to a local backup folder.
* Enables BitLocker on the OS drive (software encryption is the default for compatibility).
* Optionally prefers hardware encryption when explicitly selected; warns if the drive falls back to software.
* Adds a TPM+PIN startup protector (when you re-run the script after encryption is active).
* Optionally removes TPM-only protectors (requires typing `DELETE` to confirm).
* Saves `manage-bde` and protector output to the backup folder for auditing.

---

## Requirements

* Windows client OS (Windows 10 / 11).
* Run **64-bit PowerShell (powershell.exe)** as **Administrator**.
* TPM must be enabled/activated for TPM-based protectors.
* Secure Boot for full PCR-based integrity checks.
* Local machine (Group Policy / MDM may override local registry changes).

---

## Important notes about hardware vs software encryption

* The script defaults to **software encryption (XTS-AES-256)** for compatibility.
* Some self-encrypting drives (SEDs) or vendor firmware do not reliably expose hardware encryption to Windows. Vendors (for example certain Samsung models) may require special preparation (PSID revert / secure erase) before hardware encryption will work.

---

## How to use (clear, step-by-step)

1. **Backup everything important** and make a separate copy of any existing recovery keys. Do this before you run the script.  
2. Open **64-bit PowerShell** **as Administrator**.  
3. Run the script and follow prompts:  

   * Confirm you accept risk.  
   * The script will create and save a recovery password if none exists and will add a TPM protector.  
   * The script enables BitLocker (requires a reboot to run a hardware test).  
4. **IMPORTANT NEXT STEPS (after this first run):**  

   1. If prompted to reboot to run a hardware test, **reboot now**: `shutdown /r /t 0`.  
   2. **Allow BitLocker to finish encryption fully.** Monitor progress with:  

      * `Get-BitLockerVolume -MountPoint C:`  
      * or `manage-bde -status C:`  
   3. Once encryption is complete (EncryptionPercentage = 100 and ProtectionStatus = 1), **reboot again**.  
   4. After that second reboot, **re-run the script** (elevated, 64-bit PowerShell). The script will then add the TPM+PIN protector and remove any TPM-only protectors.  
5. After the final run, verify protectors and status:  

   * `manage-bde -protectors -get C:`
   * `Get-BitLockerVolume -MountPoint C:`

---

## Typical safe flow (summary)

1. Run script → it creates/saves recovery protector and enables BitLocker.
2. Reboot if prompted (hardware test) → encryption starts.
3. Let encryption complete → reboot.
4. Re-run script → script adds TPM+PIN and you may remove TPM-only protectors.

---

## How the script handles recovery keys and deletion

* The script saves `manage-bde` output and a recovery-password text file to the backup folder (default `C:\ProgramData\BitLocker_Backup`).
* The script will **not** delete TPM-only protectors silently. To delete them you must re-run the script after encryption completes and type the literal `DELETE` at the confirmation prompt.

---

## Rotating recovery keys (example)

Add a new recovery password:

```powershell
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector | Out-Null
manage-bde -protectors -get C:
```

Remove older recovery protectors while keeping the newest:

```powershell
$all = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
       Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
       Select-Object -ExpandProperty KeyProtectorId
$latest = $all[-1]
foreach ($id in $all) {
  if ($id -ne $latest) { manage-bde -protectors -delete C: -id "$id" }
}
```

---

## Verification commands

* `Get-BitLockerVolume -MountPoint C:`
* `manage-bde -status C:`
* `manage-bde -protectors -get C:`

Use these to confirm encryption method, percentage, and protector list.

---

## Limitations and cautions

* Domain/MDM: Group Policy can override local registry and policy changes.
* Hardware encryption is device/firmware dependent. If you need guaranteed behavior at scale, prefer software encryption.
* Changing encryption method on an already encrypted volume requires re-encryption.
* The script does not run destructive vendor operations (PSID revert / secure erase). Those are *manual, vendor-specific* steps and are not automated here.

---

## Disclaimer (plain and explicit)

I provide this script as-is. By using it you accept full responsibility for running it and for any consequences. I am **not** responsible for any data loss, system damage, lockout, downtime, or other issues that result from using the script, following its prompts, or from any recovery key handling. It is your decision to run the script; make backups and verify recovery key backups before you proceed.