# STAI Windows Protection installer

The installer is a per-machine WiX v4 MSI. It installs the service and signed rule files, records the dashboard user's SID, locks the protection database/quarantine directories to SYSTEM and administrators, configures service recovery restarts, installs the minifilter from its INF, then waits for the local pipe to report a healthy service, driver, and rules package. Before changing service or driver state, it registers a SYSTEM startup rollback task backed by a protected ProgramData marker/helper. If rollback cannot unload/remove the filter safely, the marker and task remain and automatic starts are disabled so cleanup can retry after reboot. A committed install marker prevents recovery from removing a healthy installation. Uninstall stops and unloads the service/filter before removing files; it deliberately leaves `C:\ProgramData\STAI\Protection` and quarantine contents in place.

## Build a test-channel package

Build the service with the Ed25519 **public** key whose private key signed the test rules package. Keep the signing private key out of the repository and off the endpoint. Then provide a WDK-built driver package directory containing `StaiProtection.inf`, `StaiProtection.sys`, and `StaiProtection.cat`, plus a rules directory containing `manifest.json` and `manifest.sig`:

```powershell
powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-service.ps1 `
  -Configuration Test -TrustedRulesPublicKeyPath C:/secure-build/rules-public.pem

powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-installer.ps1 `
  -Configuration Test `
  -ServiceExePath windows_protection/installer/build/Test/dist/STAIProtectionService.exe `
  -DriverPackagePath C:/secure-build/driver `
  -SignedRulesPackagePath C:/secure-build/rules
```

The rule package is checked by the exact embedded public key before WiX runs. Test-channel metadata always marks the package non-production. Install it only in an isolated Windows 10/11 x64 VM with test signing enabled. This host has no built driver package, so an MSI has not been produced or installed here.

## Production release candidate

Build the service executable with the same trusted rules public key and a code-signing certificate available in the Windows certificate store. Before a Release build, the release owner must approve the publisher certificate and pin its thumbprint in `release-policy.json`; the checked-in policy is intentionally blocked. Release builds require `signtool.exe`; the service EXE and final MSI are both signed and verified. Supply release evidence JSON containing passing `microsoft_signed_driver`, `allocated_altitude`, and `clean_windows_vm_validation` gates. The VM evidence must list every required installer, enforcement, rollback, and test-signature assertion as passed. The build emits a separate `build/Release/release-readiness.json` only after SignTool verifies the final MSI; the checked-in readiness file remains blocked until the organization adds its actual evidence.

```powershell
powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-service.ps1 `
  -Configuration Release `
  -TrustedRulesPublicKeyPath C:/secure-build/rules-public.pem `
  -SigningCertificateThumbprint <certificate-thumbprint>

powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-installer.ps1 `
  -Configuration Release `
  -ServiceExePath windows_protection/installer/build/Release/dist/STAIProtectionService.exe `
  -DriverPackagePath C:/secure-build/microsoft-signed-driver `
  -SignedRulesPackagePath C:/secure-build/rules `
  -ReleaseEvidencePath C:/secure-build/release-evidence.json `
  -SigningCertificateThumbprint <certificate-thumbprint>
```

## Staged update and recovery

Run the installed `update.ps1` from the protected Program Files directory and pass the staged package directory produced by `build-installer.ps1`. It verifies the new rules with both the current and staged service binaries, records last-known-good service/driver/rules backups, and commits only after the named pipe reports healthy. Once the journal is written and before service/filter changes begin, it registers a SYSTEM startup recovery task. If Windows restarts during an update, the task runs the installed updater to restore the recorded baseline. An administrator can also run `update.ps1 -Recover -RecoveryInstallRoot <installed protection directory>` manually. Test-channel updates require `-AllowTestPackage` and a test-signing VM.

## Production gate

`release-readiness.json` and `release-policy.json` are intentionally blocked. A Release build requires the organization's approved service/MSI publisher thumbprint to be pinned in the release policy, an approved code-signing EKU, a Microsoft hardware-driver EKU and SignTool kernel-policy verification for the driver catalog and its INF/SYS members, a reviewed Microsoft Hardware Dev Center altitude record, passing clean Windows VM install/enforcement/rollback results, and signed release artifacts. The altitude evidence JSON must include `issuer`, `filter_name`, `altitude`, `reference_id`, official `source_url`, `reviewed_by`, `reviewed_utc`, `official_record_file`, and `official_record_sha256`; the builder checks the official HTTPS host and the allocation document's SHA-256. Its exact numeric altitude must match the INF. The gate compares numeric altitude values, so `329999.0` is also rejected. No subject-name substring is treated as proof of a production signer.

No signed `.sys`/`.cat`, Microsoft altitude allocation, isolated VM results, or independent antivirus lab evaluation is present. STAI must not be described as production-ready, active, or equivalent to Bitdefender based on this package source alone.
