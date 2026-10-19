[CmdletBinding()]
param([switch] $Disable)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$dataRoot = Join-Path $env:ProgramData "STAI\Protection"
$credentialDirectory = Join-Path $dataRoot "ai"
$credentialPath = Join-Path $credentialDirectory "gemini.key.dpapi"
$consentPath = Join-Path $credentialDirectory "cloud-triage-enabled"
if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
    throw "STAI Protection is not installed. Install the protection package first."
}
if ($Disable) {
    foreach ($path in @($consentPath, $credentialPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    if ((Test-Path -LiteralPath $consentPath) -or (Test-Path -LiteralPath $credentialPath)) {
        throw "The stored triage consent or credential remains; revocation was not confirmed."
    }
    Write-Host "Cloud triage has been disabled and the locally stored credential removed. Restart STAIProtection to apply the change."
    exit 0
}

Add-Type -ReferencedAssemblies "System.Security" -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

public static class StaiProtectionCredential {
    public static byte[] Protect(SecureString value) {
        IntPtr pointer = IntPtr.Zero;
        byte[] clear = null;
        try {
            pointer = Marshal.SecureStringToBSTR(value);
            string text = Marshal.PtrToStringBSTR(pointer);
            clear = Encoding.UTF8.GetBytes(text);
            return ProtectedData.Protect(clear, null, DataProtectionScope.LocalMachine);
        } finally {
            if (clear != null) Array.Clear(clear, 0, clear.Length);
            if (pointer != IntPtr.Zero) Marshal.ZeroFreeBSTR(pointer);
        }
    }
}
'@

$consent = Read-Host "Enable optional cloud triage? This sends coarse detection metadata and your questions to Google Gemini. Type ENABLE to consent"
if ($consent -cne "ENABLE") { throw "Cloud triage was not enabled; no credential was stored." }

$secret = Read-Host "Gemini API key (stored encrypted with Windows DPAPI)" -AsSecureString
if ($secret.Length -lt 1) { throw "The API key cannot be empty." }
$encrypted = [StaiProtectionCredential]::Protect($secret)
$secret.Dispose()

New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
$directoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
    $identityRef = [System.Security.Principal.SecurityIdentifier]::new($sid)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identityRef,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $directoryAcl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $credentialDirectory -AclObject $directoryAcl
[System.IO.File]::WriteAllBytes($credentialPath, $encrypted)
[Array]::Clear($encrypted, 0, $encrypted.Length)
[System.IO.File]::WriteAllText($consentPath, "stai-cloud-triage-consent-v1`n", [System.Text.UTF8Encoding]::new($false))

$fileAcl = [System.Security.AccessControl.FileSecurity]::new()
$fileAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
    $identityRef = [System.Security.Principal.SecurityIdentifier]::new($sid)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identityRef,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $fileAcl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $credentialPath -AclObject $fileAcl
Write-Host "Cloud triage consent and an encrypted credential were saved under $credentialDirectory. Restart STAIProtection to load them."
