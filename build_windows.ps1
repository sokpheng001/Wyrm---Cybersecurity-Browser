#------------------------------------------------------------------------------
# Wyrm — build_windows.ps1
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
# Build The Hidden Browser on Windows:
#   dist\Wyrm\Wyrm.exe       (portable folder)
#   dist\Wyrm-windows.zip             (portable zip)
#   dist\Wyrm-Setup-<version>.exe     (installer, needs Inno Setup 6: winget install JRSoftware.InnoSetup)
Set-Location $PSScriptRoot
function Invoke-Step($exe) {
    # native tools write notices to stderr; judge success by exit code, not by stderr output
    & $exe @args 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw "Failed ($LASTEXITCODE): $exe $args" }
}
$py = if (Test-Path ..\venv\Scripts\python.exe) { "..\venv\Scripts\python.exe" } else {
    if (-not (Test-Path .venv)) { python -m venv .venv }
    ".\.venv\Scripts\python.exe"
}
Invoke-Step $py -m pip install -q --disable-pip-version-check -r requirements.txt pyinstaller pillow
Invoke-Step $py tools\make_icons.py
Invoke-Step $py tools\fetch_filters.py
Invoke-Step $py -m PyInstaller --noconfirm --clean --log-level WARN wyrm.spec

# Optional Authenticode signing. Set SIGN_PFX (path to a code-signing .pfx) and SIGN_PFX_PASSWORD.
# A certificate from a trusted CA (or Azure Trusted Signing) is what removes SmartScreen/AV "unknown publisher" warnings.
function Set-CodeSignature($file) {
    if (-not $env:SIGN_PFX) { return }
    $cert = Get-PfxCertificate -FilePath $env:SIGN_PFX -Password (ConvertTo-SecureString $env:SIGN_PFX_PASSWORD -AsPlainText -Force)
    $r = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
    Write-Host "Signed $file : $($r.Status)"
}
Set-CodeSignature dist\Wyrm\Wyrm.exe
Compress-Archive -Path dist\Wyrm\* -DestinationPath dist\Wyrm-windows.zip -Force

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    Invoke-Step $iscc /Q installer\windows.iss
    $setup = Get-ChildItem dist\Wyrm-Setup-*.exe | Select-Object -Last 1
    Set-CodeSignature $setup.FullName
    Write-Host "Installer: $setup"
} else {
    Write-Warning "Inno Setup not found; skipped the installer. Install it with: winget install JRSoftware.InnoSetup"
}

