;------------------------------------------------------------------------------
; Wyrm — installer/windows.iss
; Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
; Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
; Authors: @oda, @sopi, @kwan
;------------------------------------------------------------------------------
; Inno Setup script: builds dist\Wyrm-Setup-<version>.exe from the PyInstaller folder.
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\windows.iss
#define AppName "Wyrm Browser"
#define AppVersion "0.0.3"
#define AppPublisher "HackPi"
#define AppExe "Wyrm.exe"

[Setup]
AppId={{6E2B1C55-8F3A-4C2E-9B7D-4A1F0D9E7C31}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppCopyright=Copyright (c) 2023-{#GetDateTimeString('yyyy', '', '')} {#AppPublisher}
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoCopyright=Copyright (c) 2023-{#GetDateTimeString('yyyy', '', '')} {#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
DefaultDirName={autopf}\HackPi\Hidden Browser
DefaultGroupName=HackPi
DisableProgramGroupPage=yes
; install per-user without admin rights by default; the user can choose all-users in the dialog
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=Wyrm-Setup-{#AppVersion}
SetupIconFile=..\wyrm\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\Wyrm\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
; in-app updates: "Restart now" passes /RELAUNCH (start the new version); "Later" installs on close without it
Filename: "{app}\{#AppExe}"; Flags: nowait; Check: WantRelaunch

[Code]
function WantRelaunch: Boolean;
begin
  Result := WizardSilent and (Pos('/RELAUNCH', Uppercase(GetCmdTail)) > 0);
end;
