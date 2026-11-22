;------------------------------------------------------------------------------
; Wyrm — installer/windows.iss
; Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
; Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
; Authors: @oda, @sopi, @kwan
;------------------------------------------------------------------------------
; Inno Setup script: builds dist\Wyrm-Setup-<version>.exe from the PyInstaller folder.
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\windows.iss
#define AppName "Wyrm Browser"
#define AppVersion "0.0.8"
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
DefaultDirName={autopf}\HackPi\Wyrm Browser
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

; The ProjectDiscovery tools are optional (ticked by default): some antivirus products label security tools
; such as naabu/nuclei "HackTool", so users can still install the browser without them. Silent updates keep
; whatever the user chose last time (Inno remembers the selected components).
[Types]
Name: "full"; Description: "Full installation (browser + security tools)"
Name: "compact"; Description: "Browser only"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "main"; Description: "Wyrm Browser"; Types: full compact custom; Flags: fixed
Name: "tools"; Description: "ProjectDiscovery security tools (nuclei, katana, subfinder, httpx, naabu, ...) — about 480 MB"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\Wyrm\*"; DestDir: "{app}"; Excludes: "\_internal\wyrm\bin"; Components: main; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\Wyrm\_internal\wyrm\bin\*"; DestDir: "{app}\_internal\wyrm\bin"; Components: tools; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[InstallDelete]
; "Browser only" chosen on an update: remove tools installed earlier
Type: filesandordirs; Name: "{app}\_internal\wyrm\bin"; Components: not tools

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
