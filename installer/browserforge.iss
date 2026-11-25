#ifndef AppVersion
  #define AppVersion "0.5.3"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\installer_stage"
#endif
#ifndef ArchSuffix
  #define ArchSuffix "x64"
#endif
#ifndef ArchMode
  #define ArchMode "x64compatible"
#endif

[Setup]
AppId={{7B2E6A4E-9C3D-4F1A-B8E5-3D4A6F8E2C19}
AppName=BrowserForge
AppVersion={#AppVersion}
AppVerName=BrowserForge {#AppVersion}
AppPublisher=BrowserForge
AppPublisherURL=https://github.com/yattin/browserforge
AppSupportURL=https://github.com/yattin/browserforge/issues
AppUpdatesURL=https://github.com/yattin/browserforge/releases
DefaultDirName={localappdata}\BrowserForge
DefaultGroupName=BrowserForge
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed={#ArchMode}
ArchitecturesInstallIn64BitMode={#ArchMode}
OutputDir=..\dist
OutputBaseFilename=BrowserForge-Setup-v{#AppVersion}-{#ArchSuffix}
SetupIconFile=..\assets\browserforge.ico
UninstallDisplayIcon={app}\browserforge.ico
UninstallDisplayName=BrowserForge {#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut / 创建桌面图标"; GroupDescription: "Shortcuts & System Integration:"
Name: "startup"; Description: "Start BrowserForge automatically with Windows / 开机自动启动"; GroupDescription: "Shortcuts & System Integration:"
Name: "addpath"; Description: "Add BrowserForge CLI to user PATH / 添加到用户环境变量 PATH"; GroupDescription: "Shortcuts & System Integration:"

[Files]
Source: "{#SourceDir}\browserforge.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\browserforge-daemon.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "..\assets\browserforge.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\browserforge.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\skills\browserforge\*"; DestDir: "{app}\skills\browserforge"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\BrowserForge"; Filename: "{app}\bin\browserforge-daemon.exe"; IconFilename: "{app}\browserforge.ico"; Comment: "BrowserForge — Anti-Detect Browser & CDP Automation"; Tasks: desktopicon
Name: "{group}\BrowserForge"; Filename: "{app}\bin\browserforge-daemon.exe"; IconFilename: "{app}\browserforge.ico"; Comment: "BrowserForge — Anti-Detect Browser & CDP Automation"
Name: "{group}\Uninstall BrowserForge"; Filename: "{uninstallexe}"; IconFilename: "{app}\browserforge.ico"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BrowserForgeDaemon"; ValueData: """{app}\bin\browserforge-daemon.exe"" --quiet"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\bin\browserforge-daemon.exe"; Description: "Launch BrowserForge now / 立即启动 BrowserForge"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopRunningDaemon();
var
  ResultCode: Integer;
  CliPath: String;
begin
  CliPath := ExpandConstant('{app}\bin\browserforge.exe');
  if FileExists(CliPath) then
    Exec(CliPath, 'daemon stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM browserforge-daemon.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningDaemon();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopRunningDaemon();
  Result := True;
end;

procedure AddDirToUserPath(Dir: String);
var
  OldPath, UpperOld, UpperDir, NewPath: String;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OldPath) then
    OldPath := '';
  UpperOld := ';' + UpperCase(OldPath) + ';';
  UpperDir := ';' + UpperCase(Dir) + ';';
  if Pos(UpperDir, UpperOld) > 0 then
    Exit;
  if (OldPath <> '') and (OldPath[Length(OldPath)] <> ';') then
    NewPath := OldPath + ';' + Dir
  else
    NewPath := OldPath + Dir;
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
end;

procedure RemoveDirFromUserPath(Dir: String);
var
  OldPath, Part, NewPath: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OldPath) then
    Exit;
  NewPath := '';
  while OldPath <> '' do
  begin
    P := Pos(';', OldPath);
    if P = 0 then
    begin
      Part := OldPath;
      OldPath := '';
    end
    else
    begin
      Part := Copy(OldPath, 1, P - 1);
      Delete(OldPath, 1, P);
    end;
    if (Part <> '') and (CompareText(Part, Dir) <> 0) then
    begin
      if NewPath <> '' then
        NewPath := NewPath + ';';
      NewPath := NewPath + Part;
    end;
  end;
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addpath') then
    AddDirToUserPath(ExpandConstant('{app}\bin'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveDirFromUserPath(ExpandConstant('{app}\bin'));
end;
