; Plex Command Center - self-contained Windows installer
;
; This installer bundles Node.js, ffmpeg, ffprobe, yt-dlp, and pre-built node_modules.
; End users do not need any prerequisites - download, run, done.
;
; To rebuild the .exe, run:    build-installer.ps1
; (That script stages everything into windows\staging\ then calls ISCC on this file.)

#define MyAppName     "Plex Command Center"
#define MyAppVersion  "3.0.0"
#define MyServiceName "PlexCommandCenter"
#define MyAppPublisher "Plex Command Center"

[Setup]
; A stable GUID - DO NOT regenerate, otherwise upgrade detection breaks.
AppId={{8A7B3C2E-1F4D-4A5B-9C8E-7F6E5D4C3B2A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/
AppSupportURL=https://github.com/
DefaultDirName={autopf}\PlexCommandCenter
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=PlexCommandCenter-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\public\favicon.ico
ShowLanguageDialog=no
CloseApplications=force
CloseApplicationsFilter=*.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "openbrowser"; Description: "Open the dashboard in your browser when done"; Flags: checkedonce
Name: "migratedata"; Description: "Migrate existing Docker data\ folder (if found next to this installer)"; Flags: unchecked

[Files]
; Bundle the entire pre-staged tree (app + bundled Node + ffmpeg/yt-dlp + node_modules).
; build-installer.ps1 assembles this directory before invoking ISCC.
Source: "staging\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Optional env template
Source: "env.example.txt"; DestDir: "{app}"; DestName: ".env.example"; Flags: ignoreversion onlyifdoesntexist

[Dirs]
; Permissions: users-full so the LocalSystem service can also write the dir if launched
; via a non-default account later (rare, but harmless).
Name: "{commonappdata}\PlexCommandCenter";                  Permissions: users-full
Name: "{commonappdata}\PlexCommandCenter\logs";             Permissions: users-full
Name: "{commonappdata}\PlexCommandCenter\fillers";          Permissions: users-full
Name: "{commonappdata}\PlexCommandCenter\fillers\uploads";  Permissions: users-full
Name: "{commonappdata}\PlexCommandCenter\subs";             Permissions: users-full

[Icons]
Name: "{group}\Open Dashboard";          Filename: "http://localhost:{code:GetPort}"
Name: "{group}\Restart Service";         Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName} & sc start {#MyServiceName}"; WorkingDir: "{app}"; Flags: runminimized
Name: "{group}\Open Data Folder";        Filename: "{commonappdata}\PlexCommandCenter"
Name: "{group}\Open Install Folder";     Filename: "{app}"
Name: "{group}\Uninstall {#MyAppName}";  Filename: "{uninstallexe}"

[Run]
; --- (1) Optional: migrate Docker data --------------------------------------
Filename: "{cmd}"; \
  Parameters: "/C xcopy ""{src}\data\*"" ""{commonappdata}\PlexCommandCenter\"" /E /I /Y"; \
  StatusMsg: "Migrating Docker data..."; \
  Flags: runhidden; \
  Tasks: migratedata; \
  Check: HasDockerData

; --- (2) Register + start the Windows Service (uses BUNDLED node.exe) -------
; The env vars seed service-installer.js, which bakes them into the service definition so
; the service uses our bundled Node, our bundled ffmpeg/yt-dlp, and our data dir at runtime.
Filename: "{cmd}"; \
  Parameters: "/C set PCC_DATA_DIR={commonappdata}\PlexCommandCenter&& set PCC_BIN_DIR={app}\bin&& set PORT={code:GetPort}&& ""{app}\node\node.exe"" ""{app}\windows\service-installer.js"""; \
  WorkingDir: "{app}"; \
  StatusMsg: "Registering Windows Service..."; \
  Flags: runhidden waituntilterminated

; --- (3) Optional: open dashboard -------------------------------------------
Filename: "http://localhost:{code:GetPort}"; \
  Description: "Open dashboard"; \
  Flags: postinstall nowait shellexec skipifsilent; \
  Tasks: openbrowser

[UninstallRun]
; Stop + unregister the service before files are removed (otherwise winsw holds locks).
Filename: "{cmd}"; \
  Parameters: "/C ""{app}\node\node.exe"" ""{app}\windows\service-uninstaller.js"""; \
  WorkingDir: "{app}"; \
  RunOnceId: "stopservice"; \
  Flags: runhidden waituntilterminated

[UninstallDelete]
; Sweep generated artifacts the [Files] section doesn't track. node-windows places its
; daemon files in <script-dir>\daemon by default; we handle both possible locations.
Type: filesandordirs; Name: "{app}\daemon"
Type: filesandordirs; Name: "{app}\windows\daemon"
Type: filesandordirs; Name: "{app}\logs"
; Data dir is intentionally NOT touched - see CurUninstallStepChanged for the explicit prompt.

[Code]
var
  PortPage: TInputQueryWizardPage;

// --- Custom wizard page: HTTP port ------------------------------------------
procedure InitializeWizard();
begin
  PortPage := CreateInputQueryPage(wpSelectDir,
    'HTTP Port',
    'On which TCP port should the dashboard listen?',
    'Default is 3001. Pick a different port if you already have something there.');
  PortPage.Add('Port:', False);
  PortPage.Values[0] := '3001';
end;

function GetPort(Param: String): String;
begin
  if PortPage = nil then Result := '3001'
  else if PortPage.Values[0] = '' then Result := '3001'
  else Result := PortPage.Values[0];
end;

// --- "Migrate Docker data" gate ---------------------------------------------
function HasDockerData(): Boolean;
begin
  Result := DirExists(ExpandConstant('{src}\data'));
end;

// --- Stop + uninstall the service BEFORE replacing files (for upgrades) ----
// Just stopping isn't enough - winsw may hold file handles. svc.uninstall() does a clean
// stop + handle release + registration removal. We invoke the OLD bundled node + OLD
// uninstaller script (still in place from the previous install) so we don't depend on
// system Node existing at all.
function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if Exec(ExpandConstant('{sys}\sc.exe'), 'query {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := (ResultCode = 0);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  OldNodeExe, OldUninstaller, AppDir: String;
begin
  if CurStep = ssInstall then
  begin
    if ServiceExists() then
    begin
      AppDir := ExpandConstant('{app}');
      OldNodeExe := AppDir + '\node\node.exe';
      OldUninstaller := AppDir + '\windows\service-uninstaller.js';
      if FileExists(OldNodeExe) and FileExists(OldUninstaller) then
        Exec(OldNodeExe, '"' + OldUninstaller + '"', AppDir, SW_HIDE, ewWaitUntilTerminated, ResultCode)
      else
        // Fallback: best-effort stop only (handles may not release immediately)
        Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Sleep(2000);
    end;
  end;
end;

// --- Uninstall confirm: offer to wipe data dir ------------------------------
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\PlexCommandCenter');
    if DirExists(DataDir) then
      if MsgBox(
        'Also remove the data folder (DBs, fillers, sub cache)?' + #13#10 + #13#10 +
        DataDir + #13#10 + #13#10 +
        'Choose No to keep your data for a future re-install.',
        mbConfirmation, MB_YESNO) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
