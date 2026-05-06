program sgcClaudeCodeRemote;

{$APPTYPE CONSOLE}

uses
  System.SysUtils, System.IniFiles, System.Classes,
  Winapi.Windows,
  uServer in 'uServer.pas',
  uConPTY in 'uConPTY.pas';

{$R *.res}
{$R html.res}

procedure PrintUsage;
begin
  WriteLn('Claude Code Remote Terminal Server');
  WriteLn('');
  WriteLn('Usage: sgcClaudeCodeRemote.exe [options]');
  WriteLn('');
  WriteLn('Options:');
  WriteLn('  --port <port>        WebSocket port (default: 8765)');
  WriteLn('  --cols <cols>        Terminal columns (default: 120)');
  WriteLn('  --rows <rows>        Terminal rows (default: 40)');
  WriteLn('  --command <cmd>      Command to run (default: claude)');
  WriteLn('  --password <pwd>     Auth password (required)');
  WriteLn('  --no-auth            Disable authentication');
  WriteLn('  --timeout <sec>      Auth timeout in seconds (default: 15)');
  WriteLn('  --max-conn <n>       Max concurrent connections (default: 10)');
  WriteLn('  --allow-ip <cidr>    Allow IP or range (e.g. 192.168.1.0/24). Repeat for multiple.');
  WriteLn('  --deny-ip <cidr>     Deny IP or range. Repeat for multiple.');
  WriteLn('');
  WriteLn('TLS options:');
  WriteLn('  --tls                Enable TLS 1.3 (requires cert and key)');
  WriteLn('  --tls-cert <file>    Path to certificate file (.pem)');
  WriteLn('  --tls-key <file>     Path to private key file (.pem)');
  WriteLn('  --tls-password <pwd> Private key password (if encrypted)');
  WriteLn('  --tls-port <port>    TLS port (default: same as --port)');
  WriteLn('  --config <file>      Load settings from INI file');
  WriteLn('');
  WriteLn('  --help               Show this help');
  WriteLn('');
  WriteLn('INI file format (default: sgcClaudeCodeRemote.ini):');
  WriteLn('  [Server]');
  WriteLn('  Port=8765');
  WriteLn('  Command=claude');
  WriteLn('  Password=MyPassword');
  WriteLn('  Cols=120');
  WriteLn('  Rows=40');
  WriteLn('  MaxConnections=10');
  WriteLn('  AuthTimeout=15');
  WriteLn('  NoAuth=0');
  WriteLn('');
  WriteLn('  [TLS]');
  WriteLn('  Enabled=0');
  WriteLn('  CertFile=cert.pem');
  WriteLn('  KeyFile=key.pem');
  WriteLn('  Password=');
  WriteLn('  Port=0');
  WriteLn('');
  WriteLn('  [Firewall]');
  WriteLn('  Allow=192.168.1.0/24');
  WriteLn('  Allow=10.0.0.0/8');
  WriteLn('  Deny=203.0.113.0/24');
end;

function GetParamValue(const AName: string; const ADefault: string = ''): string;
var
  I: Integer;
begin
  Result := ADefault;
  for I := 1 to ParamCount - 1 do
  begin
    if SameText(ParamStr(I), AName) then
    begin
      Result := ParamStr(I + 1);
      Exit;
    end;
  end;
end;

function HasParam(const AName: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if SameText(ParamStr(I), AName) then
      Exit(True);
  end;
end;

procedure LoadINI(const AFile: string; AServer: TRemoteServer);
var
  Ini: TIniFile;
  Keys: TStringList;
  I: Integer;
  FWLine, FWValue: string;
begin
  if not FileExists(AFile) then
    Exit;

  WriteLn('Loading config: ' + AFile);
  Ini := TIniFile.Create(AFile);
  try
    // [Server]
    AServer.Port := Ini.ReadInteger('Server', 'Port', AServer.Port);
    AServer.Command := Ini.ReadString('Server', 'Command', AServer.Command);
    AServer.Password := Ini.ReadString('Server', 'Password', AServer.Password);
    AServer.Cols := Ini.ReadInteger('Server', 'Cols', AServer.Cols);
    AServer.Rows := Ini.ReadInteger('Server', 'Rows', AServer.Rows);
    AServer.MaxConnections := Ini.ReadInteger('Server', 'MaxConnections', AServer.MaxConnections);
    AServer.AuthTimeoutSec := Ini.ReadInteger('Server', 'AuthTimeout', AServer.AuthTimeoutSec);
    AServer.PromptMode := Ini.ReadBool('Server', 'PromptMode', False);
    if Ini.ReadBool('Server', 'NoAuth', False) then
      AServer.RequireAuth := False;

    // [TLS]
    AServer.TLSEnabled := Ini.ReadBool('TLS', 'Enabled', AServer.TLSEnabled);
    AServer.TLSCertFile := Ini.ReadString('TLS', 'CertFile', AServer.TLSCertFile);
    AServer.TLSKeyFile := Ini.ReadString('TLS', 'KeyFile', AServer.TLSKeyFile);
    AServer.TLSPassword := Ini.ReadString('TLS', 'Password', AServer.TLSPassword);
    AServer.TLSPort := Ini.ReadInteger('TLS', 'Port', AServer.TLSPort);

    // [Firewall] - multiple Allow=/Deny= lines
    Keys := TStringList.Create;
    try
      Keys.LoadFromFile(AFile);
      FWValue := '';
      for I := 0 to Keys.Count - 1 do
      begin
        FWLine := Trim(Keys[I]);
        if SameText(FWLine, '[Firewall]') then
          FWValue := 'Firewall'
        else if (Length(FWLine) > 0) and (FWLine[1] = '[') then
        begin
          if FWValue = 'Firewall' then Break;
        end
        else if FWValue = 'Firewall' then
        begin
          if SameText(Copy(FWLine, 1, 6), 'Allow=') then
          begin
            AServer.Firewall.Whitelist.Enabled := True;
            AServer.Firewall.Whitelist.IPs.Add(Trim(Copy(FWLine, 7, MaxInt)));
          end
          else if SameText(Copy(FWLine, 1, 5), 'Deny=') then
          begin
            AServer.Firewall.Blacklist.Enabled := True;
            AServer.Firewall.Blacklist.IPs.Add(Trim(Copy(FWLine, 6, MaxInt)));
          end;
        end;
      end;
    finally
      Keys.Free;
    end;

  finally
    Ini.Free;
  end;
end;

var
  Server: TRemoteServer;
  StopEvent: THandle;
  INIFile: string;
  I: Integer;

function ConsoleCtrlHandler(CtrlType: DWORD): BOOL; stdcall;
begin
  SetEvent(StopEvent);
  // Give the main thread time to clean up, then force exit
  Sleep(5000);
  ExitProcess(0);
end;

begin
  try
    if HasParam('--help') or HasParam('-h') then
    begin
      PrintUsage;
      Exit;
    end;

    Server := TRemoteServer.Create;
    try
      // Load INI file (--config or default beside exe)
      INIFile := GetParamValue('--config');
      if INIFile = '' then
        INIFile := ChangeFileExt(ParamStr(0), '.ini');
      LoadINI(INIFile, Server);

      // Command-line overrides
      if HasParam('--port') then
        Server.Port := StrToIntDef(GetParamValue('--port'), Server.Port);
      if HasParam('--cols') then
        Server.Cols := StrToIntDef(GetParamValue('--cols'), Server.Cols);
      if HasParam('--rows') then
        Server.Rows := StrToIntDef(GetParamValue('--rows'), Server.Rows);
      if HasParam('--command') then
        Server.Command := GetParamValue('--command', Server.Command);
      if HasParam('--password') then
        Server.Password := GetParamValue('--password');
      if HasParam('--no-auth') then
        Server.RequireAuth := False;
      if HasParam('--timeout') then
        Server.AuthTimeoutSec := StrToIntDef(GetParamValue('--timeout'), Server.AuthTimeoutSec);
      if HasParam('--max-conn') then
        Server.MaxConnections := StrToIntDef(GetParamValue('--max-conn'), Server.MaxConnections);

      // Firewall (CLI adds to INI entries)
      for I := 1 to ParamCount - 1 do
      begin
        if SameText(ParamStr(I), '--allow-ip') then
        begin
          Server.Firewall.Whitelist.Enabled := True;
          Server.Firewall.Whitelist.IPs.Add(ParamStr(I + 1));
        end
        else if SameText(ParamStr(I), '--deny-ip') then
        begin
          Server.Firewall.Blacklist.Enabled := True;
          Server.Firewall.Blacklist.IPs.Add(ParamStr(I + 1));
        end;
      end;

      // TLS (CLI overrides)
      if HasParam('--tls') then
        Server.TLSEnabled := True;
      if HasParam('--tls-cert') then
        Server.TLSCertFile := GetParamValue('--tls-cert');
      if HasParam('--tls-key') then
        Server.TLSKeyFile := GetParamValue('--tls-key');
      if HasParam('--tls-password') then
        Server.TLSPassword := GetParamValue('--tls-password');
      if HasParam('--tls-port') then
        Server.TLSPort := StrToIntDef(GetParamValue('--tls-port'), 0);

      Server.Start;

      WriteLn('');
      WriteLn('Press Ctrl+C to stop the server.');
      WriteLn('');

      // Wait for Ctrl+C
      StopEvent := CreateEvent(nil, True, False, nil);
      try
        SetConsoleCtrlHandler(@ConsoleCtrlHandler, True);
        WaitForSingleObject(StopEvent, INFINITE);
      finally
        CloseHandle(StopEvent);
      end;

      WriteLn('');
      WriteLn('Shutting down...');
      Server.Stop;
    finally
      Server.Free;
    end;
  except
    on E: Exception do
    begin
      WriteLn('FATAL: ' + E.Message);
      ExitCode := 1;
    end;
  end;
end.
