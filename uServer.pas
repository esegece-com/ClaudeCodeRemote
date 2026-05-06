unit uServer;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes,
  System.Generics.Collections, System.DateUtils, System.Hash,
  // sgcWebSockets
  sgcWebSocket, sgcWebSocket_Server, sgcWebSocket_Types,
  sgcWebSocket_Classes, sgcBase_Classes,
  // Indy
  sgcIdContext, sgcIdCustomHTTPServer,
  // ConPTY
  uConPTY, sgcSocket_Classes, sgcTCP_Classes,
  sgcWebSocket_Server_Firewall;

type
  TClientState = class
    Authenticated: Boolean;
    ConnectTime: TDateTime;
    IP: string;
    SessionName: string;
    ConPTY: TConPTY;
    Connection: TsgcWSConnection;
    LastPong: TDateTime;
  end;

  TScheduledSession = class
    Name: string;
    Prompt: string;
    StartTime: TDateTime;
    SkipPerms: Boolean;
    Started: Boolean;
    AfterSession: string; // Start after this session's process exits (empty = use timer)
  end;

  TRemoteServer = class
  private
    FServer: TsgcWebSocketHTTPServer;
    FSessions: TDictionary<string, TConPTY>;
    FConnectionCount: Integer;
    FLock: TRTLCriticalSection;
    FLastActivity: TDictionary<string, TDateTime>;
    FLastOutput: TDictionary<string, TDateTime>;
    FCleanupThread: TThread;
    FScheduledSessions: TObjectList<TScheduledSession>;

    // Config
    FPort: Integer;
    FCols: Integer;
    FRows: Integer;
    FCommand: string;
    FPassword: string;
    FRequireAuth: Boolean;
    FAuthTimeoutSec: Integer;
    FStartTime: TDateTime;
    FWorkDir: string;
    FPromptMode: Boolean;

    // Limits
    FMaxConnections: Integer;

    // TLS
    FTLSEnabled: Boolean;
    FTLSCertFile: string;
    FTLSKeyFile: string;
    FTLSPassword: string;
    FTLSPort: Integer;

    // Auth state
    FClientStates: TObjectDictionary<string, TClientState>;

    procedure Log(const AMsg: string);

    // ConPTY
    function StartNewConPTY(const ACommand: string): TConPTY;
    procedure OnConPTYData(Sender: TObject; const AData: TBytes);
    procedure OnConPTYExit(Sender: TObject; AExitCode: DWORD);

    // WebSocket events
    procedure OnConnect(Connection: TsgcWSConnection);
    procedure OnDisconnect(Connection: TsgcWSConnection; Code: Integer);
    procedure OnMessage(Connection: TsgcWSConnection; const Text: string);
    procedure OnBinary(Connection: TsgcWSConnection; const Data: TMemoryStream);
    procedure HandleCommandGet(AContext: TIdContext;
      ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);

    // Targeted output
    procedure SendToConPTYClients(AConPTY: TConPTY; const AData: TBytes);
    procedure NotifySessionClients(const ASessionName: string;
      const AMessage: string);
    procedure BroadcastClientCount(const ASessionName: string);

    // Session helpers
    function GetOrCreateSession(const AName: string;
      ASkipPerms: Boolean; out AIsNew: Boolean): TConPTY;
    // Auth helpers
    function GetClientState(Connection: TsgcWSConnection): TClientState;
    function IsAuthenticated(Connection: TsgcWSConnection): Boolean;
    function ValidateCredentials(const AUser, APassword: string): Boolean;
    function GenerateSessionToken: string;
    procedure SendAuthRequired(Connection: TsgcWSConnection);
    procedure SendAuthResult(Connection: TsgcWSConnection; ASuccess: Boolean;
      const AMessage: string; const AToken: string = '');
    procedure DisconnectClient(Connection: TsgcWSConnection;
      const AReason: string);
    procedure BroadcastSessionsList;
    procedure BroadcastSchedulesList;
    procedure SendSchedulesTo(Connection: TsgcWSConnection);
    procedure SaveSchedules;
    procedure LoadSchedules;
    procedure OnFirewallFiltered(Sender: TObject; const aIP: string;
      const AReason: string; var Allow: Boolean);
    procedure OnFirewallViolation(Sender: TObject; const aIP: string;
      const aViolationType: TsgcFirewallViolationType; const aDetails: string);
  public
    constructor Create;
    destructor Destroy; override;

    procedure Start;
    procedure Stop;

    property Port: Integer read FPort write FPort;
    property Cols: Integer read FCols write FCols;
    property Rows: Integer read FRows write FRows;
    property Command: string read FCommand write FCommand;
    property Password: string read FPassword write FPassword;
    property RequireAuth: Boolean read FRequireAuth write FRequireAuth;
    property AuthTimeoutSec: Integer read FAuthTimeoutSec write FAuthTimeoutSec;
    property MaxConnections: Integer read FMaxConnections write FMaxConnections;
    property PromptMode: Boolean read FPromptMode write FPromptMode;

    function GetFirewall: TsgcWSFirewall;
    property Firewall: TsgcWSFirewall read GetFirewall;

    // TLS
    property TLSEnabled: Boolean read FTLSEnabled write FTLSEnabled;
    property TLSCertFile: string read FTLSCertFile write FTLSCertFile;
    property TLSKeyFile: string read FTLSKeyFile write FTLSKeyFile;
    property TLSPassword: string read FTLSPassword write FTLSPassword;
    property TLSPort: Integer read FTLSPort write FTLSPort;
    property WorkDir: string read FWorkDir write FWorkDir;
  end;

implementation

uses
  System.JSON, System.IOUtils;

const
  MAX_FAILED_ATTEMPTS = 5;
  BLOCK_DURATION_MIN = 5;
  MAX_COLS = 500;
  MAX_ROWS = 200;
  MIN_COLS = 10;
  MIN_ROWS = 2;

  { TRemoteServer }

constructor TRemoteServer.Create;
begin
  inherited;
  InitializeCriticalSection(FLock);
  FConnectionCount := 0;

  FPort := 8765;
  FCols := 120;
  FRows := 40;
  FCommand := 'claude';
  FPassword := '';
  FRequireAuth := True;
  FAuthTimeoutSec := 15;
  FMaxConnections := 10;
  FTLSEnabled := False;
  FTLSPort := 0;
  FStartTime := Now;
  FWorkDir := GetCurrentDir;
  FPromptMode := False;

  FClientStates := TObjectDictionary<string, TClientState>.Create
    ([doOwnsValues]);
  FSessions := TDictionary<string, TConPTY>.Create;
  FLastActivity := TDictionary<string, TDateTime>.Create;
  FLastOutput := TDictionary<string, TDateTime>.Create;
  FScheduledSessions := TObjectList<TScheduledSession>.Create(True);
  LoadSchedules;

  FServer := TsgcWebSocketHTTPServer.Create(nil);
  FServer.NotifyEvents := neNoSync;
  FServer.OnConnect := OnConnect;
  FServer.OnDisconnect := OnDisconnect;
  FServer.OnMessage := OnMessage;
  FServer.OnBinary := OnBinary;
  FServer.OnCommandGet := HandleCommandGet;

  // Firewall ? assigned to the server, which handles all checks internally
  FServer.Firewall := TsgcWSFirewall.Create(FServer);
  FServer.Firewall.Enabled := True;
  FServer.Firewall.BruteForce.Enabled := True;
  FServer.Firewall.BruteForce.MaxAttempts := MAX_FAILED_ATTEMPTS;
  FServer.Firewall.BruteForce.BanDurationSec := BLOCK_DURATION_MIN * 60;
  FServer.Firewall.OnFiltered := OnFirewallFiltered;
  FServer.Firewall.OnViolation := OnFirewallViolation;
end;

destructor TRemoteServer.Destroy;
begin
  Stop;
  FServer.Free;
  FClientStates.Free;
  FLastActivity.Free;
  FLastOutput.Free;
  FScheduledSessions.Free;
  FSessions.Free;
  DeleteCriticalSection(FLock);
  inherited;
end;

procedure TRemoteServer.Log(const AMsg: string);
begin
  WriteLn(FormatDateTime('hh:nn:ss', Now) + ' | ' + AMsg);
end;

// =========================================================================
// Start / Stop
// =========================================================================

procedure TRemoteServer.Start;
var
  vIsNew: Boolean;
begin
  if FRequireAuth and (Trim(FPassword) = '') then
  begin
    WriteLn('ERROR: Password is required when auth is enabled. Use --password <pwd>');
    Halt(1);
  end;

  FServer.Port := FPort;

  // TLS configuration
  if FTLSEnabled then
  begin
    if not FileExists(FTLSCertFile) then
    begin
      WriteLn('ERROR: Certificate file not found: ' + FTLSCertFile);
      Halt(1);
    end;
    if (FTLSKeyFile <> '') and not FileExists(FTLSKeyFile) then
    begin
      WriteLn('ERROR: Key file not found: ' + FTLSKeyFile);
      Halt(1);
    end;

    FServer.SSLOptions.CertFile := FTLSCertFile;
    FServer.SSLOptions.KeyFile := FTLSKeyFile;
    FServer.SSLOptions.Password := FTLSPassword;
    FServer.SSLOptions.Version := tls1_3;
    FServer.SSLOptions.OpenSSL_Options.APIVersion := oslAPI_3_0;
    if FTLSPort > 0 then
      FServer.SSLOptions.Port := FTLSPort
    else
      FServer.SSLOptions.Port := FPort;
  end;

  try
    FServer.Active := True;
  except
    on E: Exception do
    begin
      WriteLn(Format('ERROR: Could not start server on port %d. %s',
        [FPort, E.Message]));
      WriteLn('Hint: Another process may already be using this port.');
      Halt(1);
    end;
  end;
  Log(Format('WebSocket server started on port %d', [FPort]));

  if FTLSEnabled then
    Log(Format('TLS 1.3 ENABLED (cert: %s, port: %d)',
      [ExtractFileName(FTLSCertFile), FServer.SSLOptions.Port]));

  Log(Format('Max connections: %d', [FMaxConnections]));

  if not FRequireAuth then
  begin
    Log('WARNING: Auth DISABLED - anyone can connect!');
    GetOrCreateSession('default', False, vIsNew);
  end
  else
  begin
    Log(Format('Auth ENABLED (timeout: %ds)', [FAuthTimeoutSec]));
    Log('Sessions created on demand after authentication.');
  end;

  if FServer.Firewall.Whitelist.Enabled then
    Log(Format('Firewall: whitelist ENABLED (%d entries)', [FServer.Firewall.Whitelist.IPs.Count]))
  else if FServer.Firewall.Blacklist.Enabled then
    Log(Format('Firewall: blacklist ENABLED (%d entries)', [FServer.Firewall.Blacklist.IPs.Count]))
  else
    Log('Firewall: IP filtering DISABLED');
  if FServer.Firewall.BruteForce.Enabled then
    Log(Format('Brute-force protection: %d attempts, ban %ds',
      [FServer.Firewall.BruteForce.MaxAttempts,
      FServer.Firewall.BruteForce.BanDurationSec]));

  if FTLSEnabled then
    Log(Format('Open browser: https://localhost:%d/',
      [FServer.SSLOptions.Port]))
  else
    Log(Format('Open browser: http://localhost:%d/', [FPort]));
  Log('QR code page: /qr');

  FCleanupThread := TThread.CreateAnonymousThread(procedure
    var
      Sessions: TList<string>;
      S: string;
      LastTime: TDateTime;
      JSON: TJSONObject;
      Msg: string;
      WarnMsg: string;
      PTY: TConPTY;
      ClientPair: TPair<string, TClientState>;
      vActive: Boolean;
      PingMsg, DeadKey: string;
      DeadClients: TList<string>;
      DeadState: TClientState;
      SchedI: Integer;
      SchedItem: TScheduledSession;
      SchedPTY: TConPTY;
      vSchedIsNew: Boolean;
      ReadyScheds: TList<TScheduledSession>;
    begin
      while not TThread.Current.CheckTerminated do
      begin
        Sleep(5000); // Check every 5 seconds (was 30s)
        if TThread.Current.CheckTerminated then
          Break;

        // Ping all authenticated clients and detect dead connections
        // Wrapped in try/except so any failure here NEVER kills the scheduler.
        try
          EnterCriticalSection(FLock);
          try
            PingMsg := '{"type":"ping"}';
            DeadClients := TList<string>.Create;
            try
              for ClientPair in FClientStates do
              begin
                if ClientPair.Value.Authenticated then
                begin
                  // Heartbeat threshold (90s) is independent of loop interval
                  if SecondsBetween(Now, ClientPair.Value.LastPong) > 90 then
                    DeadClients.Add(ClientPair.Key)
                  else
                  begin
                    try
                      ClientPair.Value.Connection.WriteData(PingMsg);
                    except
                    end;
                  end;
                end;
              end;

              // Disconnect dead clients
              for DeadKey in DeadClients do
              begin
                if FClientStates.TryGetValue(DeadKey, DeadState) then
                begin
                  Log('HEARTBEAT: disconnecting unresponsive client ' +
                    DeadState.IP);
                  try
                    DeadState.Connection.Close;
                  except
                  end;
                end;
              end;
            finally
              DeadClients.Free;
            end;
          finally
            LeaveCriticalSection(FLock);
          end;
        except
          on E: Exception do
            Log('Cleanup ping error: ' + E.Message);
        end;

        // Check scheduled sessions ? collect all ready ones
        // CRITICAL: this section MUST keep running even if every other
        // section above/below fails. Schedules are the whole point of
        // running the server while no client is connected.
        try
          ReadyScheds := TList<TScheduledSession>.Create;
          try
            EnterCriticalSection(FLock);
            try
              for SchedI := 0 to FScheduledSessions.Count - 1 do
              begin
                SchedItem := FScheduledSessions[SchedI];
                if (not SchedItem.Started) and (SchedItem.AfterSession = '') and (Now >= SchedItem.StartTime) then
                begin
                  SchedItem.Started := True;
                  ReadyScheds.Add(SchedItem);
                end;
              end;
              if ReadyScheds.Count > 0 then
                SaveSchedules;
            finally
              LeaveCriticalSection(FLock);
            end;

            // Start each ready schedule
            for SchedI := 0 to ReadyScheds.Count - 1 do
            begin
              SchedItem := ReadyScheds[SchedI];
              Log(Format('STARTING scheduled session: "%s"', [SchedItem.Name]));
              SchedPTY := nil;
              EnterCriticalSection(FLock);
              try
                try
                  SchedPTY := GetOrCreateSession(SchedItem.Name,
                    SchedItem.SkipPerms, vSchedIsNew);
                except
                  on E: Exception do
                    Log('Schedule start error: ' + E.Message);
                end;
              finally
                LeaveCriticalSection(FLock);
              end;
              if Assigned(SchedPTY) and (SchedItem.Prompt <> '') then
              begin
                Sleep(3000); // Wait for Claude Code to start
                try
                  SchedPTY.WriteInput(TEncoding.UTF8.GetBytes(
                    SchedItem.Prompt + #13));
                  Log('Scheduled prompt sent: ' +
                    Copy(SchedItem.Prompt, 1, 50));
                except
                  on E: Exception do
                    Log('Schedule prompt write error: ' + E.Message);
                end;
              end;
            end;

            // Broadcast updated schedule status
            if ReadyScheds.Count > 0 then
            begin
              EnterCriticalSection(FLock);
              try
                BroadcastSchedulesList;
              finally
                LeaveCriticalSection(FLock);
              end;
            end;
          finally
            ReadyScheds.Free;
          end;
        except
          on E: Exception do
            Log('Schedule check error: ' + E.Message);
        end;

        // Broadcast activity status every iteration
        try
          EnterCriticalSection(FLock);
          try
            for S in FSessions.Keys.ToArray do
            begin
              if FLastOutput.TryGetValue(S, LastTime) then
                vActive := SecondsBetween(Now, LastTime) < 10
              else
                vActive := False;

              JSON := TJSONObject.Create;
              try
                JSON.AddPair('type', 'activity');
                JSON.AddPair('active', TJSONBool.Create(vActive));
                Msg := JSON.ToString;
              finally
                JSON.Free;
              end;
              NotifySessionClients(S, Msg);
            end;
          finally
            LeaveCriticalSection(FLock);
          end;
        except
          on E: Exception do
            Log('Activity broadcast error: ' + E.Message);
        end;

        // Idle session cleanup
        try
          Sessions := TList<string>.Create;
          try
            EnterCriticalSection(FLock);
            try
              for S in FLastActivity.Keys do
              begin
                if FLastActivity.TryGetValue(S, LastTime) then
                begin
                  if MinutesBetween(Now, LastTime) > 60 then
                    Sessions.Add(S)
                  else if MinutesBetween(Now, LastTime) >= 55 then
                  begin
                    // Send idle warning
                    JSON := TJSONObject.Create;
                    try
                      JSON.AddPair('type', 'idle_warning');
                      JSON.AddPair('minutes',
                        TJSONNumber.Create(60 - MinutesBetween(Now, LastTime)));
                      WarnMsg := JSON.ToString;
                    finally
                      JSON.Free;
                    end;
                    NotifySessionClients(S, WarnMsg);
                  end;
                end;
              end;
            finally
              LeaveCriticalSection(FLock);
            end;

            for S in Sessions do
            begin
              Log(Format
                ('Session "%s" idle timeout (>60 min). Cleaning up.', [S]));
              JSON := TJSONObject.Create;
              try
                JSON.AddPair('type', 'session_expired');
                JSON.AddPair('session', S);
                Msg := JSON.ToString;
              finally
                JSON.Free;
              end;

              PTY := nil;
              EnterCriticalSection(FLock);
              try
                NotifySessionClients(S, Msg);
                // Clear ConPTY from clients
                for ClientPair in FClientStates do
                begin
                  if ClientPair.Value.SessionName = S then
                    ClientPair.Value.ConPTY := nil;
                end;
                // Remove session
                if FSessions.TryGetValue(S, PTY) then
                begin
                  FSessions.Remove(S);
                  FLastActivity.Remove(S);
                  BroadcastSessionsList;
                end;
              finally
                LeaveCriticalSection(FLock);
              end;

              if Assigned(PTY) then
              begin
                PTY.Stop;
                PTY.Free;
              end;
            end;
          finally
            Sessions.Free;
          end;
        except
          on E: Exception do
            Log('Idle cleanup error: ' + E.Message);
        end;
      end;
    end);
  FCleanupThread.FreeOnTerminate := False;
  FCleanupThread.Start;
end;

procedure TRemoteServer.Stop;
var
  SessionPair: TPair<string, TConPTY>;
  ConPTYList: TList<TConPTY>;
  PTY: TConPTY;
begin
  if Assigned(FCleanupThread) then
  begin
    FCleanupThread.Terminate;
    FCleanupThread.WaitFor;
    FCleanupThread.Free;
    FCleanupThread := nil;
  end;

  if FServer.Active then
    FServer.Active := False;

  // Collect ConPTYs under lock, then stop them outside
  ConPTYList := TList<TConPTY>.Create;
  try
    EnterCriticalSection(FLock);
    try
      for SessionPair in FSessions do
        ConPTYList.Add(SessionPair.Value);
      FSessions.Clear;
      FClientStates.Clear;
    finally
      LeaveCriticalSection(FLock);
    end;

    for PTY in ConPTYList do
    begin
      PTY.Stop;
      PTY.Free;
    end;
  finally
    ConPTYList.Free;
  end;
end;

// =========================================================================
// ConPTY Management
// =========================================================================

function TRemoteServer.StartNewConPTY(const ACommand: string): TConPTY;
begin
  Result := TConPTY.Create;
  Result.OnData := OnConPTYData;
  Result.OnExit := OnConPTYExit;
  if Result.Start(ACommand, FCols, FRows) then
    Log(Format('ConPTY started: "%s" (%dx%d)', [ACommand, FCols, FRows]))
  else
  begin
    Log('ERROR: Failed to start ConPTY.');
    FreeAndNil(Result);
  end;
end;

procedure TRemoteServer.OnConPTYData(Sender: TObject; const AData: TBytes);
var
  SessionPair: TPair<string, TConPTY>;
begin
  // Runs on the ConPTY read thread. Any exception that escapes will kill
  // the thread; once dead, ConPTY output stops draining, the OS pipe
  // fills, and the child process blocks indefinitely (looks like a
  // frozen session).
  try
    SendToConPTYClients(TConPTY(Sender), AData);

    // Track output activity
    EnterCriticalSection(FLock);
    try
      for SessionPair in FSessions do
      begin
        if SessionPair.Value = TConPTY(Sender) then
        begin
          FLastOutput.AddOrSetValue(SessionPair.Key, Now);
          Break;
        end;
      end;
    finally
      LeaveCriticalSection(FLock);
    end;
  except
    on E: Exception do
      Log('OnConPTYData error: ' + E.Message);
  end;
end;

procedure TRemoteServer.OnConPTYExit(Sender: TObject; AExitCode: DWORD);
var
  SessionPair: TPair<string, TConPTY>;
  ClientPair: TPair<string, TClientState>;
  SessName: string;
  JSON: TJSONObject;
  Msg: string;
  I: Integer;
  ChainPTY, ChainPTYRef: TConPTY;
  ChainPrompt: string;
  vChainIsNew: Boolean;
begin
  Log(Format('Process exited (code: %d)', [AExitCode]));
  ChainPrompt := '';
  ChainPTYRef := nil;

  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'process_exit');
    JSON.AddPair('code', TJSONNumber.Create(Integer(AExitCode)));
    Msg := JSON.ToString;
  finally
    JSON.Free;
  end;

  EnterCriticalSection(FLock);
  try
    // Find which session owns this ConPTY
    SessName := '';
    for SessionPair in FSessions do
    begin
      if SessionPair.Value = TConPTY(Sender) then
      begin
        SessName := SessionPair.Key;
        Break;
      end;
    end;

    if SessName <> '' then
    begin
      // Notify all clients in this session
      NotifySessionClients(SessName, Msg);

      // Clear ConPTY reference from clients
      for ClientPair in FClientStates do
      begin
        if ClientPair.Value.SessionName = SessName then
          ClientPair.Value.ConPTY := nil;
      end;

      // Remove session
      FSessions.Remove(SessName);
      Log(Format('Session "%s" removed (process exited)', [SessName]));
      BroadcastSessionsList;

      // Check for dependent scheduled sessions waiting for this one
      for I := 0 to FScheduledSessions.Count - 1 do
      begin
        if (not FScheduledSessions[I].Started) and
           (FScheduledSessions[I].AfterSession <> '') and
           SameText(FScheduledSessions[I].AfterSession, SessName) then
        begin
          FScheduledSessions[I].Started := True;
          Log(Format('CHAIN STARTING: session "%s" (after "%s" finished)',
            [FScheduledSessions[I].Name, SessName]));
          ChainPTY := GetOrCreateSession(FScheduledSessions[I].Name,
            FScheduledSessions[I].SkipPerms, vChainIsNew);
          ChainPrompt := FScheduledSessions[I].Prompt;
          ChainPTYRef := ChainPTY;
          SaveSchedules;
          BroadcastSchedulesList;
        end;
      end;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;

  // Send chained prompt outside lock
  if (ChainPrompt <> '') and Assigned(ChainPTYRef) then
  begin
    Sleep(3000);
    ChainPTYRef.WriteInput(TEncoding.UTF8.GetBytes(ChainPrompt + #13));
    Log('Chained prompt sent: ' + Copy(ChainPrompt, 1, 50));
  end;
end;

// =========================================================================
// Session helpers
// =========================================================================

function TRemoteServer.GetOrCreateSession(const AName: string;
ASkipPerms: Boolean; out AIsNew: Boolean): TConPTY;
var
  Cmd: string;
begin
  AIsNew := False;
  // Must be called inside FLock or during Start (single-threaded)
  if FSessions.TryGetValue(AName, Result) then
  begin
    Log(Format('Session "%s": client joined', [AName]));
    Exit;
  end;
  AIsNew := True;

  Cmd := FCommand;
  if ASkipPerms then
  begin
    Cmd := Cmd + ' --dangerously-skip-permissions';
    Log(Format('Session "%s": permission prompts DISABLED', [AName]));
  end;

  Result := StartNewConPTY(Cmd);
  if Assigned(Result) then
  begin
    FSessions.Add(AName, Result);
    FLastActivity.AddOrSetValue(AName, Now);
    Log(Format('Session "%s": created', [AName]));
    BroadcastSessionsList;
  end;
end;

// =========================================================================
function TRemoteServer.GetFirewall: TsgcWSFirewall;
begin
  Result := FServer.Firewall;
end;

// Firewall events
// =========================================================================

procedure TRemoteServer.OnFirewallFiltered(Sender: TObject; const aIP: string;
const AReason: string; var Allow: Boolean);
begin
  if not Allow then
    Log('FIREWALL BLOCKED: ' + aIP + ' (' + AReason + ')');
end;

procedure TRemoteServer.OnFirewallViolation(Sender: TObject; const aIP: string;
const aViolationType: TsgcFirewallViolationType; const aDetails: string);
begin
  Log('FIREWALL VIOLATION: ' + aIP + ' - ' + aDetails);
end;

// =========================================================================
// Authentication helpers
// =========================================================================

function TRemoteServer.GenerateSessionToken: string;
var
  GUID: TGUID;
begin
  CreateGUID(GUID);
  Result := THashSHA2.GetHashString(GUIDToString(GUID) +
    FormatDateTime('yyyymmddhhnnsszzz', Now), SHA256);
end;

function TRemoteServer.GetClientState(Connection: TsgcWSConnection)
  : TClientState;
var
  Key: string;
begin
  Key := Connection.GUID;
  EnterCriticalSection(FLock);
  try
    if not FClientStates.TryGetValue(Key, Result) then
      Result := nil;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TRemoteServer.IsAuthenticated(Connection: TsgcWSConnection): Boolean;
var
  State: TClientState;
begin
  if not FRequireAuth then
    Exit(True);
  State := GetClientState(Connection);
  Result := Assigned(State) and State.Authenticated;
end;

function TRemoteServer.ValidateCredentials(const AUser,
  APassword: string): Boolean;
begin
  Result := (APassword = FPassword);
end;

procedure TRemoteServer.SendAuthRequired(Connection: TsgcWSConnection);
var
  JSON: TJSONObject;
  SessionsArr: TJSONArray;
  SessionKey: string;
begin
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'auth_required');
    JSON.AddPair('timeout', TJSONNumber.Create(FAuthTimeoutSec));
    // Add active sessions list
    SessionsArr := TJSONArray.Create;
    EnterCriticalSection(FLock);
    try
      for SessionKey in FSessions.Keys do
        SessionsArr.Add(SessionKey);
    finally
      LeaveCriticalSection(FLock);
    end;
    JSON.AddPair('sessions', SessionsArr);
    Connection.WriteData(JSON.ToString);
  finally
    JSON.Free;
  end;
end;

procedure TRemoteServer.SendAuthResult(Connection: TsgcWSConnection;
ASuccess: Boolean; const AMessage: string; const AToken: string);
var
  JSON: TJSONObject;
begin
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'auth_result');
    JSON.AddPair('success', TJSONBool.Create(ASuccess));
    JSON.AddPair('message', AMessage);
    if AToken <> '' then
      JSON.AddPair('token', AToken);
    Connection.WriteData(JSON.ToString);
  finally
    JSON.Free;
  end;
end;

procedure TRemoteServer.DisconnectClient(Connection: TsgcWSConnection;
const AReason: string);
var
  JSON: TJSONObject;
begin
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'disconnect');
    JSON.AddPair('reason', AReason);
    Connection.WriteData(JSON.ToString);
  finally
    JSON.Free;
  end;
  Connection.Close;
end;

// =========================================================================
// WebSocket event handlers
// =========================================================================

procedure TRemoteServer.OnConnect(Connection: TsgcWSConnection);
var
  State: TClientState;
  JSON: TJSONObject;
  Rejected: Boolean;
begin
  State := nil;
  Rejected := False;
  EnterCriticalSection(FLock);
  try
    if FConnectionCount >= FMaxConnections then
      Rejected := True
    else
    begin
      Inc(FConnectionCount);
      State := TClientState.Create;
      State.Authenticated := not FRequireAuth;
      State.ConnectTime := Now;
      State.IP := Connection.IP;
      State.Connection := Connection;
      State.LastPong := Now;
      FClientStates.AddOrSetValue(Connection.GUID, State);
    end;
  finally
    LeaveCriticalSection(FLock);
  end;

  if Rejected then
  begin
    Log('REJECTED connection from ' + Connection.IP +
      Format(' (max connections reached: %d)', [FMaxConnections]));
    DisconnectClient(Connection,
      'Server is full. Maximum connections reached.');
    Exit;
  end;

  Log('Client connected: ' + Connection.IP + Format(' [%d active]',
    [FConnectionCount]));

  if FRequireAuth then
  begin
    SendAuthRequired(Connection);
    Log('  Awaiting authentication...');
  end
  else
  begin
    State.SessionName := 'default';
    FSessions.TryGetValue('default', State.ConPTY);

    JSON := TJSONObject.Create;
    try
      JSON.AddPair('type', 'init');
      JSON.AddPair('cols', TJSONNumber.Create(FCols));
      JSON.AddPair('rows', TJSONNumber.Create(FRows));
      JSON.AddPair('promptMode', TJSONBool.Create(FPromptMode));
      Connection.WriteData(JSON.ToString);
    finally
      JSON.Free;
    end;
  end;
end;

procedure TRemoteServer.OnDisconnect(Connection: TsgcWSConnection;
Code: Integer);
var
  State: TClientState;
  SessName: string;
begin
  SessName := '';

  EnterCriticalSection(FLock);
  try
    if FClientStates.TryGetValue(Connection.GUID, State) then
      SessName := State.SessionName;

    Dec(FConnectionCount);
    if FConnectionCount < 0 then
      FConnectionCount := 0;
    FClientStates.Remove(Connection.GUID);
  finally
    LeaveCriticalSection(FLock);
  end;

  if SessName <> '' then
  begin
    Log(Format('Client left session "%s": %s [%d active]',
      [SessName, Connection.IP, FConnectionCount]));
    EnterCriticalSection(FLock);
    try
      BroadcastClientCount(SessName);
    finally
      LeaveCriticalSection(FLock);
    end;
  end
  else
    Log('Client disconnected: ' + Connection.IP + Format(' [%d active]',
      [FConnectionCount]));
end;

procedure TRemoteServer.OnMessage(Connection: TsgcWSConnection;
const Text: string);
var
  JSON: TJSONObject;
  MsgType, Data: string;
  MsgCols, MsgRows: Integer;
  MsgUser, MsgPassword: string;
  State: TClientState;
  Token: string;
  InitJSON: TJSONObject;
  SessName: string;
  SkipPerms: Boolean;
  Sched: TScheduledSession;
  SchedName: string;
  SchedIdx: Integer;
  ClosePTY: TConPTY;
  IsNewSession: Boolean;
  ResizeClientCount: Integer;
  ClientPair: TPair<string, TClientState>;
begin
  try
    JSON := TJSONObject.ParseJSONValue(Text) as TJSONObject;
    if JSON = nil then
      Exit;
    try
      MsgType := JSON.GetValue<string>('type', '');

      // -- Authentication ----------------------------------------------
      if MsgType = 'auth' then
      begin
        State := GetClientState(Connection);

        if Assigned(State) and State.Authenticated then
        begin
          SendAuthResult(Connection, True, 'Already authenticated.');
          Exit;
        end;

        if FServer.Firewall.IsBanned(Connection.IP) then
        begin
          SendAuthResult(Connection, False, Format('Blocked for %d minutes.',
            [BLOCK_DURATION_MIN]));
          DisconnectClient(Connection, 'Blocked');
          Exit;
        end;

        if Assigned(State) and (SecondsBetween(Now, State.ConnectTime) >
          FAuthTimeoutSec) then
        begin
          SendAuthResult(Connection, False,
            'Authentication timeout. Reconnect and try again.');
          DisconnectClient(Connection, 'Auth timeout');
          Exit;
        end;

        MsgUser := JSON.GetValue<string>('user', '');
        MsgPassword := JSON.GetValue<string>('password', '');

        if ValidateCredentials(MsgUser, MsgPassword) then
        begin
          if Assigned(State) then
            State.Authenticated := True;

          Token := GenerateSessionToken;
          SendAuthResult(Connection, True, 'Authentication successful.', Token);
          Log('AUTHENTICATED: ' + Connection.IP);

          // Join or create named session
          SessName := Trim(JSON.GetValue<string>('session', 'default'));
          if SessName = '' then
            SessName := 'default';
          SkipPerms := JSON.GetValue<Boolean>('skipPermissions', True);

          EnterCriticalSection(FLock);
          try
            State.SessionName := SessName;
            State.ConPTY := GetOrCreateSession(SessName, SkipPerms, IsNewSession);
          finally
            LeaveCriticalSection(FLock);
          end;

          // Send terminal init after successful auth
          InitJSON := TJSONObject.Create;
          try
            InitJSON.AddPair('type', 'init');
            InitJSON.AddPair('cols', TJSONNumber.Create(FCols));
            InitJSON.AddPair('rows', TJSONNumber.Create(FRows));
            InitJSON.AddPair('promptMode', TJSONBool.Create(FPromptMode));
            InitJSON.AddPair('newSession', TJSONBool.Create(IsNewSession));
            Connection.WriteData(InitJSON.ToString);
          finally
            InitJSON.Free;
          end;

          // Force ConPTY redraw for existing sessions so new client sees current screen
          if (not IsNewSession) and Assigned(State.ConPTY) and
             (not JSON.GetValue<Boolean>('textOnly', False)) then
          begin
            // Briefly resize +1 row then back ? triggers full screen repaint
            State.ConPTY.Resize(FCols, FRows + 1);
            Sleep(50);
            State.ConPTY.Resize(FCols, FRows);
          end;

          EnterCriticalSection(FLock);
          try
            BroadcastClientCount(SessName);
            // Targeted send: doesn't depend on the new client's
            // Authenticated flag being visible to other threads yet.
            SendSchedulesTo(Connection);
          finally
            LeaveCriticalSection(FLock);
          end;
        end
        else
        begin
          FServer.Firewall.RegisterFailedAttempt(Connection.IP);
          Log('AUTH FAILED: ' + Connection.IP);

          if FServer.Firewall.IsBanned(Connection.IP) then
          begin
            SendAuthResult(Connection, False,
              Format('Too many attempts. Blocked for %d minutes.',
              [BLOCK_DURATION_MIN]));
            DisconnectClient(Connection, 'Blocked');
          end
          else
            SendAuthResult(Connection, False, 'Invalid username or password.');
        end;
        Exit;
      end;

      // -- Reject unauthenticated messages -----------------------------
      if not IsAuthenticated(Connection) then
      begin
        SendAuthResult(Connection, False, 'Not authenticated.');
        Exit;
      end;

      // -- Terminal input ----------------------------------------------
      if MsgType = 'input' then
      begin
        Data := JSON.GetValue<string>('data', '');
        State := GetClientState(Connection);
        if (Data <> '') and Assigned(State) and Assigned(State.ConPTY) then
        begin
          State.ConPTY.WriteInput(TEncoding.UTF8.GetBytes(Data));
          EnterCriticalSection(FLock);
          try
            if State.SessionName <> '' then
              FLastActivity.AddOrSetValue(State.SessionName, Now);
          finally
            LeaveCriticalSection(FLock);
          end;
        end;
      end
      // -- Terminal resize ---------------------------------------------
      else if MsgType = 'resize' then
      begin
        MsgCols := JSON.GetValue<Integer>('cols', 120);
        MsgRows := JSON.GetValue<Integer>('rows', 40);
        if MsgCols < MIN_COLS then
          MsgCols := MIN_COLS
        else if MsgCols > MAX_COLS then
          MsgCols := MAX_COLS;
        if MsgRows < MIN_ROWS then
          MsgRows := MIN_ROWS
        else if MsgRows > MAX_ROWS then
          MsgRows := MAX_ROWS;
        State := GetClientState(Connection);
        if Assigned(State) and Assigned(State.ConPTY) then
        begin
          // Only resize if this is the only client, or new size is larger
          ResizeClientCount := 0;
          EnterCriticalSection(FLock);
          try
            for ClientPair in FClientStates do
              if ClientPair.Value.Authenticated and
                 (ClientPair.Value.SessionName = State.SessionName) then
                Inc(ResizeClientCount);
          finally
            LeaveCriticalSection(FLock);
          end;
          if (ResizeClientCount <= 1) or (MsgCols >= FCols) then
          begin
            State.ConPTY.Resize(MsgCols, MsgRows);
            Log(Format('Terminal resized to %dx%d', [MsgCols, MsgRows]));
          end;
        end;
      end
      else if MsgType = 'pong' then
      begin
        State := GetClientState(Connection);
        if Assigned(State) then
          State.LastPong := Now;
      end
      // -- Schedule session -----------------------------------------------
      else if MsgType = 'schedule_session' then
      begin
        EnterCriticalSection(FLock);
        try
          Sched := TScheduledSession.Create;
          Sched.Name := JSON.GetValue<string>('name', '');
          Sched.Prompt := JSON.GetValue<string>('prompt', '');
          // Parse ISO datetime: "2026-04-10T15:30" or "2026-04-10T15:30:00"
          Sched.StartTime := Now;
          try
            SchedName := JSON.GetValue<string>('startTime', '');
            if Length(SchedName) >= 16 then
              Sched.StartTime := EncodeDateTime(
                StrToInt(Copy(SchedName, 1, 4)),
                StrToInt(Copy(SchedName, 6, 2)),
                StrToInt(Copy(SchedName, 9, 2)),
                StrToInt(Copy(SchedName, 12, 2)),
                StrToInt(Copy(SchedName, 15, 2)),
                0, 0);
          except
          end;
          Sched.SkipPerms := JSON.GetValue<Boolean>('skipPerms', True);
          Sched.AfterSession := JSON.GetValue<string>('afterSession', '');
          Sched.Started := False;
          if Sched.Name <> '' then
          begin
            FScheduledSessions.Add(Sched);
            Log(Format('SCHEDULED: session "%s" at %s', [Sched.Name, FormatDateTime('yyyy-mm-dd hh:nn:ss', Sched.StartTime)]));
            SaveSchedules;
            BroadcastSchedulesList;
          end
          else
            Sched.Free;
        finally
          LeaveCriticalSection(FLock);
        end;
      end
      // -- Cancel scheduled session ---------------------------------------
      else if MsgType = 'cancel_schedule' then
      begin
        EnterCriticalSection(FLock);
        try
          SchedName := JSON.GetValue<string>('name', '');
          for SchedIdx := FScheduledSessions.Count - 1 downto 0 do
          begin
            if (FScheduledSessions[SchedIdx].Name = SchedName) and
               (not FScheduledSessions[SchedIdx].Started) then
            begin
              Log(Format('SCHEDULE CANCELLED: "%s"', [SchedName]));
              FScheduledSessions.Delete(SchedIdx);
              SaveSchedules;
              Break;
            end;
          end;
          BroadcastSchedulesList;
        finally
          LeaveCriticalSection(FLock);
        end;
      end
      // -- Close session --------------------------------------------------
      else if MsgType = 'close_session' then
      begin
        SchedName := JSON.GetValue<string>('name', '');
        if SchedName <> '' then
        begin
          Log(Format('CLOSING session: "%s"', [SchedName]));
          EnterCriticalSection(FLock);
          try
            if FSessions.TryGetValue(SchedName, ClosePTY) then
            begin
              // Notify clients in that session
              NotifySessionClients(SchedName,
                '{"type":"process_exit","code":0}');
              // Clear ConPTY from clients
              for ClientPair in FClientStates do
              begin
                if ClientPair.Value.SessionName = SchedName then
                  ClientPair.Value.ConPTY := nil;
              end;
              // Remove session
              FSessions.Remove(SchedName);
              FLastActivity.Remove(SchedName);
              FLastOutput.Remove(SchedName);
              BroadcastSessionsList;
            end
            else
              ClosePTY := nil;
          finally
            LeaveCriticalSection(FLock);
          end;
          // Stop ConPTY outside lock
          if Assigned(ClosePTY) then
          begin
            ClosePTY.Stop;
            ClosePTY.Free;
          end;
        end;
      end;

    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      Log('Error parsing client message: ' + E.Message);
  end;
end;

procedure TRemoteServer.OnBinary(Connection: TsgcWSConnection;
const Data: TMemoryStream);
begin
  // No binary input handling needed
end;

// =========================================================================
// Targeted output
// =========================================================================

procedure TRemoteServer.SendToConPTYClients(AConPTY: TConPTY;
const AData: TBytes);
var
  Pair: TPair<string, TClientState>;
  Stream: TMemoryStream;
begin
  if not FServer.Active then
    Exit;
  if Length(AData) = 0 then
    Exit;

  EnterCriticalSection(FLock);
  try
    for Pair in FClientStates do
    begin
      if Pair.Value.Authenticated and (Pair.Value.ConPTY = AConPTY) then
      begin
        Stream := TMemoryStream.Create;
        try
          Stream.WriteBuffer(AData[0], Length(AData));
          Stream.Position := 0;
          // try/except is critical: this runs on the ConPTY read thread.
          // An unhandled WriteData exception (e.g., a stuck/dead client)
          // would kill the read thread; the OS pipe then fills and the
          // child process blocks, looking exactly like a frozen session.
          try
            Pair.Value.Connection.WriteData(Stream);
          except
          end;
        finally
          Stream.Free;
        end;
      end;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TRemoteServer.NotifySessionClients(const ASessionName: string;
const AMessage: string);
var
  Pair: TPair<string, TClientState>;
begin
  // Must be called inside FLock
  for Pair in FClientStates do
  begin
    if Pair.Value.Authenticated and (Pair.Value.SessionName = ASessionName) then
    begin
      try
        Pair.Value.Connection.WriteData(AMessage);
      except
      end;
    end;
  end;
end;

procedure TRemoteServer.BroadcastClientCount(const ASessionName: string);
var
  Pair: TPair<string, TClientState>;
  Count: Integer;
  JSON: TJSONObject;
  Msg: string;
begin
  // Must be called inside FLock
  if ASessionName = '' then
    Exit;

  Count := 0;
  for Pair in FClientStates do
  begin
    if Pair.Value.Authenticated and (Pair.Value.SessionName = ASessionName) then
      Inc(Count);
  end;

  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'clients');
    JSON.AddPair('count', TJSONNumber.Create(Count));
    Msg := JSON.ToString;
  finally
    JSON.Free;
  end;

  NotifySessionClients(ASessionName, Msg);
end;

procedure TRemoteServer.BroadcastSessionsList;
var
  Pair: TPair<string, TClientState>;
  SessionKey: string;
  JSON: TJSONObject;
  Arr: TJSONArray;
  Msg: string;
begin
  // Must be called inside FLock
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'sessions_update');
    Arr := TJSONArray.Create;
    for SessionKey in FSessions.Keys do
      Arr.Add(SessionKey);
    JSON.AddPair('sessions', Arr);
    Msg := JSON.ToString;
  finally
    JSON.Free;
  end;

  for Pair in FClientStates do
  begin
    if Pair.Value.Authenticated then
    begin
      try
        Pair.Value.Connection.WriteData(Msg);
      except
      end;
    end;
  end;
end;

procedure TRemoteServer.BroadcastSchedulesList;
var
  Pair: TPair<string, TClientState>;
  JSON: TJSONObject;
  Arr: TJSONArray;
  Item: TJSONObject;
  Sched: TScheduledSession;
  Msg: string;
  I: Integer;
begin
  // Must be called inside FLock
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'schedules_update');
    Arr := TJSONArray.Create;
    for I := 0 to FScheduledSessions.Count - 1 do
    begin
      Sched := FScheduledSessions[I];
      Item := TJSONObject.Create;
      Item.AddPair('name', Sched.Name);
      Item.AddPair('prompt', Sched.Prompt);
      Item.AddPair('startTime', FormatDateTime('yyyy-mm-dd"T"hh:nn:ss', Sched.StartTime));
      Item.AddPair('skipPerms', TJSONBool.Create(Sched.SkipPerms));
      Item.AddPair('afterSession', Sched.AfterSession);
      Item.AddPair('started', TJSONBool.Create(Sched.Started));
      Arr.Add(Item);
    end;
    JSON.AddPair('schedules', Arr);
    Msg := JSON.ToString;
  finally
    JSON.Free;
  end;

  for Pair in FClientStates do
  begin
    if Pair.Value.Authenticated then
    begin
      try
        Pair.Value.Connection.WriteData(Msg);
      except
      end;
    end;
  end;
end;

procedure TRemoteServer.SendSchedulesTo(Connection: TsgcWSConnection);
var
  JSON: TJSONObject;
  Arr: TJSONArray;
  Item: TJSONObject;
  Sched: TScheduledSession;
  Msg: string;
  I: Integer;
begin
  // Must be called inside FLock. Sends the current schedule list to a
  // single connection — used right after authentication so the client
  // sees existing schedules without waiting for the next change.
  JSON := TJSONObject.Create;
  try
    JSON.AddPair('type', 'schedules_update');
    Arr := TJSONArray.Create;
    for I := 0 to FScheduledSessions.Count - 1 do
    begin
      Sched := FScheduledSessions[I];
      Item := TJSONObject.Create;
      Item.AddPair('name', Sched.Name);
      Item.AddPair('prompt', Sched.Prompt);
      Item.AddPair('startTime', FormatDateTime('yyyy-mm-dd"T"hh:nn:ss',
        Sched.StartTime));
      Item.AddPair('skipPerms', TJSONBool.Create(Sched.SkipPerms));
      Item.AddPair('afterSession', Sched.AfterSession);
      Item.AddPair('started', TJSONBool.Create(Sched.Started));
      Arr.Add(Item);
    end;
    JSON.AddPair('schedules', Arr);
    Msg := JSON.ToString;
  finally
    JSON.Free;
  end;
  try
    Connection.WriteData(Msg);
  except
  end;
end;

procedure TRemoteServer.SaveSchedules;
var
  JSON: TJSONArray;
  Item: TJSONObject;
  Sched: TScheduledSession;
  I: Integer;
  FilePath: string;
begin
  // Must be called inside FLock. Must never raise: a transient disk error
  // here would otherwise crash the cleanup thread and stop all future
  // schedule firings.
  FilePath := ChangeFileExt(ParamStr(0), '.schedules.json');
  JSON := TJSONArray.Create;
  try
    for I := 0 to FScheduledSessions.Count - 1 do
    begin
      Sched := FScheduledSessions[I];
      if not Sched.Started then
      begin
        Item := TJSONObject.Create;
        Item.AddPair('name', Sched.Name);
        Item.AddPair('prompt', Sched.Prompt);
        Item.AddPair('startTime', FormatDateTime('yyyy-mm-dd"T"hh:nn:ss', Sched.StartTime));
        Item.AddPair('skipPerms', TJSONBool.Create(Sched.SkipPerms));
        Item.AddPair('afterSession', Sched.AfterSession);
        JSON.Add(Item);
      end;
    end;
    try
      TFile.WriteAllText(FilePath, JSON.ToString);
    except
      on E: Exception do
        Log('Error saving schedules: ' + E.Message);
    end;
  finally
    JSON.Free;
  end;
end;

procedure TRemoteServer.LoadSchedules;
var
  FilePath, Content, SchedTimeStr: string;
  JSON: TJSONArray;
  Item: TJSONObject;
  Sched: TScheduledSession;
  I: Integer;
begin
  FilePath := ChangeFileExt(ParamStr(0), '.schedules.json');
  if not FileExists(FilePath) then
    Exit;
  try
    Content := TFile.ReadAllText(FilePath);
    JSON := TJSONObject.ParseJSONValue(Content) as TJSONArray;
    if JSON = nil then
      Exit;
    try
      for I := 0 to JSON.Count - 1 do
      begin
        Item := JSON.Items[I] as TJSONObject;
        Sched := TScheduledSession.Create;
        Sched.Name := Item.GetValue<string>('name', '');
        Sched.Prompt := Item.GetValue<string>('prompt', '');
        Sched.SkipPerms := Item.GetValue<Boolean>('skipPerms', True);
        Sched.AfterSession := Item.GetValue<string>('afterSession', '');
        Sched.Started := False;
        // Parse ISO datetime
        SchedTimeStr := Item.GetValue<string>('startTime', '');
        Sched.StartTime := Now;
        try
          if Length(SchedTimeStr) >= 16 then
            Sched.StartTime := EncodeDateTime(
              StrToInt(Copy(SchedTimeStr, 1, 4)),
              StrToInt(Copy(SchedTimeStr, 6, 2)),
              StrToInt(Copy(SchedTimeStr, 9, 2)),
              StrToInt(Copy(SchedTimeStr, 12, 2)),
              StrToInt(Copy(SchedTimeStr, 15, 2)),
              0, 0);
        except
        end;
        if (Sched.Name <> '') and ((Sched.AfterSession <> '') or (Sched.StartTime > Now)) then
        begin
          FScheduledSessions.Add(Sched);
          Log(Format('LOADED schedule: "%s" at %s',
            [Sched.Name, FormatDateTime('yyyy-mm-dd hh:nn:ss', Sched.StartTime)]));
        end
        else
          Sched.Free; // Past schedules are discarded
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      Log('Error loading schedules: ' + E.Message);
  end;
end;

// =========================================================================
// HTTP handler ? serve embedded index.html
// =========================================================================

procedure TRemoteServer.HandleCommandGet(AContext: TIdContext;
ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  ResStream: TResourceStream;
  Stream: TMemoryStream;
  vURL: string;
  StatsJSON, StatsSessionObj: TJSONObject;
  StatsSessionsArr: TJSONArray;
  StatsPair: TPair<string, TConPTY>;
  StatsClientPair: TPair<string, TClientState>;
  StatsClientCount: Integer;
  vToken, vCookie, vFileName, vFilePath: string;
  vPos: Integer;
  vFileStream: TFileStream;
begin
  if (ARequestInfo.Document = '/upload') and (ARequestInfo.CommandType = hcPOST)
  then
  begin
    AResponseInfo.ContentType := 'application/json';

    // Check authentication via session cookie
    vToken := '';
    vCookie := ARequestInfo.RawHeaders.Values['Cookie'];
    vPos := Pos('session=', vCookie);
    if vPos > 0 then
    begin
      vToken := Copy(vCookie, vPos + 8, MaxInt);
      vPos := Pos(';', vToken);
      if vPos > 0 then
        vToken := Copy(vToken, 1, vPos - 1);
      vToken := Trim(vToken);
    end;

    // For simplicity, just check that a non-empty request body exists
    // The file content is sent as the raw POST body with filename in header
    vFileName := ARequestInfo.RawHeaders.Values['X-Filename'];
    if vFileName = '' then
      vFileName := 'uploaded-file.txt';

    // Sanitize filename -- remove path separators
    vFileName := StringReplace(vFileName, '/', '', [rfReplaceAll]);
    vFileName := StringReplace(vFileName, '\', '', [rfReplaceAll]);
    vFileName := StringReplace(vFileName, '..', '', [rfReplaceAll]);

    vFilePath := IncludeTrailingPathDelimiter(FWorkDir) + vFileName;

    try
      if Assigned(ARequestInfo.PostStream) and (ARequestInfo.PostStream.Size > 0)
      then
      begin
        vFileStream := TFileStream.Create(vFilePath, fmCreate);
        try
          ARequestInfo.PostStream.Position := 0;
          vFileStream.CopyFrom(ARequestInfo.PostStream,
            ARequestInfo.PostStream.Size);
        finally
          vFileStream.Free;
        end;
        Log('FILE UPLOADED: ' + vFileName + ' (' +
          IntToStr(ARequestInfo.PostStream.Size) + ' bytes)');
        AResponseInfo.ResponseText :=
          Format('{"success":true,"filename":"%s","path":"%s","size":%d}',
          [vFileName, StringReplace(vFilePath, '\', '\\', [rfReplaceAll]),
          ARequestInfo.PostStream.Size]);
      end
      else
      begin
        AResponseInfo.ResponseText :=
          '{"success":false,"error":"No file data received"}';
        AResponseInfo.ResponseNo := 400;
      end;
    except
      on E: Exception do
      begin
        AResponseInfo.ResponseText := Format('{"success":false,"error":"%s"}',
          [StringReplace(E.Message, '"', '\"', [rfReplaceAll])]);
        AResponseInfo.ResponseNo := 500;
      end;
    end;
    Exit;
  end;

  if ARequestInfo.Document = '/qr' then
  begin
    if FTLSEnabled then
      vURL := Format('https://%s/', [ARequestInfo.Host])
    else
      vURL := Format('http://%s/', [ARequestInfo.Host]);
    AResponseInfo.ContentType := 'text/html; charset=utf-8';
    AResponseInfo.ContentText :=
      '<!DOCTYPE html><html><head><meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1.0">' +
      '<title>Connect to Claude Code Remote</title>' +
      '<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>'
      + '</head><body style="display:flex;flex-direction:column;align-items:center;justify-content:center;'
      + 'min-height:100vh;background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;">'
      + '<h2 style="color:#d4a574;">Claude Code Remote</h2>' +
      '<div id="qr" style="margin:20px 0;"></div>' + '<p><a href="' + vURL +
      '" style="color:#58a6ff;font-size:16px;">' + vURL + '</a></p>' +
      '<p style="color:#8b949e;font-size:12px;margin-top:20px;">Scan the QR code with your phone to connect</p>'
      + '<script>var q=qrcode(0,"M");q.addData("' + vURL + '");q.make();' +
      'document.getElementById("qr").innerHTML=q.createSvgTag(6,0);</script>' +
      '</body></html>';
    Exit;
  end;

  if ARequestInfo.Document = '/stats' then
  begin
    AResponseInfo.ContentType := 'application/json';
    EnterCriticalSection(FLock);
    try
      // Build sessions array
      StatsSessionsArr := TJSONArray.Create;
      for StatsPair in FSessions do
      begin
        StatsSessionObj := TJSONObject.Create;
        StatsSessionObj.AddPair('name', StatsPair.Key);
        // Count clients in this session
        StatsClientCount := 0;
        for StatsClientPair in FClientStates do
        begin
          if StatsClientPair.Value.Authenticated and
            (StatsClientPair.Value.SessionName = StatsPair.Key) then
            Inc(StatsClientCount);
        end;
        StatsSessionObj.AddPair('clients',
          TJSONNumber.Create(StatsClientCount));
        StatsSessionsArr.Add(StatsSessionObj);
      end;

      StatsJSON := TJSONObject.Create;
      try
        StatsJSON.AddPair('status', 'ok');
        StatsJSON.AddPair('uptime', TJSONNumber.Create(SecondsBetween(Now,
          FStartTime)));
        StatsJSON.AddPair('connections', TJSONNumber.Create(FConnectionCount));
        StatsJSON.AddPair('sessions', StatsSessionsArr);
        AResponseInfo.ResponseText := StatsJSON.ToString;
      finally
        StatsJSON.Free;
      end;
    finally
      LeaveCriticalSection(FLock);
    end;
    Exit;
  end;

  if ARequestInfo.Document = '/health' then
  begin
    AResponseInfo.ContentType := 'application/json';
    EnterCriticalSection(FLock);
    try
      AResponseInfo.ResponseText :=
        Format('{"status":"ok","uptime":%d,"sessions":%d,"connections":%d}',
        [SecondsBetween(Now, FStartTime), FSessions.Count, FConnectionCount]);
    finally
      LeaveCriticalSection(FLock);
    end;
    Exit;
  end;

  if ARequestInfo.Document = '/' then
  begin
    AResponseInfo.ContentType := 'text/html; charset=utf-8';
    Stream := TMemoryStream.Create;
    try
      ResStream := TResourceStream.Create(HInstance, 'INDEX_HTML', RT_RCDATA);
      try
        Stream.CopyFrom(ResStream, ResStream.Size);
        Stream.Position := 0;
      finally
        ResStream.Free;
      end;
    except
      Stream.Free;
      raise;
    end;
    AResponseInfo.ContentStream := Stream;
  end;
end;

end.
