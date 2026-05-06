unit uConPTY;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.SyncObjs;

type
  HPCON = THandle;

  TConPTYDataEvent = procedure(Sender: TObject; const AData: TBytes) of object;
  TConPTYExitEvent = procedure(Sender: TObject; AExitCode: DWORD) of object;

  TConPTY = class
  private
    FhPC: HPCON;
    FInputWriteHandle: THandle;
    FOutputReadHandle: THandle;
    FProcessInfo: TProcessInformation;
    FReadThread: TThread;
    FWatchThread: TThread;
    FRunning: Boolean;
    FCols: Integer;
    FRows: Integer;

    FOnData: TConPTYDataEvent;
    FOnExit: TConPTYExitEvent;

    procedure CloseHandleSafe(var AHandle: THandle);
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// Start a process inside a ConPTY pseudo-console.
    /// ACommand: command line to execute (e.g. 'claude' or 'cmd.exe')
    /// ACols, ARows: initial terminal dimensions
    /// </summary>
    function Start(const ACommand: string; ACols, ARows: Integer): Boolean;

    /// <summary>Stop the ConPTY session and terminate the child process.</summary>
    procedure Stop;

    /// <summary>Write raw bytes to the process stdin (keyboard input).</summary>
    procedure WriteInput(const AData: TBytes);

    /// <summary>Resize the pseudo-console.</summary>
    procedure Resize(ACols, ARows: Integer);

    property Running: Boolean read FRunning;
    property OnData: TConPTYDataEvent read FOnData write FOnData;
    property OnExit: TConPTYExitEvent read FOnExit write FOnExit;
  end;

implementation

// -------------------------------------------------------------------------
// ConPTY API declarations (Windows 10 1809+)
// -------------------------------------------------------------------------

type
  TStartupInfoExW = record
    StartupInfo: TStartupInfo;
    lpAttributeList: Pointer;
  end;
  TStartupInfoEx = TStartupInfoExW;

const
  PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = $00020016;
  // $00020016 = ProcThreadAttributePseudoConsole

function CreatePseudoConsole(
  size: COORD;
  hInput: THandle;
  hOutput: THandle;
  dwFlags: DWORD;
  out phPC: HPCON
): HRESULT; stdcall; external kernel32;

function ResizePseudoConsole(
  hPC: HPCON;
  size: COORD
): HRESULT; stdcall; external kernel32;

procedure ClosePseudoConsole(
  hPC: HPCON
); stdcall; external kernel32;

// -------------------------------------------------------------------------
// Thread attribute list helpers
// -------------------------------------------------------------------------

function InitializeProcThreadAttributeList(
  lpAttributeList: Pointer;
  dwAttributeCount: DWORD;
  dwFlags: DWORD;
  var lpSize: SIZE_T
): BOOL; stdcall; external kernel32;

function UpdateProcThreadAttribute(
  lpAttributeList: Pointer;
  dwFlags: DWORD;
  Attribute: DWORD_PTR;
  lpValue: Pointer;
  cbSize: SIZE_T;
  lpPreviousValue: Pointer;
  lpReturnSize: PSIZE_T
): BOOL; stdcall; external kernel32;

procedure DeleteProcThreadAttributeList(
  lpAttributeList: Pointer
); stdcall; external kernel32;

// -------------------------------------------------------------------------
// Read thread: reads ConPTY output and fires OnData
// -------------------------------------------------------------------------

type
  TReadThread = class(TThread)
  private
    FOwner: TConPTY;
    FOutputReadHandle: THandle;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TConPTY; AOutputReadHandle: THandle);
  end;

constructor TReadThread.Create(AOwner: TConPTY; AOutputReadHandle: THandle);
begin
  inherited Create(True); // create suspended
  FOwner := AOwner;
  FOutputReadHandle := AOutputReadHandle;
  FreeOnTerminate := False;
end;

procedure TReadThread.Execute;
var
  Buffer: array[0..4095] of Byte;
  BytesRead: DWORD;
  Data: TBytes;
begin
  while not Terminated do
  begin
    BytesRead := 0;
    if not ReadFile(FOutputReadHandle, Buffer[0], SizeOf(Buffer), BytesRead, nil) then
      Break; // pipe closed or error

    if BytesRead > 0 then
    begin
      SetLength(Data, BytesRead);
      Move(Buffer[0], Data[0], BytesRead);

      if Assigned(FOwner.OnData) then
        FOwner.OnData(FOwner, Data);
    end;
  end;
end;

// -------------------------------------------------------------------------
// Watch thread: waits for the child process to exit
// -------------------------------------------------------------------------

type
  TWatchThread = class(TThread)
  private
    FOwner: TConPTY;
    FProcessHandle: THandle;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TConPTY; AProcessHandle: THandle);
  end;

constructor TWatchThread.Create(AOwner: TConPTY; AProcessHandle: THandle);
begin
  inherited Create(True);
  FOwner := AOwner;
  FProcessHandle := AProcessHandle;
  FreeOnTerminate := False;
end;

procedure TWatchThread.Execute;
var
  ExitCode: DWORD;
begin
  WaitForSingleObject(FProcessHandle, INFINITE);

  ExitCode := 0;
  GetExitCodeProcess(FProcessHandle, ExitCode);

  FOwner.FRunning := False;

  if Assigned(FOwner.OnExit) then
    FOwner.OnExit(FOwner, ExitCode);
end;

// -------------------------------------------------------------------------
// TConPTY implementation
// -------------------------------------------------------------------------

constructor TConPTY.Create;
begin
  inherited;
  FhPC := 0;
  FInputWriteHandle := INVALID_HANDLE_VALUE;
  FOutputReadHandle := INVALID_HANDLE_VALUE;
  FRunning := False;
  ZeroMemory(@FProcessInfo, SizeOf(FProcessInfo));
end;

destructor TConPTY.Destroy;
begin
  Stop;
  inherited;
end;

procedure TConPTY.CloseHandleSafe(var AHandle: THandle);
begin
  if (AHandle <> 0) and (AHandle <> INVALID_HANDLE_VALUE) then
  begin
    CloseHandle(AHandle);
    AHandle := INVALID_HANDLE_VALUE;
  end;
end;

function TConPTY.Start(const ACommand: string; ACols, ARows: Integer): Boolean;
var
  InputReadSide, OutputWriteSide: THandle;
  Size: COORD;
  HR: HRESULT;
  AttrListSize: SIZE_T;
  AttrList: Pointer;
  SI: TStartupInfoEx;
  CreationFlags: DWORD;
  CmdLine: string;
begin
  Result := False;
  FCols := ACols;
  FRows := ARows;

  InputReadSide := INVALID_HANDLE_VALUE;
  OutputWriteSide := INVALID_HANDLE_VALUE;
  FInputWriteHandle := INVALID_HANDLE_VALUE;
  FOutputReadHandle := INVALID_HANDLE_VALUE;
  AttrList := nil;

  try
    // Step 1: Create communication pipes
    if not CreatePipe(InputReadSide, FInputWriteHandle, nil, 0) then
      Exit;
    if not CreatePipe(FOutputReadHandle, OutputWriteSide, nil, 0) then
      Exit;

    // Step 2: Create the Pseudo Console
    Size.X := ACols;
    Size.Y := ARows;

    HR := CreatePseudoConsole(Size, InputReadSide, OutputWriteSide, 0, FhPC);
    if Failed(HR) then
    begin
      FhPC := 0;
      Exit;
    end;

    // Step 3: Prepare startup info with the pseudo console attribute
    AttrListSize := 0;
    InitializeProcThreadAttributeList(nil, 1, 0, AttrListSize);
    AttrList := GetMemory(AttrListSize);
    if not InitializeProcThreadAttributeList(AttrList, 1, 0, AttrListSize) then
      Exit;

    if not UpdateProcThreadAttribute(
      AttrList,
      0,
      PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
      Pointer(FhPC),
      SizeOf(HPCON),
      nil,
      nil
    ) then
      Exit;

    ZeroMemory(@SI, SizeOf(SI));
    SI.StartupInfo.cb := SizeOf(TStartupInfoEx);
    SI.lpAttributeList := AttrList;

    // Step 4: Launch the child process
    // Use Git Bash if available (Claude Code on Windows runs via Git Bash)
    CmdLine := ACommand;

    CreationFlags := EXTENDED_STARTUPINFO_PRESENT;

    if not CreateProcessW(
      nil,
      PChar(CmdLine),
      nil,
      nil,
      False,
      CreationFlags,
      nil,
      nil, // current directory
      SI.StartupInfo,
      FProcessInfo
    ) then
      Exit;

    FRunning := True;

    // Close the sides of the pipes we don't need in the host
    CloseHandleSafe(InputReadSide);
    CloseHandleSafe(OutputWriteSide);

    // Step 5: Start the reader thread
    FReadThread := TReadThread.Create(Self, FOutputReadHandle);
    FReadThread.Start;

    // Step 6: Start the process watcher thread
    FWatchThread := TWatchThread.Create(Self, FProcessInfo.hProcess);
    FWatchThread.Start;

    Result := True;
  finally
    if not Result then
    begin
      // Cleanup on failure
      CloseHandleSafe(InputReadSide);
      CloseHandleSafe(OutputWriteSide);
      CloseHandleSafe(FInputWriteHandle);
      CloseHandleSafe(FOutputReadHandle);
      if FhPC <> 0 then
      begin
        ClosePseudoConsole(FhPC);
        FhPC := 0;
      end;
    end
    else
    begin
      // Clean up pipe ends not needed anymore
      CloseHandleSafe(InputReadSide);
      CloseHandleSafe(OutputWriteSide);
    end;

    if AttrList <> nil then
    begin
      DeleteProcThreadAttributeList(AttrList);
      FreeMemory(AttrList);
    end;
  end;
end;

procedure TConPTY.Stop;
begin
  FRunning := False;

  // Terminate child process first to unblock everything
  if FProcessInfo.hProcess <> 0 then
  begin
    TerminateProcess(FProcessInfo.hProcess, 1);
    WaitForSingleObject(FProcessInfo.hProcess, 2000);
    CloseHandle(FProcessInfo.hProcess);
    FProcessInfo.hProcess := 0;
  end;

  if FProcessInfo.hThread <> 0 then
  begin
    CloseHandle(FProcessInfo.hThread);
    FProcessInfo.hThread := 0;
  end;

  // Close handles to unblock threads
  CloseHandleSafe(FOutputReadHandle);
  CloseHandleSafe(FInputWriteHandle);

  // Terminate read thread
  if Assigned(FReadThread) then
  begin
    FReadThread.Terminate;
    if FReadThread.WaitFor <> 0 then; // ignore result
    FreeAndNil(FReadThread);
  end;

  // Terminate watch thread
  if Assigned(FWatchThread) then
  begin
    FWatchThread.Terminate;
    if FWatchThread.WaitFor <> 0 then; // ignore result
    FreeAndNil(FWatchThread);
  end;

  // Close pseudo console last (can block if done before process kill)
  if FhPC <> 0 then
  begin
    ClosePseudoConsole(FhPC);
    FhPC := 0;
  end;
end;

procedure TConPTY.WriteInput(const AData: TBytes);
var
  Written: DWORD;
begin
  if not FRunning then Exit;
  if Length(AData) = 0 then Exit;
  if FInputWriteHandle = INVALID_HANDLE_VALUE then Exit;

  WriteFile(FInputWriteHandle, AData[0], Length(AData), Written, nil);
end;

procedure TConPTY.Resize(ACols, ARows: Integer);
var
  Size: COORD;
begin
  if FhPC = 0 then Exit;

  FCols := ACols;
  FRows := ARows;
  Size.X := ACols;
  Size.Y := ARows;

  ResizePseudoConsole(FhPC, Size);
end;

end.
