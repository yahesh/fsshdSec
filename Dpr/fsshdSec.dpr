program fsshdSec;

{$R DATA.RES}

{$DEFINE MAX_SIZE}

uses
  WinSvc,
  Windows,
  TinyAppU,
  SysUtils,
  Registry,
  Messages,
  Menus,
  IniFiles,
  ExtCtrls,
  Dialogs,
  Controls,
  Classes;

const
  CFilterInclude = 'HostRestrictionsAllow';
  CFilterList    = 'HostRestrictions';
  CFilterSection = 'Access filtering';
  CIconID        = 100;
  CIniFileName   = 'FreeSSHDService.ini';
  CLogActive     = 'LogEvents';
  CLogFile       = 'LogFilePath';
  CLogResolve    = 'LogResolveIP';
  CLogSection    = 'Logging';
{$IF DEFINED(MAX_SIZE)}
  CMaxListSize   = 2048;
{$IFEND}  
  CRegistryKey   = 'SOFTWARE\fsshdSec\';
  CRegistryValue = 'LastPosition';
  CServiceName   = 'FreeSSHDService';
  CTitle         = 'freeSSHd Security';

var
  VInIFileName : String;

type
  TIniOptions = record
    FilterInclude : Boolean;
    FilterList    : String;
    LogActive     : Boolean;
    LogFile       : String;
    LogResolve    : Boolean;
    Result        : Boolean;
  end;

  TfreeSSHdSecurity = class(TTinyApplication)
  private
  protected
    FClose        : TMenuItem;
    FDivTerminate : TMenuItem;
    FFilterList   : TStringList;
    FIniFileName  : String;
    FLastPos      : Int64;
    FPopupMenu    : TPopupMenu;
    FProcess      : THandle;
    FTerminate    : TMenuItem;
    FTimer        : TTimer;

    class function ServiceGetPath(const AServiceName : String) : String;
    class function ServiceGetState(const AServiceName : String) : LongInt;
    class function ServiceStart(const AServiceName : String) : Boolean;
    class function ServiceStop(const AServiceName : String) : Boolean;

    function GetFileSize(const AFileName : String) : Int64;

    function GetLastPosition : Int64;
    procedure SetLastPosition;

    function GetIniOptions : TIniOptions;
    procedure SetIniOptions(var AIniOptions : TIniOptions);

    procedure CreateMenu;
    procedure DestroyMenu;

    procedure CheckTimer(Sender : TObject);
    procedure TerminateClick(Sender : TObject);

    procedure TaskBarMenu(var AMessage : TMessage);
  public
    constructor Create(const AIniFileName : String);

    destructor Destroy; override;
  published
  end;

{ TfreeSSHdSecurity }

class function TfreeSSHdSecurity.ServiceGetPath(const AServiceName : String) : String;
var
  LConfig  : PQueryServiceConfig;
  LManager : SC_Handle;
  LService : SC_Handle;
  LSize    : DWord;
begin
  Result := '';

  LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if (LManager <> 0) then
  begin
    try
      LService := OpenService(LManager, PChar(AServiceName), SERVICE_QUERY_CONFIG or SERVICE_CHANGE_CONFIG);
      if (LService <> 0) then
      begin
        try
          QueryServiceConfig(LService, nil, 0, LSize);
          GetMem(LConfig, LSize);
          try
            if QueryServiceConfig(LService, LConfig, LSize, LSize) then
            begin
              Result := LConfig^.lpBinaryPathName;
              Result := ExtractFilePath(Result);
              if (Length(Result) > 0) then
              begin
                if (Result[Length(Result)] <> '\') then
                  Result := Result + '\';
              end;
            end;
          finally
            FreeMem(LConfig);
          end;
        finally
          CloseServiceHandle(LService);
        end;
      end;
    finally
      CloseServiceHandle(LManager);
    end;
  end;
end;

class function TfreeSSHdSecurity.ServiceGetState(const AServiceName : String) : LongInt;
var
  LManager : SC_Handle;
  LService : SC_Handle;
  LStatus  : TServiceStatus;
begin
  Result := - 1;

  LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if (LManager <> 0) then
  begin
    try
      LService := OpenService(LManager, PChar(AServiceName), SERVICE_QUERY_STATUS);
      if (LService <> 0) then
      begin
        try
          if QueryServiceStatus(LService, LStatus) then
            Result := LStatus.dwCurrentState;
        finally
          CloseServiceHandle(LService);
        end;
      end;
    finally
      CloseServiceHandle(LManager);
    end;
  end;
end;

class function TfreeSSHdSecurity.ServiceStart(const AServiceName : String) : Boolean;
var
  LCheckPoint : LongWord;
  LExit       : Boolean;
  LManager    : SC_Handle;
  LService    : SC_Handle;
  LStatus     : TServiceStatus;
  LTemp       : PChar;
begin
  Result := false;

  if not(Result) then
  begin
    LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
    if (LManager <> 0) then
    begin
      try
        LService := OpenService(LManager, PChar(AServiceName), SERVICE_START or SERVICE_QUERY_STATUS);
        if (LService <> 0) then
        begin
          try
            if QueryServiceStatus(LService, LStatus) then
            begin
              Result := (LStatus.dwCurrentState = SERVICE_RUNNING);
              if not(Result) then
              begin
                LTemp := nil;
                if StartService(LService, 0, LTemp) then
                begin
                  repeat
                    LCheckPoint := LStatus.dwCheckPoint;
                    Sleep(LStatus.dwWaitHint);

                    LExit := not(QueryServiceStatus(LService, LStatus));
                    if not(LExit) then
                      LExit := (LStatus.dwCheckPoint < LCheckPoint);
                  until ((LStatus.dwCurrentState = SERVICE_RUNNING) or LExit);

                  Result := (LStatus.dwCurrentState = SERVICE_RUNNING);
                end;
              end;
            end;
          finally
            CloseServiceHandle(LService);
          end;
        end;
      finally
        CloseServiceHandle(LManager);
      end;
    end;
  end;
end;

class function TfreeSSHdSecurity.ServiceStop(const AServiceName : String) : Boolean;
var
  LCheckPoint : LongWord;
  LExit       : Boolean;
  LManager    : SC_Handle;
  LService    : SC_Handle;
  LStatus     : TServiceStatus;
begin
  Result := false;

  if not(Result) then
  begin
    LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
    if (LManager <> 0) then
    begin
      try
        LService := OpenService(LManager, PChar(AServiceName), SERVICE_STOP or SERVICE_QUERY_STATUS);
        if (LService <> 0) then
        begin
          try
            if QueryServiceStatus(LService, LStatus) then
            begin
              Result := (LStatus.dwCurrentState = SERVICE_STOPPED);
              if not(Result) then
              begin
                if ControlService(LService, SERVICE_CONTROL_STOP, LStatus) then
                begin
                  repeat
                    LCheckPoint := LStatus.dwCheckPoint;
                    Sleep(LStatus.dwWaitHint);

                    LExit := not(QueryServiceStatus(LService, LStatus));
                    if not(LExit) then
                      LExit := (LStatus.dwCheckPoint < LCheckPoint);
                  until ((LStatus.dwCurrentState = SERVICE_STOPPED) or LExit);

                  Result := (LStatus.dwCurrentState = SERVICE_STOPPED);
                end;
              end;
            end;
          finally
            CloseServiceHandle(LService);
          end;
        end;
      finally
        CloseServiceHandle(LManager);
      end;
    end;
  end;
end;

function TfreeSSHdSecurity.GetFileSize(const AFileName : String) : Int64;
var
  LSearchRec : TSearchRec;
begin
  if FindFirst(AFileName, faAnyFile, LSearchRec) = 0 then
  begin
    try
      Result := Int64(LSearchRec.FindData.nFileSizeHigh) shl SizeOf(LSearchRec.FindData.nFileSizeHigh) +  Int64(LSearchRec.FindData.nFileSizeLow)
    finally
      FindClose(LSearchRec);
    end;
  end
  else
     Result := -1;
end;

function TfreeSSHdSecurity.GetLastPosition : Int64;
var
  LIniOptions : TIniOptions;
  LRegistry   : TRegistry;
  LTempA      : Int64;
  LTempB      : Int64;
begin
  Result := 0;

  LIniOptions := GetIniOptions;
  if (LIniOptions.Result) then
  begin
    if FileExists(LIniOptions.LogFile) then
    begin
      LRegistry := TRegistry.Create;
      try
        LRegistry.RootKey := HKEY_LOCAL_MACHINE;

        if LRegistry.OpenKey(CRegistryKey, false) then
        begin
          try
            if LRegistry.ValueExists(CRegistryValue) then
            begin
              if (LRegistry.ReadBinaryData(CRegistryValue, LTempA, SizeOf(Int64)) = SizeOf(Int64)) then
              begin
                LTempB := GetFileSize(LIniOptions.LogFile);
                if (LTempB >= LTempA) then
                  Result := LTempA;
              end;
            end;
          finally
            LRegistry.CloseKey;
          end;
        end;
      finally
        LRegistry.Free;
      end;
    end;
  end;
end;

procedure TfreeSSHdSecurity.SetLastPosition;
var
  LRegistry : TRegistry;
begin
  LRegistry := TRegistry.Create;
  try
    LRegistry.RootKey := HKEY_LOCAL_MACHINE;

    if LRegistry.OpenKey(CRegistryKey, true) then
    begin
      try
        LRegistry.WriteBinaryData(CRegistryValue, FLastPos, SizeOf(Int64));
      finally
        LRegistry.CloseKey;
      end;
    end;
  finally
    LRegistry.Free;
  end;
end;

function TfreeSSHdSecurity.GetIniOptions : TIniOptions;
var
  LIniFile : TIniFile;
begin
  Result.FilterInclude := false;
  Result.FilterList    := '';
  Result.LogActive     := false;
  Result.LogFile       := '';
  Result.LogResolve    := false;
  Result.Result        := false;

  if FileExists(FIniFileName) then // does *.ini file exist?
  begin
    LIniFile := TIniFile.Create(FIniFileName); // open *.ini file
    try
      Result.LogActive     := LIniFile.ReadBool(CLogSection,      CLogActive,     false); // check if logging is activated
      Result.LogFile       := LIniFile.ReadString(CLogSection,    CLogFile,       '');    // get log file name
      Result.LogResolve    := LIniFile.ReadBool(CLogSection,      CLogResolve,    false); // check if host resolving is inactivated
      Result.FilterInclude := LIniFile.ReadBool(CFilterSection,   CFilterInclude, false);
      Result.FilterList    := LIniFile.ReadString(CFilterSection, CFilterList,    '');
      Result.Result        := true;
    finally
      LiniFile.Free;
    end;
  end;
end;

procedure TfreeSSHdSecurity.SetIniOptions(var AIniOptions : TIniOptions);
var
  LIniFile : TIniFile;
begin
  AIniOptions.Result := false;

  if FileExists(FIniFileName) then // does *.ini file exist?
  begin
    LIniFile := TIniFile.Create(FIniFileName); // open *.ini file
    try
      LIniFile.WriteBool(CLogSection,      CLogActive,     AIniOptions.LogActive);
      LIniFile.WriteString(CLogSection,    CLogFile,       AIniOptions.LogFile);
      LIniFile.WriteBool(CLogSection,      CLogResolve,    AIniOptions.LogResolve);
      LIniFile.WriteBool(CFilterSection,   CFilterInclude, AIniOptions.FilterInclude);
      LIniFile.WriteString(CFilterSection, CFilterList,    AIniOptions.FilterList);
      AIniOptions.Result := true;
    finally
      LiniFile.Free;
    end;
  end;
end;

procedure TfreeSSHdSecurity.CreateMenu;
begin
  FPopupMenu := TPopupMenu.Create(nil);
  try
    FTerminate := TMenuItem.Create(FPopupMenu);
    try
      FTerminate.Caption := 'Terminate Application';
      FTerminate.Enabled := true;
      FTerminate.Name    := 'StartMenuItem';
      FTerminate.OnClick := TerminateClick;
      FTerminate.Visible := true;

      FPopupMenu.Items.Add(FTerminate);
    except
    end;

    FDivTerminate := TMenuItem.Create(FPopupMenu);
    try
      FDivTerminate.Caption := '-';
      FDivTerminate.Enabled := true;
      FDivTerminate.Name    := 'DivTerminateMenuItem';
      FDivTerminate.OnClick := nil;
      FDivTerminate.Visible := true;

      FPopupMenu.Items.Add(FDivTerminate);
    except
    end;

    FClose := TMenuItem.Create(FPopupMenu);
    try
      FClose.Caption := 'Close Menu';
      FClose.Enabled := true;
      FClose.Name    := 'CloseMenuItem';
      FClose.OnClick := nil;
      FClose.Visible := true;

      FPopupMenu.Items.Add(FClose);
    except
    end;

    TaskBarEvent := TaskBarMenu;
  except
  end;
end;

procedure TfreeSSHdSecurity.DestroyMenu;
begin
  FTaskBarEvent := nil;
  if (FClose <> nil) then
    FClose.Free;
  if (FDivTerminate <> nil) then
    FDivTerminate.Free;
  if (FTerminate <> nil) then
    FTerminate.Free;
  if (FPopupMenu <> nil) then
    FPopupMenu.Free;
end;

procedure TfreeSSHdSecurity.CheckTimer(Sender : TObject);
const
  CAfterIPLine     = 'SSH';
  CBeforeIPLine    = 'IP';
  CCutLength       = 204800;
  CErrorLineA      = 'submitted a bad password.';
  CErrorLineB      = 'user unknown.';
  CFilterDelimiter = '\/';
  CFilterThreshold = 10;
  CSuccessLine     = 'successfully logged on using password.';
  CUpdateRate      = 1000;

  procedure FilterListFromString(const AFilterList : TStringList; AString : String);
  var
    LIndex : Integer;
    LPos   : Integer;
    LTemp  : String;
  begin
    if (AFilterList <> nil) then
    begin
      repeat
        AString := Trim(AString);

        LPos  := Pos(CFilterDelimiter, AString);
        LTemp := '';
        if (LPos > 0) then
        begin
          LTemp := Trim(Copy(AString, 1, Pred(LPos)));
          Delete(AString, 1, Pred(LPos + Length(CFilterDelimiter)));
        end
        else
        begin
          if (Length(AString) > 0) then
          begin
            LTemp   := AString;
            AString := '';
          end;
        end;

        if (Length(LTemp) > 0) then
        begin
          LIndex := AFilterList.IndexOf(LTemp);
          if (LIndex >= 0) then
            AFilterList.Objects[LIndex] := TObject(CFilterThreshold)
          else
            AFilterList.AddObject(LTemp, TObject(CFilterThreshold));
        end;
      until (Length(AString) <= 0);
    end;
  end;

  function FilterListToString(const AFilterList : TStringList) : String;
  var
    LIndex : Integer;
  begin
    Result := '';

    if (AFilterList <> nil) then
    begin
      for LIndex := 0 to Pred(AFilterList.Count) do
      begin
        if (Length(Trim(AFilterList[LIndex])) > 0) then
        begin
          if (Integer(AFilterList.Objects[LIndex]) >= CFilterThreshold) then
          begin
            if (Length(Result) > 0) then
              Result := Result + CFilterDelimiter;

            Result := Result + Trim(AFilterList[LIndex]);
          end;
        end;
      end;
    end;
  end;

  function GetIPFromLine(const ALine : String) : String;
  var
    LPosAfter  : Integer;
    LPosBefore : Integer;
  begin
    Result := '';

    LPosAfter  := Pos(CAfterIPLine, ALine);
    LPosBefore := Pos(CBeforeIPLine, ALine);

    if ((LPosAfter > 0) and (LPosBefore > 0) and (LPosAfter > LPosBefore)) then
      Result := Trim(Copy(ALine, LPosBefore + Length(CBeforeIPLine), LPosAfter - LPosBefore - Length(CBeforeIPLine)));
  end;

  function GetIsError(ALine : String) : Boolean;
  begin
    Result := ((Pos(CErrorLineA, ALine) > 0) or (Pos(CErrorLineB, ALine) > 0));
  end;

  function GetIsSuccess(const ALine : String) : Boolean;
  begin
    Result := (Pos(CSuccessLine, ALine) > 0);
  end;

var
  LBufferPos     : Integer;
  LChanged       : Boolean;
  LFile          : TFileStream;
  LIndex         : Integer;
  LIniOptions    : TIniOptions;
  LIP            : String;
  LLine          : String;
  LLineBuffer    : String;
  LLineCount     : Integer;
  LPos           : Integer;
begin
  FTimer.Enabled := false;
  try
    LIniOptions := GetIniOptions;
    if LIniOptions.Result then
    begin
      if (LIniOptions.LogActive and not(LIniOptions.LogResolve)) then
      begin
        if FileExists(LIniOptions.LogFile) then
        begin
          FilterListFromString(FFilterList, LIniOptions.FilterList);
          if (not(LIniOptions.FilterInclude) or (FFilterList.Count = 0)) then // check whether we can modify the filter
          begin
            SetLength(LLineBuffer, 0);

            try
              LFile := TFileStream.Create(LIniOptions.LogFile, fmOpenRead);
              try
                if (LFile.Size > FLastPos) then
                begin
                  LFile.Seek(FLastPos, soFromBeginning);

                  // read unhandled chunk from log file
                  SetLength(LLineBuffer, LFile.Size - FLastPos);
                  LFile.Read(LLineBuffer[1], Length(LLineBuffer));

                  FLastPos := LFile.Size;
                end;
              finally
                LFile.Free;
              end;

              if (Length(LLineBuffer) > 0) then
              begin
                LBufferPos := 1;
                LChanged   := false;
                LLineCount := 0;
                while (LBufferPos <= Length(LLineBuffer)) do
                begin
                  // cut Buffer after 200kb have been handled
                  // speeds up Pos() operation again
                  while (LBufferPos > CCutLength) do
                  begin
                    Delete(LLineBuffer, 1, CCutLength);
                    LBufferPos := LBufferPos - CCutLength;
                  end;

                  LPos  := Pos(sLineBreak, LLineBuffer);
                  if (LPos > 0) then
                  begin
                    // read next line by looking for line break
                    LLine      := Copy(LLineBuffer, LBufferPos, LPos - LBufferPos);
                    LBufferPos := LPos + Length(sLineBreak);

                    // kill found line break
                    for LIndex := 1 to Length(sLineBreak) do
                      LLineBuffer[Pred(LPos + LIndex)] := #0;
                  end
                  else
                  begin
                    // get rest of file
                    // move buffer pointer behind last character
                    LLine      := Copy(LLineBuffer, LBufferPos, Succ(Length(LLineBuffer) - LBufferPos));
                    LBufferPos := Succ(Length(LLineBuffer));
                  end;
                  Inc(LLineCount);

                  if ((LLineCount mod CUpdateRate) = 0) then
                  begin
                    // update label
                    Tip := CTitle + #32 + '(Line' + #32 + IntToStr(LLineCount) + ')';
                    UpdateInSystemTray;
                    ProcessMessages;
                  end;

                  LIP := GetIPFromLine(LLine); // extract IP number
                  if (Length(LIP) > 0) then
                  begin
                    LIndex := FFilterList.IndexOf(LIP);
                    if ((LIndex < 0) or (Integer(FFilterList.Objects[LIndex]) < CFilterThreshold)) then  // only proceed if IP is not in filter yet
                    begin
                      if GetIsError(LLine) then // IP did something wrong (wrong name, wrong password)
                      begin
                        if (LIndex < 0) then
                          FFilterList.AddObject(LIP, TObject(1)) // put IP onto observation list
                        else
                        begin
                          FFilterList.Objects[LIndex] := TObject(Succ(Integer(FFilterList.Objects[LIndex]))); // count mistakes of IP

                          if (Integer(FFilterList.Objects[LIndex]) >= CFilterThreshold) then
{$IF DEFINED(MAX_SIZE)}
                          begin
                            FFilterList.Move(LIndex, 0); // put IP at the start of the filter
{$IFEND}
                            LChanged := true; // rewrite config and restart server
{$IF DEFINED(MAX_SIZE)}
                          end;
{$IFEND}
                        end;
                      end
                      else
                      begin
                        if (GetIsSuccess(LLine) and (LIndex >= 0)) then // IP did something correct
                          FFilterList.Objects[LIndex] := TObject(0);
                      end;
{$IF DEFINED(MAX_SIZE)}
                    end
                    else
                    begin
                      if ((LIndex >= 0) and (Integer(FFilterList.Objects[LIndex]) >= CFilterThreshold)) then
                      begin
                        FFilterList.Move(LIndex, 0); // put IP at the start of the filter
                        LChanged := true; // rewrite config and restart server
                      end;
{$IFEND}
                    end;
                  end;
                end;

                if LChanged then // write changes
                begin
                  if (ServiceGetState(CServiceName) = SERVICE_RUNNING) then // stop server
                    ServiceStop(CServiceName);

                  LIniOptions.FilterInclude := false;
                  LIniOptions.FilterList    := FilterListToString(FFilterList);
                  SetIniOptions(LIniOptions);
                end;
              end;
            except
              // do nothing
            end;
          end;
        end;
      end;
    end;

    Tip := CTitle + #32 + '(Position' + #32 + IntToStr(FLastPos) + ')';
    UpdateInSystemTray;
    ProcessMessages;

    if (ServiceGetState(CServiceName) <> SERVICE_RUNNING) then // start server
      ServiceStart(CServiceName);
  finally
    FTimer.Enabled := true;
  end;
end;

procedure TfreeSSHdSecurity.TerminateClick(Sender : TObject);
var
  LResult : Integer;
begin
  LResult := MessageDlg('Do you want to save the current log file position?',
                        mtConfirmation, [mbYes, mbNo, mbCancel], 0);

  if (LResult = mrYes) then
    SetLastPosition;

  if (LResult <> mrCancel) then
    SendMessage(FTinyApplicationHandle, CCloseTinyApplicationMessage, 0, 0);
end;

procedure TfreeSSHdSecurity.TaskBarMenu(var AMessage : TMessage);
var
  LMousePos : TPoint;
begin
  case AMessage.LParamLo of
    WM_RBUTTONDOWN :
    begin
      GetCursorPos(LMousePos);
      FPopupMenu.Popup(LMousePos.X, LMousePos.Y);
    end;
  end;
end;

constructor TfreeSSHdSecurity.Create(const AIniFileName : String);
begin
  inherited Create(CTitle);
  Tip := CTitle;

  FFilterList  := TStringList.Create;
  FIniFileName := AIniFileName;
  FLastPos     := GetLastPosition;

  CreateMenu;
  LoadIconFromResourceID(CIconID);
  PutToSystemTray;

  FTimer := TTimer.Create(nil);
  FTimer.OnTimer  := CheckTimer;
  FTimer.Interval := 10000; // checks every 10 seconds
  FTimer.Enabled  := true;
end;

destructor TfreeSSHdSecurity.Destroy;
begin
  FFilterList.Free;

  FTimer.Enabled := false;
  FTimer.Free;

  TakeFromSystemTray;
  DestroyMenu;

  inherited Destroy;
end;

begin
  VIniFileName := TfreeSShdSecurity.ServiceGetPath(CServiceName) + CIniFileName;
  if FileExists(VIniFileName) then
  begin
    with TfreeSSHdSecurity.Create(VIniFileName) do
    begin
      try
        RunLoop(true);
      finally
        Free;
      end;
    end;
  end;
end.
