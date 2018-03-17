unit TinyAppU;

interface

uses
  Windows,
  SysUtils,
  ShellAPI,
  Messages,
  Graphics,
  Classes;

const
  CTinyApplicationTaskBarEventMessage = WM_USER + 12121;

  CCloseTinyApplicationMessage  = WM_USER + 12131;
  CUpdateTinyApplicationMessage = WM_USER + 13121;

type
  TTinyApplication = class;

  TTinyApplicationTaskBarEvent = procedure (var AMessage : TMessage) of Object;
  TTinyApplicationEvent        = procedure of Object;
  TWindowHandle                = type LongWord;

  TTinyApplication = class(TObject)
  protected
    FClosed                : Boolean;
    FCloseEvent            : TTinyApplicationEvent;
    FCloseOnMessage        : Boolean;
    FTaskBarEvent          : TTinyApplicationTaskBarEvent;
    FTinyApplicationIcon   : TIcon;
    FTinyApplicationHandle : LongWord;
    FTinyApplicationMutex  : THandle;
    FTip                   : String;
    FUpdateEvent           : TTinyApplicationEvent;

    procedure HandleMessages(var AMessage : TMessage);
  public
    constructor Create(const AMutexName : String);

    destructor Destroy; override;

    property CloseEvent    : TTinyApplicationEvent        read FCloseEvent    write FCloseEvent;
    property TaskBarEvent  : TTinyApplicationTaskBarEvent read FTaskBarEvent  write FTaskBarEvent;
    property Tip           : String                       read FTip           write FTip;
    property UpdateEvent   : TTinyApplicationEvent        read FUpdateEvent   write FUpdateEvent;

    procedure LoadIconFromFile(const AFileName : String);
    procedure LoadIconFromResourceID(const AResourceID : LongInt);
    procedure LoadIconFromResourceName(const AResourceName : String);
    procedure ProcessMessages;
    procedure PutToSystemTray;
    procedure RunLoop(const AStopOnCloseMessage : Boolean);
    procedure TakeFromSystemTray;
    procedure UpdateInSystemTray;
  end;

implementation

const
  CTimerMessage = $0113;

{ TTinyApplication }

procedure TTinyApplication.HandleMessages(var AMessage : TMessage);
begin
  if not(FClosed) then
  begin
    case AMessage.Msg of
      CCloseTinyApplicationMessage,
      WM_CLOSE,
      WM_QUERYENDSESSION,
      WM_QUIT :
      begin
        FClosed := true;

        if Assigned(FCloseEvent) and FCloseOnMessage then
          FCloseEvent;

        AMessage.Result := 1;
      end;

      CTinyApplicationTaskBarEventMessage :
      begin
        if Assigned(FTaskBarEvent) then
          FTaskBarEvent(AMessage);
      end;

      CUpdateTinyApplicationMessage :
      begin
        if Assigned(FUpdateEvent) then
          FUpdateEvent;
      end;
    else
      DefWindowProc(FTinyApplicationHandle,
                    AMessage.Msg,
                    AMessage.wParam,
                    AMessage.lParam);
    end;
  end;
end;

constructor TTinyApplication.Create(const AMutexName : String);
begin
  inherited Create;

  FClosed := false;

  FTinyApplicationHandle := AllocateHWnd(HandleMessages);
  FTinyApplicationIcon   := TIcon.Create;
  FTinyApplicationMutex  := CreateMutex(nil, true, PChar(AMutexName));

  if (GetLastError = ERROR_ALREADY_EXISTS) then
    Destroy;
end;

destructor TTinyApplication.Destroy;
begin
  TakeFromSystemTray;

  DeallocateHWnd(FTinyApplicationHandle);

  if (FTinyApplicationIcon <> nil) then
    FTinyApplicationIcon.Free;

  if (FTinyApplicationMutex <> 0) then
    CloseHandle(FTinyApplicationMutex);

  inherited Destroy;
end;

procedure TTinyApplication.LoadIconFromFile(const AFileName : String);
begin
  FTinyApplicationIcon.LoadFromFile(AFileName);
end;

procedure TTinyApplication.LoadIconFromResourceID(const AResourceID : LongInt);
var
  ResourceStream : TResourceStream;
begin
  ResourceStream := TResourceStream.CreateFromID(hInstance, AResourceID, RT_RCDATA);
  try
    FTinyApplicationIcon.LoadFromStream(ResourceStream);
  finally
    ResourceStream.Free;
  end;
end;

procedure TTinyApplication.LoadIconFromResourceName(const AResourceName : String);
var
  ResourceStream : TResourceStream;
begin
  ResourceStream := TResourceStream.Create(hInstance, AResourceName, RT_RCDATA);
  try
    FTinyApplicationIcon.LoadFromStream(ResourceStream);
  finally
    ResourceStream.Free;
  end;
end;

procedure TTinyApplication.ProcessMessages;
var
  LMessage : TMsg;
begin
  while PeekMessage(LMessage, 0, 0, 0, PM_REMOVE) do
  begin
    if ((LMessage.Message <> CCloseTinyApplicationMessage) and
        (LMessage.Message <> WM_CLOSE) and
        (LMessage.Message <> WM_QUERYENDSESSION) and
        (LMessage.Message <> WM_QUIT)) then
    begin
      TranslateMessage(LMessage);
      DispatchMessage(LMessage);
    end
    else
      Break;
  end;
end;

procedure TTinyApplication.PutToSystemTray;
var
  MaxLength      : Integer;
  NotifyIconData : TNotifyIconData;
begin
  try
    FillChar(NotifyIconData.szTip, Length(NotifyIconData.szTip), 0);

    MaxLength := Length(FTip);
    if (MaxLength >= Length(NotifyIconData.szTip)) then
      MaxLength := Pred(Length(NotifyIconData.szTip));

    StrLCopy(@NotifyIconData.szTip[0], @FTip[1], MaxLength);

    NotifyIconData.cbSize           := SizeOf(TNotifyIconData);
    NotifyIconData.hIcon            := FTinyApplicationIcon.Handle;
    NotifyIconData.uCallbackMessage := CTinyApplicationTaskBarEventMessage;
    NotifyIconData.uFlags           := NIF_MESSAGE or NIF_ICON or NIF_TIP;
    NotifyIconData.uID              := 1;
    NotifyIconData.Wnd              := FTinyApplicationHandle;

    Shell_NotifyIcon(NIM_ADD, @NotifyIconData);
  except
  end;
end;

procedure TTinyApplication.RunLoop(const AStopOnCloseMessage : Boolean);
var
  MessageRecord : TMsg;
begin
  FClosed         := false;
  FCloseOnMessage := AStopOnCloseMessage;

  while (not(FClosed and FCloseOnMessage)) and
        GetMessage(MessageRecord, 0, 0, 0) do
  begin
    TranslateMessage(MessageRecord);
    DispatchMessage(MessageRecord);
  end;
end;

procedure TTinyApplication.TakeFromSystemTray;
var
  NotifyIconData : TNotifyIconData;
begin
  try
    NotifyIconData.cbSize := SizeOf(TNotifyIconData);
    NotifyIconData.uID    := 1;
    NotifyIconData.Wnd    := FTinyApplicationHandle;

    Shell_NotifyIcon(NIM_DELETE, @NotifyIconData);
  except
  end;
end;

procedure TTinyApplication.UpdateInSystemTray;
var
  MaxLength      : Integer;
  NotifyIconData : TNotifyIconData;
begin
  try
    FillChar(NotifyIconData.szTip, Length(NotifyIconData.szTip), 0);

    MaxLength := Length(FTip);
    if (MaxLength >= Length(NotifyIconData.szTip)) then
      MaxLength := Pred(Length(NotifyIconData.szTip));

    StrLCopy(@NotifyIconData.szTip[0], @FTip[1], MaxLength);

    NotifyIconData.cbSize           := SizeOf(TNotifyIconData);
    NotifyIconData.hIcon            := FTinyApplicationIcon.Handle;
    NotifyIconData.uCallbackMessage := CTinyApplicationTaskBarEventMessage;
    NotifyIconData.uFlags           := NIF_MESSAGE or NIF_ICON or NIF_TIP;
    NotifyIconData.uID              := 1;
    NotifyIconData.Wnd              := FTinyApplicationHandle;

    Shell_NotifyIcon(NIM_MODIFY, @NotifyIconData);
  except
  end;
end;

end.