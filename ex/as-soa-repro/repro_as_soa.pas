unit repro_as_soa;

interface

{$I mormot.defines.inc}

uses
  SysUtils,
  Classes,
  mormot.core.base,
  mormot.core.os,
  mormot.core.text,
  mormot.core.json,
  mormot.core.variants,
  mormot.core.interfaces,
  mormot.core.test,
  mormot.orm.core,
  mormot.rest.core,
  mormot.rest.memserver,
  mormot.rest.http.server,
  mormot.rest.http.client,
  mormot.soa.core;

type
  TAsSoaSuite = class(TSynTests)
  published
    procedure Reproduce;
  end;

implementation

type
  IMapRelay = interface(IInvokable)
    ['{1C29113D-C199-454B-968A-F06AE78F5018}']
    function Ping: integer;
  end;

  IMapRelayLive = interface(IInvokable)
    ['{F1CBB360-3BB0-4C95-810C-5C78CACBA53D}']
    function Live: integer;
  end;

  TMapRelay = class(TInterfacedObject, IMapRelay)
    function Ping: integer;
  end;

  TMapRelayLive = class(TInterfacedObject, IMapRelayLive)
    function Live: integer;
  end;

  TCaptureClient = class(TRestHttpClientWebsockets)
  protected
    procedure InternalUri(var Call: TRestUriParams); override;
  public
    Soa: RawUtf8;
  end;

  TFirstClient = class(TThread)
  protected
    procedure Execute; override;
  public
    Client: TCaptureClient;
    Gate: TSynEvent;
    Error: string;
    constructor Create;
    destructor Destroy; override;
  end;

  TAsSoaCase = class(TSynTestCase)
  published
    procedure Scenario;
  end;

function TMapRelay.Ping: integer;
begin
  result := 1;
end;

function TMapRelayLive.Live: integer;
begin
  result := 2;
end;

procedure TCaptureClient.InternalUri(var Call: TRestUriParams);
begin
  inherited InternalUri(Call);
  if PosEx('stat/soa', Call.Url) <> 0 then
  begin
    Soa := Call.OutBody;
    UniqueRawUtf8(Soa); // ParseSoa subsequently modifies its input buffer.
  end;
end;

constructor TFirstClient.Create;
var
  error: RawUtf8;
begin
  inherited Create(true);
  Gate := TSynEvent.Create;
  Client := TCaptureClient.Create('127.0.0.1', '19091', TOrmModel.Create([]));
  Client.Model.Owner := Client;
  error := Client.WebSocketsUpgrade('');
  if error <> '' then
    raise Exception.Create(Utf8ToString(error));
end;

destructor TFirstClient.Destroy;
begin
  if Gate <> nil then
    Gate.SetEvent;
  inherited Destroy;
  Client.Free;
  Gate.Free;
end;

procedure TFirstClient.Execute;
begin
  try
    if not Gate.WaitFor(5000) then
      raise Exception.Create('client start gate timed out');
    if not Client.ServiceDefine([IMapRelay, IMapRelayLive], sicShared) then
      raise Exception.Create('ServiceDefine failed');
  except
    on E: Exception do
      Error := E.ClassName + ': ' + E.Message;
  end;
end;

function ContractText(const Value: RawUtf8): RawUtf8;
begin
  result := Value;
  if (Length(result) >= 2) and (result[1] in ['''', '"']) then
    result := Copy(result, 2, Length(result) - 2);
end;

procedure TAsSoaCase.Scenario;
var
  server: TRestServerFullMemory;
  http: TRestHttpServer;
  first, second: TServiceFactory;
  clients: array[0..1] of TFirstClient;
  expected, cached: RawUtf8;
  before: variant;
  color: TConsoleColor;
  i: integer;
begin
  TInterfaceFactory.RegisterInterfaces([TypeInfo(IMapRelay), TypeInfo(IMapRelayLive)]);
  server := TRestServerFullMemory.CreateWithOwnModel([], false);
  http := nil;
  FillChar(clients, SizeOf(clients), 0);
  try
    first := server.ServiceDefine(TMapRelay, [IMapRelay], sicShared);
    if FindCmdLineSwitch('late') then
      before := server.Services.AsSoa;
    second := server.ServiceDefine(TMapRelayLive, [IMapRelayLive], sicShared);
    expected := FormatUtf8('["MapRelay","%",1,"MapRelayLive","%",1]',
      [ContractText(first.ContractExpected), ContractText(second.ContractExpected)]);
    ConsoleWrite(FormatUtf8('EXPECTED %', [expected]), ccCyan);
    if FindCmdLineSwitch('late') then
    begin
      cached := VariantSaveJson(server.Services.AsSoa);
      ConsoleWrite(FormatUtf8('LATE %', [cached]), ccYellow);
      CheckEqual(cached, expected, 'service registered after first AsSoa');
      exit;
    end;
    if FindCmdLineSwitch('warm') then
      before := server.Services.AsSoa;
    http := TRestHttpServer.Create('19091', [server], '+', WEBSOCKETS_DEFAULT_MODE);
    http.WebSocketsEnable(server, '');
    for i := 0 to high(clients) do
    begin
      clients[i] := TFirstClient.Create;
      clients[i].Start;
    end;
    ConsoleWrite(FormatUtf8('READY two clients; warm=%',
      [FindCmdLineSwitch('warm')]), ccCyan);
    for i := 0 to high(clients) do
      clients[i].Gate.SetEvent;
    for i := 0 to high(clients) do
    begin
      clients[i].WaitFor;
      if clients[i].Error = '' then
        color := ccGreen
      else
        color := ccLightRed;
      ConsoleWrite(FormatUtf8('CLIENT % ERROR %', [i, clients[i].Error]), color);
      if clients[i].Client.Soa = expected then
        color := ccGreen
      else
        color := ccLightRed;
      ConsoleWrite(FormatUtf8('CLIENT % SOA %', [i, clients[i].Client.Soa]), color);
      Check(clients[i].Error = '', 'client exception');
      CheckEqual(clients[i].Client.Soa, expected, 'GET stat/soa response');
    end;
    cached := VariantSaveJson(server.Services.AsSoa);
    if cached = expected then
      color := ccGreen
    else
      color := ccLightRed;
    ConsoleWrite(FormatUtf8('CACHED %', [cached]), color);
    CheckEqual(cached, expected, 'cached AsSoa after both first clients');
  finally
    for i := 0 to high(clients) do
      if clients[i] <> nil then
        clients[i].Gate.SetEvent;
    for i := 0 to high(clients) do
      clients[i].Free;
    http.Free;
    server.Free;
  end;
end;

procedure TAsSoaSuite.Reproduce;
begin
  AddCase(TAsSoaCase);
end;

end.
