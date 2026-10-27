unit repro_rtti;

interface

{$I mormot.defines.inc}

uses
  SysUtils,
  Classes,
  mormot.core.base,
  mormot.core.os,
  mormot.core.text,
  mormot.core.rtti,
  mormot.core.json,
  mormot.core.test;

type
  TRttiSuite = class(TSynTests)
  published
    procedure Reproduce;
  end;

implementation

const
  INITIALIZATION_TIMEOUT_MS = 5000;
  THREAD_START_TIMEOUT_MS = 2000;
  READER_OBSERVATION_MS = 200;

type
  TReproItem = packed record
    Value: RawUtf8;
  end;
  TReproItems = array of TReproItem;

  TReproObject = class(TPersistent)
  private
    fValue: integer;
  published
    property Value: integer read fValue write fValue;
  end;

  TPausedRtti = class(TRttiJson)
  protected
    function SetParserType(aParser: TRttiParserType;
      aComplex: TRttiParserComplexType): TRttiCustom; override;
  public
    procedure FromRtti(aInfo: PRttiInfo); override;
  end;

  TRegisterWorker = class(TThread)
  protected
    procedure Execute; override;
  public
    Registry: TRttiCustomList;
    TypeToRegister: PRttiInfo;
    Metadata: TRttiCustom;
    ObservedParser: TRttiParserType;
    ObservedItemRtti: TRttiCustom;
    ErrorMessage: string;
    Started, Finished: TSynEvent;
    constructor Create(aRegistry: TRttiCustomList; aInfo: PRttiInfo);
    destructor Destroy; override;
  end;

  TRttiCase = class(TSynTestCase)
  private
    procedure RunScenario(const Name: RawUtf8; Info: PRttiInfo; IsArray: boolean);
  published
    procedure RegistrationPublication;
  end;

var
  WriterPaused, ResumeWriter: TSynEvent;
  TargetType: PRttiInfo;
  PauseNextInitialization: boolean;

procedure PauseInitialization(Info: PRttiInfo);
begin
  if not PauseNextInitialization or (Info <> TargetType) then
    exit;
  PauseNextInitialization := false;
  WriterPaused.SetEvent;
  if not ResumeWriter.WaitFor(INITIALIZATION_TIMEOUT_MS) then
    raise Exception.Create('initialization barrier timed out');
end;

procedure TPausedRtti.FromRtti(aInfo: PRttiInfo);
begin
  if aInfo = TypeInfo(TReproItems) then
    // Hold the writer before the array parser and item RTTI are initialized.
    PauseInitialization(aInfo);
  inherited FromRtti(aInfo);
end;

function TPausedRtti.SetParserType(aParser: TRttiParserType;
  aComplex: TRttiParserComplexType): TRttiCustom;
begin
  if Info = TypeInfo(TReproObject) then
    // Unpatched code has exposed the class slot before setting its parser.
    PauseInitialization(Info);
  result := inherited SetParserType(aParser, aComplex);
end;

constructor TRegisterWorker.Create(aRegistry: TRttiCustomList; aInfo: PRttiInfo);
begin
  inherited Create(true);
  Registry := aRegistry;
  TypeToRegister := aInfo;
  Started := TSynEvent.Create;
  Finished := TSynEvent.Create;
end;

destructor TRegisterWorker.Destroy;
begin
  inherited Destroy;
  Finished.Free;
  Started.Free;
end;

procedure TRegisterWorker.Execute;
begin
  Started.SetEvent;
  try
    Metadata := Registry.RegisterType(TypeToRegister);
    // Snapshot now: reading Metadata after joining could hide early publication.
    ObservedParser := Metadata.Parser;
    ObservedItemRtti := Metadata.ArrayRtti;
  except
    on E: Exception do
      ErrorMessage := E.ClassName + ': ' + E.Message;
  end;
  Finished.SetEvent;
end;

procedure TRttiCase.RunScenario(const Name: RawUtf8; Info: PRttiInfo; IsArray: boolean);
var
  registry: TRttiCustomList;
  writer, reader: TRegisterWorker;
  writerReady, readerReady, readerFinished: boolean;
  readerReturnedEarly, preRegister: boolean;
  color: TConsoleColor;
  {$ifndef NOPATCHVMT}
  classSlot: PPtrUInt;
  savedClassSlot: PtrUInt;
  {$endif NOPATCHVMT}
begin
  preRegister := FindCmdLineSwitch('warm');
  TargetType := Info;
  {$ifndef NOPATCHVMT}
  classSlot := nil;
  if not IsArray then
  begin
    classSlot := PPtrUInt(PAnsiChar(TReproObject) + vmtAutoTable);
    savedClassSlot := classSlot^;
  end;
  {$endif NOPATCHVMT}
  registry := TRttiCustomList.Create;
  registry.GlobalClass := TPausedRtti; // primitive RTTI remains in the global registry
  WriterPaused := TSynEvent.Create;
  ResumeWriter := TSynEvent.Create;
  writer := TRegisterWorker.Create(registry, Info);
  reader := TRegisterWorker.Create(registry, Info);
  PauseNextInitialization := not preRegister;
  try
    // /warm is the control: complete registration before either thread starts.
    if preRegister then
      registry.RegisterType(Info);

    // 1. Start the writer and hold it inside metadata initialization.
    writer.Start;
    if preRegister then
      writerReady := writer.Started.WaitFor(THREAD_START_TIMEOUT_MS)
    else
      writerReady := WriterPaused.WaitFor(THREAD_START_TIMEOUT_MS);
    if not writerReady then
      raise Exception.Create('writer did not reach initialization');

    // 2. Request the same type while the writer is still paused.
    reader.Start;
    readerReady := reader.Started.WaitFor(THREAD_START_TIMEOUT_MS);
    if not readerReady then
      raise Exception.Create('reader did not start');
    readerFinished := reader.Finished.WaitFor(READER_OBSERVATION_MS);
    readerReturnedEarly := readerFinished and not preRegister;

    // 3. Release the writer only after observing whether the reader returned.
    ResumeWriter.SetEvent;
    writer.WaitFor;
    reader.WaitFor;

    if readerReturnedEarly then
      color := ccLightRed
    else
      color := ccGreen;
    ConsoleWrite(FormatUtf8('% warm=% returned-before-release=% parser=% item-rtti=%',
      [Name, preRegister, readerReturnedEarly, ord(reader.ObservedParser),
       pointer(reader.ObservedItemRtti)]), color);
    Check(writer.ErrorMessage = '', 'writer error');
    Check(reader.ErrorMessage = '', 'reader error');
    Check(writer.Metadata = reader.Metadata, 'different RTTI objects');
    Check(not readerReturnedEarly, 'reader returned while initialization was paused');
    Check(reader.ObservedParser <> ptNone, 'reader observed an uninitialized parser');
    if IsArray then
      Check(reader.ObservedItemRtti <> nil, 'reader observed missing array item RTTI');
  finally
    ResumeWriter.SetEvent;
    writer.Free;
    reader.Free;
    PauseNextInitialization := false;
    {$ifndef NOPATCHVMT}
    // The isolated registry owns this class slot: restore it before freeing.
    if classSlot <> nil then
      PatchPointer(classSlot, savedClassSlot);
    {$endif NOPATCHVMT}
    registry.Free;
    ResumeWriter.Free;
    WriterPaused.Free;
  end;
end;

procedure TRttiCase.RegistrationPublication;
begin
  RunScenario('ARRAY', TypeInfo(TReproItems), {IsArray=}true);
  RunScenario('CLASS', TypeInfo(TReproObject), {IsArray=}false);
end;

procedure TRttiSuite.Reproduce;
begin
  AddCase(TRttiCase);
end;

initialization
  Rtti.RegisterFromText(TypeInfo(TReproItem), 'Value RawUtf8');

end.
