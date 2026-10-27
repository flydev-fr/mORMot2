program mormot2tests;

{$APPTYPE CONSOLE}
{$I mormot.defines.inc}

uses
  {$I mormot.uses.inc}
  mormot.core.os,
  repro_as_soa;

begin
  Executable.Command.Option('warm', 'compute AsSoa before serving');
  Executable.Command.Option('late', 'test registration after the first AsSoa');
  {$ifdef OSPOSIX}
  Executable.Command.Option('noenter', 'unattended execution');
  {$endif OSPOSIX}
  TAsSoaSuite.RunAsConsole('AsSoa standalone reproduction', []);
end.
