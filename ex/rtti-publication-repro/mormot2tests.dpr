program mormot2tests;

{$APPTYPE CONSOLE}
{$I mormot.defines.inc}

uses
  {$I mormot.uses.inc}
  mormot.core.os,
  repro_rtti;

begin
  Executable.Command.Option('warm', 'register both types before starting the threads');
  {$ifdef OSPOSIX}
  Executable.Command.Option('noenter', 'unattended execution');
  {$endif OSPOSIX}
  TRttiSuite.RunAsConsole('RTTI publication reproduction', []);
end.
