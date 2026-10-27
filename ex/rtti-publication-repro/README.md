# RTTI publication — PR 692

Controlled reproduction: a `TRttiJson` subclass pauses virtual initialization methods.
A second thread calls `RegisterType` while initialization is suspended. No framework patch.
The registry is isolated; its class VMT slot is restored during cleanup.

Compile the Delphi project, then run each attempt in a fresh process:

```powershell
.\scratch\run\mormot2tests.exe /noenter
.\scratch\run\mormot2tests.exe /noenter /warm
```

Cold: an early return with `parser=0` (`ptNone`) exposes incomplete RTTI.
`/warm` registers the types first and should pass. This is not a natural timing stress test.
