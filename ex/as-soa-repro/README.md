# AsSoa cold-start race

Two unauthenticated WebSocket clients call `ServiceDefine` together against two services.

```powershell
.\scratch\run\mormot2tests.exe /noenter
.\scratch\run\mormot2tests.exe /noenter /warm
```

Each attempt needs a fresh process. Cold failures are intermittent; `/warm` precomputes
`AsSoa` before HTTP startup and should pass all five assertions. `/late` separately
demonstrates stale metadata after adding a service.

Concurrent corruption reproduced on Windows. Not reproduced under WSL in 10 cold attempts.
