# driver

Signed kernel driver loading for the Windows agent.

## What it does

- `LoadSignedDriver(driverPath, serviceName)` — installs a driver service
  key under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` and starts the
  driver with `NtLoadDriver` via the **indirect syscall table**
  (`core/lib/syscall`), avoiding the advapi32 SCM APIs that EDRs hook.
- `LoadSignedDriverBytes(b, serviceName)` — drops the image to
  `%SystemRoot%\System32\drivers\<name>.sys`, loads it, then removes the
  file (the kernel keeps the image mapped).
- `UnloadDriver(serviceName)` — stops the driver with `NtUnloadDriver` and
  deletes the service key.
- `IsLoaded(serviceName)` — checks whether the service key exists.
- `IsDriverSigned(path)` — offline Authenticode verification via
  `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`).

## Requirements

- **Signed driver only.** No DSE bypass is attempted; the `.sys` must carry
  a valid kernel-mode signature (WHQL / attestation signed).
- Administrator privileges (needed for `SeLoadDriverPrivilege` and writing
  to `HKLM`).

## Usage

```go
table, err := syscall.InitializeSyscallTable()
if err != nil {
    return err
}
syscall.RuntimeSyscallTable = table

if err := driver.LoadSignedDriver(`C:\path\to\my.sys`, "MyDriver"); err != nil {
    return err
}
defer driver.UnloadDriver("MyDriver")
```

The driver service key is kept after a successful load so `UnloadDriver` can
resolve it later; keys created by a failed load are cleaned up automatically.

Note: `NtUnloadDriver` fails with `STATUS_INVALID_DEVICE_REQUEST`
(0xC0000010) for drivers that ship with a NULL `DriverUnload` routine (e.g.
Qihoo 360's `360Netmon`). Such drivers are permanently resident and can only
be removed by a reboot; the loader cannot work around this by design.

## Tests

Safe tests (path conversion, `UNICODE_STRING` layout, signature
verification against OS-shipped files) run out of the box. The real
load/unload round trip is gated behind the `EMP3R0R_TEST_DRIVER_PATH`
environment variable pointing at a signed test driver.
