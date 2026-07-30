# Starforge

Modular Windows implant written in C (MSVC x64). Built as part of SANS SEC670 and ongoing research. The goal is a collection of clean, well-documented modules that can drop into existing C2 frameworks or be used standalone. Not a full C2 framework.

> For authorized testing and research only.

---

## Roadmap

- Recon module + config scaffold
- Injection primitives, XOR shellcode, manual resolve, thread hijack
- ETW patching, ntdll unhooking, direct/indirect syscalls, process hiding, Defender matrix
- Reflective DLL injection (after Week 3)
- True PE process hollowing (after Day 14.5)
- Token privesc, named pipe, registry/COM persistence, WinSock2 C2
- OPSEC pass: PEB walk, encrypted API strings, sleep jitter, strip symbols

---

