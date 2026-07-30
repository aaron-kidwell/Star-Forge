# Starforge

Modular Windows implant written in C (MSVC x64). Built as part of SANS SEC670 and ongoing research. The goal is a collection of clean, well-documented modules that can drop into existing C2 frameworks or be used standalone. Not a full C2 framework.

> For authorized testing and research only.

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

