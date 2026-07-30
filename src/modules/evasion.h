#pragma once

BOOL EtwPatch();
BOOL EdrHookerCheck();
BOOL unhook_Ntdll();
BOOL AmsiPatch();
DWORD getSSN(char* funcName);
extern DWORD g_ssn;