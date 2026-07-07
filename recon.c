#include <stdio.h>
#include <windows.h>
#include "config.h"
#include <libloaderapi.h>
#include <wtsapi32.h>

VOID collect_processes()
{
	HMODULE wts = LoadLibraryW(L"wtsapi32.dll");
	if (wts == NULL) {
		printf("wtsapi32.dll could not be loaded. Error code: %d\n", GetLastError());
		return;
	}
	else {
		printf("[x] wtsapi32.dll loaded\n");
	}
	typedef BOOL(WINAPI* pWTSEnumerateProcessesW)(
		HANDLE hServer,
		DWORD Reserved,
		DWORD Version,
		PWTS_PROCESS_INFOW* ppProcessInfo,
		DWORD* pCount
		);
	typedef VOID(WINAPI* WTSFreeMemory)(
		PVOID pMemory
		);
	pWTSEnumerateProcessesW WTSEnum = (pWTSEnumerateProcessesW)GetProcAddress(wts, "WTSEnumerateProcessesW");
	WTSFreeMemory WTSFreeMem = (WTSFreeMemory)GetProcAddress(wts, "WTSFreeMemory");
	PWTS_PROCESS_INFOW procinfo = NULL;
	DWORD proccount;
	WTSEnum(WTS_CURRENT_SERVER_HANDLE, 0, 1, &procinfo, &proccount);
	DWORD i;
	for (i = 0; i < proccount; i++) {
		wprintf(L"%d - %ls\n", (procinfo + i)->ProcessId, (procinfo + i)->pProcessName);
	}
	WTSFreeMem(procinfo);
	FreeLibrary(wts);
	printf("[x] Memory freed\n");
	printf("[x] Handles closed\n");
}