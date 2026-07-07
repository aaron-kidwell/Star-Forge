#include <stdio.h>
#include <windows.h>
#include "config.h"
#include <libloaderapi.h>
#include <wtsapi32.h>
#include <lmaccess.h>
#include <lmapibuf.h>

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

VOID collect_usergrps() {
	HMODULE hNet = LoadLibraryW(L"netapi32.dll");
	if (hNet == NULL) {
		printf("netapi32.dll could not be loaded. Error code: %d\n", GetLastError());
		return;
	}
	else {
		printf("[x] netapi32.dll loaded\n");
	}
	typedef NET_API_STATUS (WINAPI* NetApiBufferFree)(
		_Frees_ptr_opt_ LPVOID Buffer
	);
	typedef NET_API_STATUS (WINAPI* NetUserEnum)(
		LPCWSTR servername,
		DWORD   level,
		DWORD   filter,
		LPBYTE * bufptr,
		DWORD   prefmaxlen,
		LPDWORD entriesread,
		LPDWORD totalentries,
		PDWORD  resume_handle
	);
	NetApiBufferFree netbufferfree = (NetApiBufferFree)GetProcAddress(hNet, "NetApiBufferFree");
	NetUserEnum userenum = (NetUserEnum)GetProcAddress(hNet, "NetUserEnum");
	LPBYTE userinfo = NULL;
	DWORD userenumcount = 0;
	DWORD userenumtotal = 0;
	userenum(
		NULL, 
		3, 
		0, 
		&userinfo,
		MAX_PREFERRED_LENGTH,
		&userenumcount,
		&userenumtotal,
		NULL);
	USER_INFO_3* users = (USER_INFO_3*)userinfo;
	int i;
	for (i = 0; i < userenumcount; i++) {
		wprintf(L"%ls\n", (users + i)->usri3_name);
	}
	
	netbufferfree(userinfo);
	FreeLibrary(hNet);
	printf("[x] Memory freed\n");
	printf("[x] Handles closed\n");
}