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
		wprintf(L"%d -> %ls\n", (procinfo + i)->ProcessId, (procinfo + i)->pProcessName);
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
	typedef NET_API_STATUS  (WINAPI* NetLocalGroupGetMembers)(
		LPCWSTR    servername,
		LPCWSTR    localgroupname,
		DWORD      level,
		LPBYTE * bufptr,
		DWORD      prefmaxlen,
		LPDWORD    entriesread,
		LPDWORD    totalentries,
		PDWORD_PTR resumehandle
	);
	typedef NET_API_STATUS (WINAPI* NetLocalGroupEnum)(
		LPCWSTR    servername,
		DWORD      level,
		LPBYTE * bufptr,
		DWORD      prefmaxlen,
		LPDWORD    entriesread,
		LPDWORD    totalentries,
		PDWORD_PTR resumehandle
	);

	NetLocalGroupEnum grpenum = (NetLocalGroupEnum)GetProcAddress(hNet, "NetLocalGroupEnum");
	NetLocalGroupGetMembers usergrpenum = (NetLocalGroupGetMembers)GetProcAddress(hNet, "NetLocalGroupGetMembers");
	NetApiBufferFree netbufferfree = (NetApiBufferFree)GetProcAddress(hNet, "NetApiBufferFree");
	NetUserEnum userenum = (NetUserEnum)GetProcAddress(hNet, "NetUserEnum");
	
	// list users
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

	//get localgroup names
	printf("\n===========GROUPS===========\n");
	LPBYTE grpinfo = NULL;
	DWORD grpsread = 0;
	DWORD grpstotal = 0;
	grpenum(NULL, 0, &grpinfo, MAX_PREFERRED_LENGTH, &grpsread, &grpstotal, NULL);
	LOCALGROUP_INFO_0* groups = (LOCALGROUP_INFO_0*)grpinfo;
	
	// get users in each group
	i = 0;
	LPBYTE usergrpinfo = NULL;
	DWORD usergrpsread = 0;
	DWORD usergrpstotal = 0;
	for (i = 0; i < grpsread; i++) {
		wprintf(L"Group: %ls\n", (groups + i)->lgrpi0_name);
		usergrpenum(NULL,
			(groups + i)->lgrpi0_name,
			1,
			&usergrpinfo,
			MAX_PREFERRED_LENGTH,
			&usergrpsread,
			&usergrpstotal,
			NULL);
		if (usergrpinfo != NULL) {
			LOCALGROUP_MEMBERS_INFO_1* usersgroups = (LOCALGROUP_MEMBERS_INFO_1*)usergrpinfo;
			for (DWORD j = 0; j < usergrpsread; j++) {
				wprintf(L"  %ls\n", (usersgroups + j)->lgrmi1_name);
			}
			netbufferfree(usergrpinfo);
			usergrpinfo = NULL;
		}
	}
	
	netbufferfree(userinfo);
	netbufferfree(grpinfo);
	netbufferfree(usergrpinfo);
	FreeLibrary(hNet);
	printf("[x] Memory freed\n");
	printf("[x] Handles closed\n");
}