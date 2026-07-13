#include <stdio.h>
#include <windows.h>
#include "config.h"
#include <wtsapi32.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <iphlpapi.h>
#include <lmshare.h>

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

VOID collect_users_groups_shares() {
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
	typedef NET_API_STATUS (WINAPI* NetShareEnum)(
		LMSTR   servername,
		DWORD   level,
		LPBYTE* bufptr,
		DWORD   prefmaxlen,
		LPDWORD entriesread,
		LPDWORD totalentries,
		LPDWORD resume_handle
	);

	NetLocalGroupEnum grpenum = (NetLocalGroupEnum)GetProcAddress(hNet, "NetLocalGroupEnum");
	NetLocalGroupGetMembers usergrpenum = (NetLocalGroupGetMembers)GetProcAddress(hNet, "NetLocalGroupGetMembers");
	NetApiBufferFree netbufferfree = (NetApiBufferFree)GetProcAddress(hNet, "NetApiBufferFree");
	NetUserEnum userenum = (NetUserEnum)GetProcAddress(hNet, "NetUserEnum");
	NetShareEnum shareenum = (NetShareEnum)GetProcAddress(hNet, "NetShareEnum");
	
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

	// get local shares
	printf("\n===========SHARES===========\n");
	LPBYTE shareinfo = NULL;
	DWORD sharesread = 0;
	DWORD shareinfototal = 0;
	shareenum(NULL, 2, &shareinfo, MAX_PREFERRED_LENGTH, &sharesread, &shareinfototal, NULL);
	SHARE_INFO_2* shares = (SHARE_INFO_2*)shareinfo;
	i = 0;
	while (i < sharesread) {
		wprintf(L"%ls - %ls - %ls - Current Connections: %lu\n", 
			shares[i].shi2_netname, 
			shares[i].shi2_path, 
			shares[i].shi2_remark, 
			shares[i].shi2_current_uses);
		i++;
	}
	 



	
	netbufferfree(userinfo);
	netbufferfree(grpinfo);
	netbufferfree(usergrpinfo);
	FreeLibrary(hNet);
	printf("[x] Memory freed\n");
	printf("[x] Handles closed\n");
}

VOID collect_interfaces() {
	HMODULE ifdll = LoadLibraryW(L"Iphlpapi.dll");
	if (ifdll == NULL) {
		printf("Iphlpapi.dll could not be loaded. Error code: %d\n", GetLastError());
		return;
	}
	else {
		printf("[x] Iphlpapi.dll loaded\n");
	}
	typedef ULONG (WINAPI * GetAdaptersInfo)(
		PIP_ADAPTER_INFO AdapterInfo,
		PULONG           SizePointer
	);
	typedef ULONG (WINAPI* GetIpNetTable)(
		PMIB_IPNETTABLE IpNetTable,
		PULONG          SizePointer,
		BOOL            Order
	);


	GetAdaptersInfo adapterinfload = (GetAdaptersInfo)GetProcAddress(ifdll, "GetAdaptersInfo");
	GetIpNetTable ipnettable = (GetIpNetTable)GetProcAddress(ifdll, "GetIpNetTable");

	PIP_ADAPTER_INFO adaptinf = NULL;
	ULONG adaptinfosize = 0;
	adapterinfload(NULL, &adaptinfosize);  // first call to get size
	adaptinf = (PIP_ADAPTER_INFO)malloc(adaptinfosize);
	adapterinfload(adaptinf, &adaptinfosize);


	// looping thru a linked list here
	PIP_ADAPTER_INFO current = adaptinf;
	while (current != NULL) {
		printf("\n");
		printf("IP Address: %s\n", current->IpAddressList.IpAddress.String);
		printf("Description: %s\n", current->Description);

		// mac address
		printf("MAC Address: ");
		for (int i = 0; i < current->AddressLength; i++) {
			printf("%02X", current->Address[i]);
			if (i < current->AddressLength - 1) printf("-");
		}
		printf("\n");

		printf("Adapter: %s\n", current->AdapterName);

		// get dhcp
		if (current->DhcpEnabled == 1) {
			printf("DHCP: Yes\n");
			printf("DHCP Server: %s\n", current->DhcpServer.IpAddress.String);
		}
		else {
			printf("DHCP: No\n");
		}

		current = current->Next;
	}
	
	// get arp cache
	PMIB_IPNETTABLE arpTable = NULL;
	ULONG arpsize = 0;
	//call to get size
	ipnettable(NULL, &arpsize, TRUE);
	// allocate memory size returned from size
	arpTable = (PMIB_IPNETTABLE)malloc(arpsize);
	// call again to fill
	ipnettable(arpTable, &arpsize, TRUE);


	printf("\nARP Entries: %d\n", arpTable->dwNumEntries);
	for (DWORD i = 0; i < arpTable->dwNumEntries; i++) {
		BYTE* ip = (BYTE*)&arpTable->table[i].dwAddr;
		printf("%d.%d.%d.%d - ", ip[0], ip[1], ip[2], ip[3]);
		if (arpTable->table[i].dwType == (DWORD)4) {
			printf("Static - ");
		}

		for (DWORD j = 0; j < arpTable->table[i].dwPhysAddrLen; j++) {
			printf("%02X", arpTable->table[i].bPhysAddr[j]);
			if (j < arpTable->table[i].dwPhysAddrLen - 1) printf("-");
		}
		printf("\n");
	}

	FreeLibrary(ifdll);
	free(adaptinf);
	free(arpTable);
	printf("\n[x] Memory freed\n");
	printf("[x] Handles closed\n");

	



}

VOID collect_integrity() {
	HMODULE tokendll = LoadLibraryW(L"Advapi32.dll");
	if (tokendll == NULL) {
		printf("[-] Advapi32.dll could not be loaded. Error code: %d\n", GetLastError());
		return;
	}
	else {
		printf("[x] Advapi32.dll loaded\n");
	}
	typedef BOOL (WINAPI* OpenProcessToken)(
		HANDLE  ProcessHandle,
		DWORD   DesiredAccess,
		PHANDLE TokenHandle
	);
	typedef BOOL (WINAPI* GetTokenInformation)(
		HANDLE                  TokenHandle,
		TOKEN_INFORMATION_CLASS TokenInformationClass,
		LPVOID                  TokenInformation,
		DWORD                   TokenInformationLength,
		PDWORD                  ReturnLength
	);
	typedef PDWORD (WINAPI* GetSidSubAuthority)(
		PSID  pSid,
		DWORD nSubAuthority
	);
	typedef PUCHAR (WINAPI* GetSidSubAuthorityCount)(
		PSID pSid
	);
	typedef BOOL (WINAPI* LookupPrivilegeNameW)(
		LPCWSTR lpSystemName,
		PLUID   lpLuid,
		LPWSTR  lpName,
		LPDWORD cchName
	);

	OpenProcessToken openproctoken = (OpenProcessToken)GetProcAddress(tokendll, "OpenProcessToken");
	GetTokenInformation gettokeninfo = (GetTokenInformation)GetProcAddress(tokendll, "GetTokenInformation");
	GetSidSubAuthority getsidsubauth = (GetSidSubAuthority)GetProcAddress(tokendll, "GetSidSubAuthority");
	GetSidSubAuthorityCount getsidsubauthcount = (GetSidSubAuthorityCount)GetProcAddress(tokendll, "GetSidSubAuthorityCount");
	LookupPrivilegeNameW getprivname = (LookupPrivilegeNameW)GetProcAddress(tokendll, "LookupPrivilegeNameW");


	HANDLE token;
	if (openproctoken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token) != 0) {
		printf("[x] Opened handle to token!\n");
	}
	else {
		printf("[-] Could not open handle to token. Error code: %d\n", GetLastError());
	}
	
	DWORD tokeninfolength = 0;
	// get the size first
	gettokeninfo(token, TokenIntegrityLevel, NULL, 0, &tokeninfolength);
	//allocate the buffer to the size of the return
	LPVOID tokeninforeturn = malloc(tokeninfolength);
	// fill the buffer with the requested info
	gettokeninfo(token, TokenIntegrityLevel, tokeninforeturn, tokeninfolength, &tokeninfolength);
	// cast that info to a struct
	TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)tokeninforeturn;

	DWORD count = *getsidsubauthcount(tml->Label.Sid);
	DWORD integrityLevel = *getsidsubauth(tml->Label.Sid, count - 1);

	if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
		printf("Integrity: Low\n");
	else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID)
		printf("Integrity: Medium\n");
	else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
		printf("Integrity: High\n");
	else
		printf("Integrity: SYSTEM\n");
	
	// reusing this
	free(tokeninforeturn);
	tokeninfolength = 0;
	tokeninforeturn = NULL;
	// get the size first
	gettokeninfo(token, TokenPrivileges, NULL, 0, &tokeninfolength);
	//allocate the buffer to the size of the return
	tokeninforeturn = malloc(tokeninfolength);
	// fill the buffer with the requested info
	gettokeninfo(token, TokenPrivileges, tokeninforeturn, tokeninfolength, &tokeninfolength);

	// cast that info to a struct
	TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)tokeninforeturn;

	DWORD i = 0;
	printf("\nPermissions: \n");
	for (i = 0; i < tp->PrivilegeCount; i++) {
		WCHAR privName[256] = { 0 };
		DWORD privsize = 256;
		getprivname(NULL, &tp->Privileges[i].Luid, privName, &privsize);
		wprintf(L"%ls - %ls\n", privName, 
			(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled");
	}
	
	CloseHandle(token);
	FreeLibrary(tokendll);
	free(tokeninforeturn);
	printf("\n[x] Memory freed\n");
	printf("[x] Handles closed\n");

}