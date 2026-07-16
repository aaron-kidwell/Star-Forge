#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include "config.h"
#include <wtsapi32.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <iphlpapi.h>
#include <lmshare.h>
#pragma comment(lib, "ws2_32.lib")
#include "injection.h"

VOID collect_installed_apps(HMODULE hAdvapi);
PVOID manual_procaddress(HMODULE hModule, const char* funcName);

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
	typedef VOID(WINAPI* pWTSFreeMemory)(
		PVOID pMemory
		);
	pWTSEnumerateProcessesW WTSEnum = (pWTSEnumerateProcessesW)manual_procaddress(wts, "WTSEnumerateProcessesW");
	pWTSFreeMemory WTSFreeMem = (pWTSFreeMemory)manual_procaddress(wts, "WTSFreeMemory");
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
	typedef NET_API_STATUS(WINAPI* pNetApiBufferFree)(
		_Frees_ptr_opt_ LPVOID Buffer
		);
	typedef NET_API_STATUS(WINAPI* pNetUserEnum)(
		LPCWSTR servername,
		DWORD   level,
		DWORD   filter,
		LPBYTE* bufptr,
		DWORD   prefmaxlen,
		LPDWORD entriesread,
		LPDWORD totalentries,
		PDWORD  resume_handle
		);
	typedef NET_API_STATUS(WINAPI* pNetLocalGroupGetMembers)(
		LPCWSTR    servername,
		LPCWSTR    localgroupname,
		DWORD      level,
		LPBYTE* bufptr,
		DWORD      prefmaxlen,
		LPDWORD    entriesread,
		LPDWORD    totalentries,
		PDWORD_PTR resumehandle
		);
	typedef NET_API_STATUS(WINAPI* pNetLocalGroupEnum)(
		LPCWSTR    servername,
		DWORD      level,
		LPBYTE* bufptr,
		DWORD      prefmaxlen,
		LPDWORD    entriesread,
		LPDWORD    totalentries,
		PDWORD_PTR resumehandle
		);
	typedef NET_API_STATUS(WINAPI* pNetShareEnum)(
		LMSTR   servername,
		DWORD   level,
		LPBYTE* bufptr,
		DWORD   prefmaxlen,
		LPDWORD entriesread,
		LPDWORD totalentries,
		LPDWORD resume_handle
		);

	pNetLocalGroupEnum grpenum = (pNetLocalGroupEnum)manual_procaddress(hNet, "NetLocalGroupEnum");
	pNetLocalGroupGetMembers usergrpenum = (pNetLocalGroupGetMembers)manual_procaddress(hNet, "NetLocalGroupGetMembers");
	pNetApiBufferFree netbufferfree = (pNetApiBufferFree)manual_procaddress(hNet, "NetApiBufferFree");
	pNetUserEnum userenum = (pNetUserEnum)manual_procaddress(hNet, "NetUserEnum");
	pNetShareEnum shareenum = (pNetShareEnum)manual_procaddress(hNet, "NetShareEnum");

	if (!grpenum || !usergrpenum || !netbufferfree || !userenum || !shareenum) {
		printf("[-] Failed to resolve one or more netapi32 functions\n");
		FreeLibrary(hNet);
		return;
	}

	// list users
	LPBYTE userinfo = NULL;
	DWORD userenumcount = 0;
	DWORD userenumtotal = 0;
	printf("calling userenum...\n");
	userenum(NULL, 3, 0, &userinfo, MAX_PREFERRED_LENGTH, &userenumcount, &userenumtotal, NULL);
	USER_INFO_3* users = (USER_INFO_3*)userinfo;
	int i;
	for (i = 0; i < userenumcount; i++) {
		wprintf(L"%ls\n", (users + i)->usri3_name);
	}

	// get localgroup names
	printf("\n===========GROUPS===========\n");
	LPBYTE grpinfo = NULL;
	DWORD grpsread = 0;
	DWORD grpstotal = 0;
	printf("calling grprenum...\n");
	grpenum(NULL, 0, &grpinfo, MAX_PREFERRED_LENGTH, &grpsread, &grpstotal, NULL);
	LOCALGROUP_INFO_0* groups = (LOCALGROUP_INFO_0*)grpinfo;

	// get users in each group
	i = 0;
	LPBYTE usergrpinfo = NULL;
	DWORD usergrpsread = 0;
	DWORD usergrpstotal = 0;
	for (i = 0; i < grpsread; i++) {
		wprintf(L"Group: %ls\n", (groups + i)->lgrpi0_name);
		printf("calling usergrpnum...\n");
		usergrpenum(NULL, (groups + i)->lgrpi0_name, 1, &usergrpinfo,
			MAX_PREFERRED_LENGTH, &usergrpsread, &usergrpstotal, NULL);
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
	printf("calling shareenum...\n");
	shareenum(NULL, 2, &shareinfo, MAX_PREFERRED_LENGTH, &sharesread, &shareinfototal, NULL);
	SHARE_INFO_2* shares = (SHARE_INFO_2*)shareinfo;
	i = 0;
	while (i < sharesread) {
		wprintf(L"%ls - %ls - %ls - Current Connections: %lu\n",
			shares[i].shi2_netname, shares[i].shi2_path,
			shares[i].shi2_remark, shares[i].shi2_current_uses);
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
	typedef ULONG(WINAPI* pGetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
	typedef ULONG(WINAPI* pGetIpNetTable)(PMIB_IPNETTABLE, PULONG, BOOL);
	typedef ULONG(WINAPI* pGetTcpTable2)(PMIB_TCPTABLE2, PULONG, BOOL);

	pGetAdaptersInfo adapterinfload = (pGetAdaptersInfo)manual_procaddress(ifdll, "GetAdaptersInfo");
	pGetIpNetTable   ipnettable = (pGetIpNetTable)manual_procaddress(ifdll, "GetIpNetTable");
	pGetTcpTable2    gettcptable = (pGetTcpTable2)manual_procaddress(ifdll, "GetTcpTable2");

	PIP_ADAPTER_INFO adaptinf = NULL;
	ULONG adaptinfosize = 0;
	adapterinfload(NULL, &adaptinfosize);
	adaptinf = (PIP_ADAPTER_INFO)malloc(adaptinfosize);
	adapterinfload(adaptinf, &adaptinfosize);

	PIP_ADAPTER_INFO current = adaptinf;
	while (current != NULL) {
		printf("\n");
		printf("IP Address: %s\n", current->IpAddressList.IpAddress.String);
		printf("Description: %s\n", current->Description);
		printf("MAC Address: ");
		for (int i = 0; i < current->AddressLength; i++) {
			printf("%02X", current->Address[i]);
			if (i < current->AddressLength - 1) printf("-");
		}
		printf("\n");
		printf("Adapter: %s\n", current->AdapterName);
		if (current->DhcpEnabled == 1) {
			printf("DHCP: Yes\n");
			printf("DHCP Server: %s\n", current->DhcpServer.IpAddress.String);
		}
		else {
			printf("DHCP: No\n");
		}
		current = current->Next;
	}

	// ARP cache
	PMIB_IPNETTABLE arpTable = NULL;
	ULONG arpsize = 0;
	ipnettable(NULL, &arpsize, TRUE);
	arpTable = (PMIB_IPNETTABLE)malloc(arpsize);
	ipnettable(arpTable, &arpsize, TRUE);

	printf("\nARP Entries: %d\n", arpTable->dwNumEntries);
	for (DWORD i = 0; i < arpTable->dwNumEntries; i++) {
		BYTE* ip = (BYTE*)&arpTable->table[i].dwAddr;
		printf("%d.%d.%d.%d - ", ip[0], ip[1], ip[2], ip[3]);
		if (arpTable->table[i].dwType == (DWORD)4) printf("Static - ");
		for (DWORD j = 0; j < arpTable->table[i].dwPhysAddrLen; j++) {
			printf("%02X", arpTable->table[i].bPhysAddr[j]);
			if (j < arpTable->table[i].dwPhysAddrLen - 1) printf("-");
		}
		printf("\n");
	}

	// TCP table
	PMIB_TCPTABLE2 tcptable = NULL;
	ULONG tcpreturn = 0;
	gettcptable(NULL, &tcpreturn, TRUE);
	tcptable = (PMIB_TCPTABLE2)malloc(tcpreturn);
	gettcptable(tcptable, &tcpreturn, TRUE);

	printf("\nTCP Entries: %d\n", tcptable->dwNumEntries);
	for (DWORD i = 0; i < tcptable->dwNumEntries; i++) {
		BYTE* srcip = (BYTE*)&tcptable->table[i].dwLocalAddr;
		BYTE* dstip = (BYTE*)&tcptable->table[i].dwRemoteAddr;
		printf("%d.%d.%d.%d:%d - %d.%d.%d.%d:%d - ",
			srcip[0], srcip[1], srcip[2], srcip[3],
			ntohs((u_short)tcptable->table[i].dwLocalPort),
			dstip[0], dstip[1], dstip[2], dstip[3],
			ntohs((u_short)tcptable->table[i].dwRemotePort));
		switch (tcptable->table[i].dwState) {
		case 1:  printf("CLOSED");       break;
		case 2:  printf("LISTEN");       break;
		case 3:  printf("SYN-SENT");     break;
		case 4:  printf("SYN-RECEIVED"); break;
		case 5:  printf("ESTABLISHED");  break;
		case 6:  printf("FIN-WAIT");     break;
		case 7:  printf("FIN-WAIT");     break;
		case 8:  printf("CLOSE-WAIT");   break;
		case 9:  printf("CLOSING");      break;
		case 10: printf("LAST-ACK");     break;
		case 11: printf("TIME-WAIT");    break;
		case 12: printf("TCB");          break;
		default: printf("NA");           break;
		}
		printf(" - PID: %d\n", tcptable->table[i].dwOwningPid);
	}

	FreeLibrary(ifdll);
	free(adaptinf);
	free(arpTable);
	free(tcptable);
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
	typedef BOOL(WINAPI* pOpenProcessToken)      (HANDLE, DWORD, PHANDLE);
	typedef BOOL(WINAPI* pGetTokenInformation)   (HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
	typedef PDWORD(WINAPI* pGetSidSubAuthority)    (PSID, DWORD);
	typedef PUCHAR(WINAPI* pGetSidSubAuthorityCount)(PSID);
	typedef BOOL(WINAPI* pLookupPrivilegeNameW)  (LPCWSTR, PLUID, LPWSTR, LPDWORD);

	pOpenProcessToken       openproctoken = (pOpenProcessToken)manual_procaddress(tokendll, "OpenProcessToken");
	pGetTokenInformation    gettokeninfo = (pGetTokenInformation)manual_procaddress(tokendll, "GetTokenInformation");
	pGetSidSubAuthority     getsidsubauth = (pGetSidSubAuthority)manual_procaddress(tokendll, "GetSidSubAuthority");
	pGetSidSubAuthorityCount getsidsubauthcount = (pGetSidSubAuthorityCount)manual_procaddress(tokendll, "GetSidSubAuthorityCount");
	pLookupPrivilegeNameW   getprivname = (pLookupPrivilegeNameW)manual_procaddress(tokendll, "LookupPrivilegeNameW");

	HANDLE token;
	if (openproctoken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token) != 0) {
		printf("[x] Opened handle to token!\n");
	}
	else {
		printf("[-] Could not open handle to token. Error code: %d\n", GetLastError());
	}

	DWORD tokeninfolength = 0;
	gettokeninfo(token, TokenIntegrityLevel, NULL, 0, &tokeninfolength);
	LPVOID tokeninforeturn = malloc(tokeninfolength);
	gettokeninfo(token, TokenIntegrityLevel, tokeninforeturn, tokeninfolength, &tokeninfolength);
	TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)tokeninforeturn;

	DWORD count = *getsidsubauthcount(tml->Label.Sid);
	DWORD integrityLevel = *getsidsubauth(tml->Label.Sid, count - 1);

	if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID)      printf("Integrity: Low\n");
	else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID)   printf("Integrity: Medium\n");
	else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) printf("Integrity: High\n");
	else                                                       printf("Integrity: SYSTEM\n");

	free(tokeninforeturn);
	tokeninfolength = 0;
	tokeninforeturn = NULL;
	gettokeninfo(token, TokenPrivileges, NULL, 0, &tokeninfolength);
	tokeninforeturn = malloc(tokeninfolength);
	gettokeninfo(token, TokenPrivileges, tokeninforeturn, tokeninfolength, &tokeninfolength);
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

	collect_installed_apps(tokendll);
	CloseHandle(token);
	FreeLibrary(tokendll);
	free(tokeninforeturn);
	printf("\n[x] Memory freed\n");
	printf("[x] Handles closed\n");
}

VOID collect_installed_apps(HMODULE hAdvapi) {
	typedef LSTATUS(WINAPI* pRegOpenKeyExW)  (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
	typedef LSTATUS(WINAPI* pRegEnumKeyExW)  (HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
	typedef LSTATUS(WINAPI* pRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

	pRegOpenKeyExW   regopen = (pRegOpenKeyExW)manual_procaddress(hAdvapi, "RegOpenKeyExW");
	pRegEnumKeyExW   regenum = (pRegEnumKeyExW)manual_procaddress(hAdvapi, "RegEnumKeyExW");
	pRegQueryValueExW regquery = (pRegQueryValueExW)manual_procaddress(hAdvapi, "RegQueryValueExW");

	printf("\n===========APPLICATIONS===========\n");

	// helper lambda equivalent — repeated block for each key
	HKEY key;
	DWORD index;
	WCHAR subkeyName[256];
	DWORD subkeyNameSize;

	// 64-bit apps
	if (regopen(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		0, KEY_READ, &key) == ERROR_SUCCESS) {
		printf("[x] Reg Key Opened\n");
		index = 0; subkeyNameSize = 256;
		while (regenum(key, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			HKEY appkey;
			regopen(key, subkeyName, 0, KEY_READ, &appkey);
			DWORD dataSize = 0;
			regquery(appkey, L"DisplayName", NULL, NULL, NULL, &dataSize);
			if (dataSize > 0) {
				WCHAR* displayName = (WCHAR*)malloc(dataSize);
				regquery(appkey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize);
				wprintf(L"%ls\n", displayName);
				free(displayName);
			}
			RegCloseKey(appkey);
			index++; subkeyNameSize = 256;
		}
		RegCloseKey(key);
	}
	else printf("[-] Error Opening Reg Key\n");

	// 32-bit apps
	if (regopen(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		0, KEY_READ, &key) == ERROR_SUCCESS) {
		printf("[x] Reg Key Opened\n");
		index = 0; subkeyNameSize = 256;
		while (regenum(key, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			HKEY appkey;
			regopen(key, subkeyName, 0, KEY_READ, &appkey);
			DWORD dataSize = 0;
			regquery(appkey, L"DisplayName", NULL, NULL, NULL, &dataSize);
			if (dataSize > 0) {
				WCHAR* displayName = (WCHAR*)malloc(dataSize);
				regquery(appkey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize);
				wprintf(L"%ls\n", displayName);
				free(displayName);
			}
			RegCloseKey(appkey);
			index++; subkeyNameSize = 256;
		}
		RegCloseKey(key);
	}
	else printf("[-] Error Opening Reg Key\n");

	// per-user apps
	if (regopen(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		0, KEY_READ, &key) == ERROR_SUCCESS) {
		printf("[x] Reg Key Opened\n");
		index = 0; subkeyNameSize = 256;
		while (regenum(key, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			HKEY appkey;
			regopen(key, subkeyName, 0, KEY_READ, &appkey);
			DWORD dataSize = 0;
			regquery(appkey, L"DisplayName", NULL, NULL, NULL, &dataSize);
			if (dataSize > 0) {
				WCHAR* displayName = (WCHAR*)malloc(dataSize);
				regquery(appkey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize);
				wprintf(L"%ls\n", displayName);
				free(displayName);
			}
			RegCloseKey(appkey);
			index++; subkeyNameSize = 256;
		}
		RegCloseKey(key);
	}
	else printf("[-] Error Opening Reg Key\n");
}