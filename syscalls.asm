.code
EXTERN g_ssn:DWORD
EXTERN g_syscall:QWORD

NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    syscall
    ret
NtAllocateVirtualMemory ENDP

iNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    jmp qword ptr [g_syscall]
iNtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    syscall
    ret
NtWriteVirtualMemory ENDP

iNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    jmp qword ptr [g_syscall]
iNtWriteVirtualMemory ENDP
end