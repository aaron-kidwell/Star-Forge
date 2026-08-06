.code
EXTERN g_ssn:DWORD
EXTERN g_syscall:QWORD



iNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    jmp qword ptr [g_syscall]
iNtAllocateVirtualMemory ENDP



iNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    jmp qword ptr [g_syscall]
iNtWriteVirtualMemory ENDP



iNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn
    jmp qword ptr [g_syscall]
iNtProtectVirtualMemory ENDP
end