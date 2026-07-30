.code
EXTERN g_ssn:DWORD

NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn    ; read SSN from global
    syscall
    ret
NtAllocateVirtualMemory ENDP
end