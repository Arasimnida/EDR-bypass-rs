.intel_syntax noprefix
.text
.extern MN_NTAVM

.globl asm_NtAllocateVirtualMemory
asm_NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTAVM]
	syscall
	ret

