.intel_syntax noprefix
.text
.extern MN_NTAVM
.extern MN_NTWVM
.extern MN_NTCTEX
.extern MN_NTOP
.extern MN_NTWFSO
.extern MN_NTC

.globl asm_NtAllocateVirtualMemory
asm_NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTAVM]
	syscall
	ret

.globl asm_NtWriteVirtualMemory
asm_NtWriteVirtualMemory:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTWVM]
	syscall
	ret

.globl asm_NtOpenProcess
asm_NtOpenProcess:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTOP]
	syscall
	ret

.globl asm_NtCreateThreadEx
asm_NtCreateThreadEx:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTCTEX]
	syscall
	ret

.globl asm_NtWaitForSingleObject
asm_NtWaitForSingleObject:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTWFSO]
	syscall
	ret

.globl asm_NtClose
asm_NtClose:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTC]
	syscall
	ret

