.intel_syntax noprefix
.text
.extern MN_NTAVM
.extern MN_NTWVM
.extern MN_NTCTEX
.extern MN_NTOP
.extern MN_NTWFSO
.extern MN_NTC
.extern SYS_ADDR_NTOP
.extern SYS_ADDR_NTAVM
.extern SYS_ADDR_NTWVM
.extern SYS_ADDR_NTCTEX
.extern SYS_ADDR_NTWFSO
.extern SYS_ADDR_NTC

.globl asm_NtAllocateVirtualMemory
asm_NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTAVM]
	jmp qword ptr [rip + SYS_ADDR_NTAVM]

.globl asm_NtWriteVirtualMemory
asm_NtWriteVirtualMemory:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTWVM]
	jmp qword ptr [rip + SYS_ADDR_NTWVM]

.globl asm_NtOpenProcess
asm_NtOpenProcess:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTOP]
	jmp qword ptr [rip + SYS_ADDR_NTOP]

.globl asm_NtCreateThreadEx
asm_NtCreateThreadEx:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTCTEX]
	jmp qword ptr [rip + SYS_ADDR_NTCTEX]

.globl asm_NtWaitForSingleObject
asm_NtWaitForSingleObject:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTWFSO]
	jmp qword ptr [rip + SYS_ADDR_NTWFSO]

.globl asm_NtClose
asm_NtClose:
	mov r10, rcx
	mov eax, dword ptr [rip + MN_NTC]
	jmp qword ptr [rip + SYS_ADDR_NTC]

