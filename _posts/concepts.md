---
title: Concepts
date: 2026-06-20 00:00:00 +0800
categories: [Red Team]
tags: [redteam, notes]
permalink: /redteam/day2/
---

# Concepts for noobs -> EDR telemetry 

## Introduction

Modules -> Kernelbase.dll

Functions -> CreateThread

Other than kernel mode drivers, code loaded from these DLLs (ntdll.dll, Kernelbase.dll) are all in user mode. 

An application running in user mode gets its own private region of private memory allocated by the operating system. If an application crashes, it does not affect other applications and its resources are released. 

An application running in kernel mode share the same virtual address. If a kernel mode driver does something wrong, it can crash the entire computer. Only code running in kernel mode can interact with a physical computer's hardware, such as RAM and hard drives.

There is a System Service Descriptor Table (SSDT) that maps syscall numbers to corresponding function pointers in the kernel. For example, `ntOpenProcess` is 0x26 (38 in dec). This is their System Service Number (SSN). 

When NtOpenProcess in ntdll.dll wants to interact with the kernel, it has to pass the SSN into the EAX register, and do a `syscall'. It allows code execution to pass from user mode into kernel mode. 

I guess its like a wall. You can't pass through it, if you want to do something like opening a process, you have to fill up a form (syscall number and arguments), through it over the wall and someone will do the work for you and throw back the result. 

## API Hooking

There are 3 types

1. IAT hooking
2. Inline hooking

You bypass these with 2 techniques
1. Manual syscalls (direct and indirect)
2. Syscall libraries
3. API unhooking

### IAT hooking

The import address table is filled with each module and the functions that are imported. 
When the PE is executed, the Windows loader loops through each DLL entry and ensure each one is loaded. It then loops through each function that is used in each loaded DLL, resolve the memory address and patch it in the IAT.

```
Flow

  1. The PE says in its Import Directory:

  I need USER32.dll
  I need MessageBoxW
  Here is the IAT slot where the address should go

  2. The Windows loader reads that metadata.
  3. The loader loads or finds USER32.dll.
  4. The loader finds MessageBoxW inside USER32.dll.
  5. The loader writes the real address into the IAT.

  Then later, when your program calls MessageBoxW, it does not search again. It
  just uses the address already stored in the IAT.
```

GetModuleHandle / LoadLibrary -> get base address of each DLL
GetProcAddress -> each function

IAT hooking is basically just changing the memory addresses in the IAT, make it jmp to Security Product's DLL instead. Then Security Product DLL will have a code to jmp back to the original code (to make sure it still works uk). 

### Inline Hooking

Basically just changing the first few functions of the code. Can be line 1 or 2 or others. 

Original function -> change into 
Detour function -> Trampoline function (just for the first few lines of code that were replaced) -> Target function (jmp back to untouched code)

### Direct syscalls

Let's say you have your own code. You want to use NtOpenProcess, but your fear it might be hooked. So you just write your own assembly stub 

```
NtOpenProcess proc
    mov r10, rcx
    mov eax, 26h
    syscall
    ret
NtOpenProcess endp
```

Since the syscall instruction is in your own code, it never touches ntdll.dll at all, so any hooks are bypassed. 

However, the call stacks look weird. 

Original
```
ntdll!NtOpenProcess
KERNELBASE!OpenProcess+0x56
Demo!main+0xa0
```

Direct syscall
```
SyscallDemo!NtOpenProcess
SyscallDemo!main+0xb7
```

Antivirus can just search for byte patterns `0xB8, 0x??, 0x00, 0x00, 0x00, 0x0F, 0x05`
```
b8 ?? 00 00 00    mov    eax,0x??
0f 05             syscall
```

### Indirect syscalls

```
NtOpenProcess proc
    mov r10, rcx
    mov eax, 26h                          ; you set the SSN yourself
    jmp QWORD PTR [ntOpenProcessSyscall]  ; jump to the syscall instruction inside ntdll!NtOpenProcess
NtOpenProcess endp
```

Basically you still set the SSN yourself, but instead of executing `syscall`, you jump to the syscall instruction inside `ntdll!NtOpenProcess`. Since this syscall is located inside ntdll.dll's memory, the call stack will show ntdll!NtOpenProcess instead of your module. 

End result - call stack
```
ntdll!NtOpenProcess+0x12
SyscallDemo!main+0x134
```

You can also try setting the SSN for NtOpenProcess but jumping to another Nt* function. 
```
EXTERN ntCloseSyscall:QWORD

.code

	NtOpenProcess proc
		mov r10, rcx
		mov eax, 26h					; <- ssn of NtOpenProcess
		jmp QWORD PTR [ntCloseSyscall]  ; <- jmp to syscall in NtClose
	NtOpenProcess endp

end
```

End result - call stack
```
ntdll!NtClose+0x12
SyscallDemo!main+0xb7
```

The point is the syscall only follows the ssn number that is set anyways. 

### Syscall libraries 

I believe this isn't an actual term. It's just that Syscall numbers changes with different build and versions of Windows, + the fact that the memory addresses of syscall instruction of any function from any module will change due to ASLR. Someone created tools to find these values at runtime so we don't need to hardcode them. 

```
0:000> uf ntdll!NtOpenProcess
00007ffd`2a6e1fb0 4c8bd1           mov     r10,rcx
00007ffd`2a6e1fb3 b826000000       mov     eax,26h
00007ffd`2a6e1fb8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffd`2a6e1fc0 7503             jne     ntdll!NtOpenProcess+0x15 (00007ffd`2a6e1fc5)  Branch
00007ffd`2a6e1fc2 0f05             syscall
00007ffd`2a6e1fc4 c3               ret
```

You probably think it's easy to just get the function pointer, add 4 to get SSN and 18 to get the syscall instruction. 
However, if this is hooked with inline hooking, this will not work. 

Remember that the point of this code is just to get the address of SSN and the syscall instruction of any function. It does not do anything else. You still have to write your own code.  

#### Hell's gate

Finds the SSN through the `mov eax` instruction. Fails to find if the function is hooked. 

#### Halo's gate

If target function is hooked, look at neighbouring functions. If neighbouring functions are hooked, keep trying until one isn't hooked, then adjust SSN accordingly. 

```
NtQueryInformationmThread 0x25
NtOpenProcess 0x26
NtSetInformationFile 0x27
```

Even if you have the SSN? How do u get the memory address of the syscall instruction? 

Remember that for `Direct Syscalls`, it doesn't matter. For `Indirect Syscalls`, you can just call from another function that isn't hooked. 

####  Tartarus's gate

2 detections for hooking. 
1. see if first 3 bytes is `4c 8b d1` (mov r10, rcx). 
2. If inline hooking doesn't hook the first line, check for the second line. Check if 4th byte is `e9` (jmp). 

## API unhooking

For IAT hooking - restore function pointers. 
For Inline hooking (more common) - restore the original functions. 

As multiple functions in ntdll.dll could be hooked, just replace the whole thing. 

Remember that most of the executable code are in .text section. Also remember that the ntdll.dll is being loaded from disk into process's memory, then the EDR's DLL overwrites the in-memory instructions with the hooks. That means the actual file on disk is never modified. 

```
Read a clean version of ntdll.dll from disk.
Get the base address of the hooked ntdll.dll in memory.
Locate its .text section.
Make the .text region writable.
Copy the .text section from the clean version over the hooked version.
Restore the .text section's memory permissions.
Flush the instruction cache.
Close handles.
```

The downside is that we are using user mode APIs like CreateFile, MapViewOfFile and VirtualProtect to read the clean copy of ntdll.dll on disk. These may be hooked. 





