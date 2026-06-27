---
title: Concepts for noobs -> Load time evasion
date: 2026-06-27 00:00:00 +0800
categories: [Red Team]
tags: [redteam, notes]
permalink: /redteam/loader/
---

# Concepts for noobs -> Load time evasion

## Simple Loader

![How the loader works](/assets/img/loader.png)

## Concept

Even in memory, before the loader decrypts and loads Beacon, the entire blob (loader + appended DLL) is sitting in a VirtualAlloc'd region. If the DLL isn't XOR'd, an EDR scanning that memory region would see a chunk of shellcode with a plain PE file stuck to the end of it. That's suspicious — shellcode shouldn't have a recognizable DLL attached to it.

After the loader decrypts the DLL and loads it properly into its own memory region, it looks like any other loaded DLL — MZ header, sections, imports, all normal. At that point, the EDR can only detect it through Beacon-specific signatures, which string replacement handles.

## Static signatures

The raw beacon DLL is appended right after the loader. When the beacon is loaded into memory, the entire PE can be seen. 
All sections, all strings, all code. However, as stated above, it doesn't matter anymore. They can only detect with Beacon-specific signatures. 

```
# replace some common strings
    $beacon = strrep_pad ( $beacon, "beacon.x64.dll", "bacon.x64.dll" );
    $beacon = strrep_pad ( $beacon, "%02d/%02d/%02d", "%02d/%02d/%04d" );
    $beacon = strrep_pad ( $beacon, "%s as %s\%s: %d", "%s - %s\%s (%d)" );
    $beacon = strrep_pad ( $beacon, "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x59\x10\x48\x8B\xF9\x48\x8B\x49\x08\xFF\x17\x33\xD2\x41\xB8\x00\x80\x00\x00", "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x59\x10\x48\x8B\xF9\x48\x8B\x49\x08\xFF\x17\x33\xD2\x41\xB8\x01\x80\x00\x00" );
```

## Removing RWX memory 

It loops through the DLL's PE section, then check where the memory addresses are for each section. for each section, change the permissions to what the default should be like using VirtualProtect.

Note: technically the logic for this part will never change, but what will change is how you hide VirtualProtect through Call Stack spoofing.

![Permissions and their original settings](/assets/img/rwxMemory.png)

## What was configured for me in the crystal kit lab

### Simple Loader takeaways

1. DFR -> Dynamic Function Resolution

Normally, when `VirtualAlloc` is called in a regular program, the compiler and linked reference it at build time, it goes into the import table, and the Windows loader connects it to the real function when the process starts. That's static resolution. 

However, since PIC has no import table, you need to find out where VirtualAlloc lives in memory by itself. 

At link time, hash of VirtualAlloc is calculated already `0x91AFCA54`. At run time, findFunctionByHash walks through the EAT entries, hashes every thing one by one, and compares it to the hashed value earlier. 

The point of this is so that the string `VirtualAlloc` and `Kernel32` is never anywhere in the final PIC.

<span style="color:rgb(192, 0, 0)">Special Note: ImportFuncs</span> 

Only for `LoadLibraryA` and `GetProcAddress`, we don't have to do `KERNEL32$LoadLibraryA` or `KERNEL32$GetProcAddress`. Crystal palace handles this shortcut. 

2. Makefile
3. Spec file
4. Linked resources

This section is just telling you how many sections you want appended to the loader, and where they are in memory. In this case we only use 1 which is DLL. 

### Loader Modularity 

### Resource Masking

### Applying Evasive Tradecraft

## What was done in the lab

1. Disable CS's built-in evasion
2. Uncomment attach/preserve in loader.spec -> enables Draugr call stack spoofing hooks
3. Add strrep_pad calls in crystalkit.cna -> replace static strings 

## Questions? 

What is link time? Build time? 

MakeFile -> Build time is when you compile a C code into COFF object file. Each .c file will become .o file by changing source code into machine code. 

Spec file (instructions for link time)-> Link time is when Crystal Palace combines everything into the final PIC.