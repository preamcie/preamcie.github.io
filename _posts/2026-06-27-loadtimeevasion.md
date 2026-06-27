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

It loops through the DLL's PE section, then check where the memory addresses are for each section. for each section, change the permissions to what the default should be like using VirtualProtect

![Permissions and their original settings](/assets/img/rwxMemory.png)

