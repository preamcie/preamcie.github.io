---
title: Concepts for noobs -> Run time evasion
date: 2026-06-30 00:00:00 +0800
categories: [Red Team]
tags: [redteam, notes]
permalink: /redteam/loader2/
---

# Concepts for noobs -> Run time evasion

## Call Stacks

Previously, we only used Call stack spoofing for VirtualAlloc, VirtualProtect, LoadLibraryA. These are the functions that the loader used to load the Beacon .dll. 

However, now the issue is that the Beacon itself makes its own API calls -> 

1. InternetConnectA
2. OpenProcess
3. Sleep

The loader's `attach` hooks don't cover those as it only patches the loader's DFR references. It didn't have an IAT. This beacon is a .dll. Beacon's API calls goes through it's own IAT. So we use `GetProcAddress` here.

The reason we can't use `findFunctionByHash` and walk the EAT entries of the Beacon (and reuse the old hooking logic), like what the loader did, is because that's how the Beacon was built by Cobalt Strike, and it's closed-sourced. 

So the only way is to hook the `GetProcAddress` functions by the Beacon itself. Now we can control the addresses that are being returned from all the APIs. If it's returned from unbacked memory, just call stack spoof it like earlier. 

![hooked flow](/assets/img/hookedFunction.png)

![pico.spec](/assets/img/picoSpec.png)

## Indirect Syscalls

Basically this is just about how to use indirect syscalls instead of call stack spoofing. The course stated explicitly that you could use both techniques at once. However, you usually only need one, depending on what kind of defense you are dealing with. 

## Memory Obfuscation

Since we disabled CS kit for `sleep_mask`, we need to implement one ourselves. 

We need to hook Beacon's `sleep` function. 

1. XOR encrypt all of Beacon's PE sections in memory
2. Change RX sections (like .text) to RW - so there's no executable memory visible. 
3. Call the real `sleep`. 
4. When Beacon wakes up, decrypt everything. 
5. Change permissions back to their original values. 
6. Return control to Beacon. 

However, when changing the memory we have to use `VirtualProtect`, but the previous `addhook` function only intecepts APIs resolved through `_GetProcAddress` during `ProcessImports` for Beacon's imports. The PICO'S own VirtualProtect calls aren't Beacon imports, so `addhook` doesn't cover them.

Fix: add `attach` in pico.spec for VirtualProtect, which patches the PICO's own DFR reference at link time. 

![3 layers of hooking](/assets/img/hooking.png)






