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





