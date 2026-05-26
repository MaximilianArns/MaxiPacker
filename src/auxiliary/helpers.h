#pragma once

#include "peb.h"

HMODULE 
WINAPI 
HlpGetModuleHandle(
    DWORD dwModuleHash,
    DWORD dwSalt
)
{
#ifdef _M_IX86 
    PEB* pPeb = (PEB*)__readfsdword(0x30);
#else
    PEB* pPeb = (PEB*)__readgsqword(0x60);
#endif

    // If dwModuleHash is 0, return the base address of the current process
    if (dwModuleHash == 0)
        return (HMODULE)(pPeb->ImageBaseAddress);

    PEB_LDR_DATA* Ldr           = pPeb->Ldr;
    LIST_ENTRY* ModuleList      = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry;           
        pListEntry != ModuleList;
        pListEntry = pListEntry->Flink) 
    {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        // Convert the Unicode buffer to a hash for comparison
        DWORD currentHash = 5381 + dwSalt;
        PWSTR pName = pEntry->BaseDllName.Buffer;
        
        while (*pName) {
            WCHAR c = *pName;
            // Convert to lowercase before hashing (since Windows modules are case-insensitive)
            if (c >= L'A' && c <= L'Z') c += 32;
            
            currentHash = ((currentHash << 5) + currentHash) + (BYTE)c;
            pName++;
        }

        if (currentHash == dwModuleHash)
            return (HMODULE)pEntry->DllBase;
    }

    return NULL;
}


FARPROC 
WINAPI 
HlpGetProcAddress(
    HMODULE hMod, 
    DWORD_PTR dwProcIdentifier, // Can be either an Ordinal or a Hash
    DWORD dwSalt
)
{
    PCHAR pBaseAddr = (PCHAR)hMod;

    IMAGE_DOS_HEADER* pDosHdr       = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr        = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* pExpDir = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pEAT = (DWORD*)(pBaseAddr + pExpDir->AddressOfFunctions);

    // Check if dwProcIdentifier is an Ordinal (below 0xFFFF)
    if ((dwProcIdentifier >> 16) == 0) 
    {
        WORD ordinal = (WORD)dwProcIdentifier & 0xFFFF;
        DWORD Base   = pExpDir->Base;

        if (ordinal < Base || ordinal >= Base + pExpDir->NumberOfFunctions)
            return NULL;

        return (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    } 
    // Otherwise, handle dwProcIdentifier as a Hash
    else 
    {
        DWORD* pNames    = (DWORD*)(pBaseAddr + pExpDir->AddressOfNames);
        WORD* pOrdinals  = (WORD*)(pBaseAddr + pExpDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) 
        {
            PCHAR sTmpFuncName = (PCHAR)(pBaseAddr + pNames[i]);
            
            // Calculate the hash for the current function name
            DWORD currentHash = 5381 + dwSalt;
            int c;
            PCHAR pStr = sTmpFuncName;
            while (c = *pStr++)
                currentHash = ((currentHash << 5) + currentHash) + c;

            // Compare the calculated hash with the target hash
            if (currentHash == (DWORD)dwProcIdentifier) 
            {
                return (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pOrdinals[i]]);
            }
        }
    }

    return NULL;
}

// Compare two memory buffers up to a specified length
static BOOL MemoryCompare(PCHAR s1, PCHAR s2, INT len) {
    for (int i = 0; i < len; i++) {
        if (s1[i] != s2[i]) return FALSE;
    }
    return TRUE;
}