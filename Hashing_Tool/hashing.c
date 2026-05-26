#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

DWORD CalculateHash(const char* str, DWORD salt, bool toLower) {
    DWORD hash = 5381 + salt;
    while (*str) {
        unsigned char c = *str;
        if (toLower && c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
        str++;
    }
    return hash;
}

int main() {
    DWORD mySalt = 0x73DA31CB; // Random salt

    printf("Använd dessa värden i din kod:\n\n");
    printf("Salt: 0x%X\n", mySalt);
    printf("Hash för amsi.dll: 0x%X\n", CalculateHash("amsi.dll", mySalt, true));
    printf("Hash för ntdll.dll: 0x%X\n", CalculateHash("ntdll.dll", mySalt, true));
    printf("Hash för kernel32.dll: 0x%X\n", CalculateHash("kernel32.dll", mySalt, true));
    printf("Hash för xpsprint.dll: 0x%X\n", CalculateHash("xpsprint.dll", mySalt, true));
    printf("Hash för AmsiScanBuffer: 0x%X\n", CalculateHash("AmsiScanBuffer", mySalt, false));
    printf("Hash för NtTraceEvent: 0x%X\n", CalculateHash("NtTraceEvent", mySalt, false));
    printf("Hash för LoadLibraryW: 0x%X\n", CalculateHash("LoadLibraryW", mySalt, false));

    return 0;
}