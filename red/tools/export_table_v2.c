#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

struct _exportTable {
        DWORD offset;
        WORD ordinal;
        DWORD *functionPtr;
        DWORD *functionNameAddr;
        char *functionName;
        char *forwarderName;
};

DWORD RVA2FileOffset(DWORD RVA, PIMAGE_SECTION_HEADER sectionHeader)
{
        return RVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
}

void printExportTable(struct _exportTable **exportTable, size_t len)
{
        printf("Offset%10sOrdinals%8sFunction RVA%8sName RVA%8s%-50s%-50s\n", " ", " ", " ", " ", "Name", "Forwarder");

        for (int i = 0; i < len; i++) {
                printf("%08x%8s%8x%8s%012x%8s%08x%8s%-50s%-50s\n",
                exportTable[i]->offset, " ",
                exportTable[i]->ordinal, " ",
                *(exportTable[i]->functionPtr), " ",
                *(exportTable[i]->functionNameAddr), " ",
                exportTable[i]->functionName,
                exportTable[i]->forwarderName);
        }

        return;
}

void findExportFunctions(char *fbuf)
{
        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)fbuf;
        IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((size_t)dosHeader + dosHeader->e_lfanew);

        PIMAGE_OPTIONAL_HEADER optHeader = &ntHeaders->OptionalHeader;
        IMAGE_DATA_DIRECTORY exportDescriptor = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)optHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
        WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

        int i;
        DWORD VirtualAddr, VirtualSize;
        for (i = 0; i < numberOfSections; i++) {
                VirtualAddr = sectionHeader->VirtualAddress;
                VirtualSize = sectionHeader->Misc.VirtualSize;

                if (VirtualAddr <= exportDescriptor.VirtualAddress &&
                    exportDescriptor.VirtualAddress < VirtualAddr + VirtualSize) {
                        break;
                }
                sectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)sectionHeader) + sizeof(IMAGE_SECTION_HEADER));
        }

        DWORD exportFileOffset = RVA2FileOffset(exportDescriptor.VirtualAddress, sectionHeader);
        IMAGE_EXPORT_DIRECTORY *exportDirectory = (IMAGE_EXPORT_DIRECTORY *)((size_t)dosHeader + exportFileOffset);
        DWORD *AddressOfFunctions = (DWORD *)((size_t)dosHeader + RVA2FileOffset(exportDirectory->AddressOfFunctions, sectionHeader));
        // WORD *AddressOfOrdinals = (WORD *)((size_t)dosHeader + RVA2FileOffset(exportDirectory->AddressOfNameOrdinals, sectionHeader) + exportDirectory->Base * sizeof(WORD));
        WORD *AddressOfOrdinals = (WORD *)((size_t)dosHeader + RVA2FileOffset(exportDirectory->AddressOfNameOrdinals, sectionHeader));
        DWORD *AddressOfNames = (DWORD *)((size_t)dosHeader + RVA2FileOffset(exportDirectory->AddressOfNames, sectionHeader));
        
        printf("%s\n\n", ((size_t)dosHeader + exportDirectory->Name - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData));

        printf("Virtual Address : %x\n", exportDescriptor.VirtualAddress);
        printf("File Offset : %x\n", exportFileOffset);

        printf("\nExported Functions: %d\n\n", exportDirectory->NumberOfFunctions);

        struct _exportTable **exportTable = malloc(sizeof(struct _exportTable *) * exportDirectory->NumberOfFunctions);
        for (i = 0; i < exportDirectory->NumberOfFunctions; i++) exportTable[i] = malloc(sizeof(struct _exportTable));

        for (i = 0; i < exportDirectory->NumberOfFunctions; i++) {
                char *functionName, *forwarderName;

                functionName = (char *)((size_t)dosHeader + RVA2FileOffset(*(AddressOfNames + i), sectionHeader));

                exportTable[i]->offset = RVA2FileOffset(exportDirectory->AddressOfFunctions + i * 4, sectionHeader);
                exportTable[i]->functionPtr = (AddressOfFunctions + i);

                WORD _ordinal = *(AddressOfOrdinals + i) + exportDirectory->Base;
                exportTable[_ordinal - 1]->ordinal = _ordinal;
                exportTable[_ordinal - 1]->functionNameAddr = (AddressOfNames + i);
                exportTable[_ordinal - 1]->functionName = functionName;
        }

        for (i = 0; i < exportDirectory->NumberOfFunctions - 1; i++) {
                int addrDiff;
                addrDiff = *(exportTable[i + 1]->functionNameAddr) - *(exportTable[i]->functionNameAddr);
                if (addrDiff != strlen(exportTable[i]->functionName) + 1) {
                        exportTable[i]->forwarderName = exportTable[i]->functionName + strlen(exportTable[i]->functionName) + 1;
                } else {
                        exportTable[i]->forwarderName = "";
                }
        }
        if (*(exportTable[i]->functionNameAddr) + strlen(exportTable[i]->functionName) + 1 != exportDescriptor.VirtualAddress + exportDescriptor.Size) {
                exportTable[i]->forwarderName = exportTable[i]->functionName + strlen(exportTable[i]->functionName) + 1;
        } else {
                exportTable[i]->forwarderName = "";
        }

        printExportTable(exportTable, exportDirectory->NumberOfFunctions);

        return;
}

BOOL readFile(char *fname, char **fbuf, size_t *len)
{
        FILE *fd = fopen(fname, "rb");
        if (fd) {
                fseek(fd, 0, SEEK_END);
                *len = ftell(fd);
                fseek(fd, 0, SEEK_SET);
                *fbuf = malloc(*len + 1);
                fread(*fbuf, *len, 1, fd);
                return 1;
        }
        return 0;
}

int main(int argc, char **argv)
{
        if (argc != 2) {
                printf("Usage: %s <PE file>\n", argv[0]);
        }

        char *fbuf; size_t len;
        if (readFile(argv[1], &fbuf, &len)) {
                findExportFunctions(fbuf);
        } else {
                printf("Failed to read file: %s\n", argv[1]);
        }

        return 0;
}