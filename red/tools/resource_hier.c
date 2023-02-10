#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

DWORD RVA2FileOffset(DWORD RVA, PIMAGE_SECTION_HEADER sectionHeader)
{
        return RVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
}

PIMAGE_SECTION_HEADER locateResourceTable(char *fbuf, IMAGE_DATA_DIRECTORY **resourceDirectoryEntry)
{
        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)fbuf;
        IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((size_t)dosHeader + dosHeader->e_lfanew);

        int adjustmentFor32 = 0;
        if (ntHeaders->OptionalHeader.Magic == 0x10B) {
                adjustmentFor32 = -2;
        };
        PIMAGE_OPTIONAL_HEADER optHeader = &ntHeaders->OptionalHeader;
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)optHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
        WORD nSections = ntHeaders->FileHeader.NumberOfSections;

        int i;
        DWORD virtualAddr, virtualSize;
        *resourceDirectoryEntry = &(optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE + adjustmentFor32]);
        for (i = 0; i < nSections; i++) {
                virtualAddr = sectionHeader->VirtualAddress;
                virtualSize = sectionHeader->Misc.VirtualSize;
                if (virtualAddr <= (*resourceDirectoryEntry)->VirtualAddress &&
                    virtualAddr + virtualSize > (*resourceDirectoryEntry)->VirtualAddress) {
                        return sectionHeader;
                }
                sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeader + sizeof(IMAGE_SECTION_HEADER));
        }

        printf("Unable to find resource directory\n");
        return NULL;
}

void processResourceTable(char *fbuf, IMAGE_DATA_DIRECTORY *resourceDirectoryEntry, IMAGE_SECTION_HEADER *sectionHeader)
{
        DWORD resourceFileOffset = RVA2FileOffset(resourceDirectoryEntry->VirtualAddress, sectionHeader);
        IMAGE_RESOURCE_DIRECTORY *resourceDirectory = (IMAGE_RESOURCE_DIRECTORY *)((size_t)fbuf + resourceFileOffset);

        int nName = resourceDirectory->NumberOfNamedEntries;
        int nID   = resourceDirectory->NumberOfIdEntries;

        DWORD *resourceEntries = (DWORD *)(resourceDirectory + 1);
        int i;
        for (i = 0; i < nName + nID; i++) {
                printf("%x\n", *resourceEntries);
                *resourceEntries++;
        }

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
        if (readFile(argv[1], &fbuf, &len) == 0) {
                printf("Failed to read file: %s\n", argv[1]);
                exit(1);
        }

        IMAGE_DATA_DIRECTORY *resourceDirectoryEntry;
        PIMAGE_SECTION_HEADER sectionHeader = locateResourceTable(fbuf, &resourceDirectoryEntry);
        processResourceTable(fbuf, resourceDirectoryEntry, sectionHeader);

        return 0;
}