#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

DWORD RVA2FileOffset(DWORD RVA, PIMAGE_SECTION_HEADER sectionHeader)
{
        return RVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
}

void processImportedLib(char *fbuf, IMAGE_IMPORT_DESCRIPTOR *importDescriptor, PIMAGE_SECTION_HEADER sectionHeader)
{
        printf("%s\n", (size_t)fbuf + RVA2FileOffset(importDescriptor->Name, sectionHeader));
        DWORD *entry= (DWORD *)((size_t)fbuf + RVA2FileOffset(importDescriptor->FirstThunk, sectionHeader));
        while (*entry) {
                IMAGE_IMPORT_BY_NAME *target = (IMAGE_IMPORT_BY_NAME *)((size_t)fbuf + RVA2FileOffset(*entry, sectionHeader));
                printf("\t%04x %s\n", target->Hint, target->Name);
                entry += 2;
        }
        printf("\n");
}

PIMAGE_SECTION_HEADER locateSection(char *fbuf, IMAGE_DATA_DIRECTORY **directoryEntry, int targetDirectory)
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
        *directoryEntry = &(optHeader->DataDirectory[targetDirectory + adjustmentFor32]);
        for (i = 0; i < nSections; i++) {
                virtualAddr = sectionHeader->VirtualAddress;
                virtualSize = sectionHeader->Misc.VirtualSize;
                if (virtualAddr <= (*directoryEntry)->VirtualAddress &&
                    virtualAddr + virtualSize > (*directoryEntry)->VirtualAddress) {
                        return sectionHeader;
                }
                sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeader + sizeof(IMAGE_SECTION_HEADER));
        }

        printf("Unable to find resource directory\n");
        return NULL;
}

void processTargetDirectory(char *fbuf, IMAGE_DATA_DIRECTORY *directoryEntry, IMAGE_SECTION_HEADER *sectionHeader)
{
        DWORD directoryFileOffset = RVA2FileOffset(directoryEntry->VirtualAddress, sectionHeader);
        IMAGE_IMPORT_DESCRIPTOR *importDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((size_t)fbuf + directoryFileOffset);
        while (importDescriptor->FirstThunk) {
                processImportedLib(fbuf, importDescriptor, sectionHeader);
                importDescriptor++;
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

        IMAGE_DATA_DIRECTORY *importDirectoryEntry;
        PIMAGE_SECTION_HEADER sectionHeader = locateSection(fbuf, &importDirectoryEntry, IMAGE_DIRECTORY_ENTRY_IMPORT);
        processTargetDirectory(fbuf, importDirectoryEntry, sectionHeader);

        return 0;
}