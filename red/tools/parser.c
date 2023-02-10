#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

void parser(char *ptr2bin)
{
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)ptr2bin;
    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((size_t)dosHeader + dosHeader->e_lfanew);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("binary is broken\n");
        return;
    }

    if (&ntHeaders->OptionalHeader) {
        IMAGE_OPTIONAL_HEADER *optHeader = &ntHeaders->OptionalHeader;
        printf("ImageBase: %p\n", optHeader->ImageBase);
        printf("Dynamic memory usage: %x bytes\n", optHeader->SizeOfImage);
        printf("Dynamic entrypoint: %p\n", optHeader->ImageBase + optHeader->AddressOfEntryPoint);
    }

    printf("Section info\n");
    IMAGE_SECTION_HEADER *secHeader = (IMAGE_SECTION_HEADER *)((size_t)ntHeaders + sizeof(*ntHeaders));
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        printf("\t#%.2x - %8s - %.8x - %.8x\n", i, secHeader[i].Name,
            secHeader[i].PointerToRawData, secHeader[i].SizeOfRawData);
    }
}

BOOL readBin(char *fname, char **buf, size_t *length)
{
    FILE *fd = fopen(fname, "rb");
    if (fd) {
        fseek(fd, 0, SEEK_END);
        *length = ftell(fd);
        fseek(fd, 0, SEEK_SET);
        *buf = malloc(*length + 1);
        fread(*buf, *length, 1, fd);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 0;
    }
    size_t length;
    char *fbuf;
    if (readBin(argv[1], &fbuf, &length)) {
        printf("Analyzing file\n");
        parser(fbuf);
    } else {
        printf("Failed to read file\n");
    }
    return 0;
}