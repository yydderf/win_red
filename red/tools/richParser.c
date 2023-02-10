#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void printHex(char *output)
{
        unsigned char *ptr;
        unsigned char ldword[4], udword[4];
        char uformatted[16], lformatted[16];

        for (int i = 0; i < 4; i++) {
                ptr = output + i;
                ldword[4-i-1] = *ptr;
                udword[4-i-1] = *(ptr + 4);
        }

        for (int i = 0; i < 4; i++) {
                sprintf(lformatted + i * 2, "%02x", ldword[i]);
                sprintf(uformatted + i * 2, "%02x", udword[i]);
        }

        printf("%s  %s - ", lformatted, uformatted);

        if (strcmp(lformatted, "536e6144") == 0) {
                printf("%-8s", "DanS");
        } else {
                printf("%d.%d.%d",
                ldword[2] * 256 + ldword[3],
                ldword[0] * 256 + ldword[1],
                udword[2] * 256 + udword[3]);
        }

        printf("\n");

        return;
}

void richParser(char *fbuf)
{
        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)fbuf;
        IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((size_t)dosHeader + dosHeader->e_lfanew);
        if (dosHeader->e_lfanew == 0x80) {
                printf("Rich Header does not exist\n");
                return;
        }

        // find "Rich"
        size_t richLen = dosHeader->e_lfanew - 0x80;
        size_t richOffset;
        char richbuf[richLen + 1];
        char *output = calloc(16, 0);
        char key[4];
        char *tok;
        char tmp;

        memcpy(richbuf, fbuf + 0x80, richLen);
        tok = strstr(richbuf, "Rich");
        richOffset = tok - richbuf;
        if (tok == NULL) {
                printf("Broken binary\n");
                return;
        }
        memcpy(key, tok + 4, 4);

        for (int i = 0; i < richOffset; i++) {
                output[i % 8] = richbuf[i] ^ key[i % 4];
                // if (i % 4 == 3) printf("%s ", output);
                if (i % 8 == 7) printHex(output);
        }

        free(output);
        free(fbuf);

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
        printf("Failed to read file: %s\n", fname);
        return 0;
}

int main(int argc, char **argv)
{
        if (argc != 2) {
                printf("Usage: %s <PE Binary>\n", argv[0]);
                return 0;
        }

        char *fbuf; size_t len;
        if (readFile(argv[1], &fbuf, &len)) {
                richParser(fbuf);
        } else {
                printf("Unable to parse exe\n");
        }

        return 0;
}