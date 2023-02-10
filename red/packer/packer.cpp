#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

#define BOOL_STR(b) b ? "true" : "false"
#define CONSOLE_COLOR_DEFAULT   SetConsoleTextAttribute(hConsole, 0x09);
#define CONSOLE_COLOR_ERROR     SetConsoleTextAttribute(hConsole, 0x0C);

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

int inputFileValidation(char *);
int createDOSHeader(IMAGE_DOS_HEADER **dosHeader);
int createNTHeaders(IMAGE_NT_HEADERS **ntHeaders);
int createCodeSection(IMAGE_SECTION_HEADER **codeSec);
int createDataSection(IMAGE_SECTION_HEADER **dataSec);
int createPEFile(char *);

int main(int argc, char **argv)
{
        SetConsoleTitle("PE Packer");
        FlushConsoleInputBuffer(hConsole);
        CONSOLE_COLOR_DEFAULT;

        if (argc != 3) return EXIT_FAILURE;

        char *inputFile = argv[1];
        char *outputFile= argv[2];

        if (inputFileValidation(inputFile)) return EXIT_FAILURE;

        createPEFile(outputFile);


        return EXIT_SUCCESS;
}

int inputFileValidation(char *filename)
{
        std::ifstream inputFileReader(filename, std::ios::binary);
        std::vector<uint8_t> inputFileBuffer(std::istreambuf_iterator<char>(inputFileReader), {});

        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)inputFileBuffer.data();
        IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)(inputFileBuffer.data() + dosHeader->e_lfanew);

        bool isPE  = dosHeader->e_magic == IMAGE_DOS_SIGNATURE;
        bool is64  = ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
                     ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        bool isDLL = ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL;
        bool isNET = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0;

        printf("[+] is PE     : %s\n", BOOL_STR(isPE));
        printf("[+] is 64-bit : %s\n", BOOL_STR(is64));
        printf("[+] is DLL    : %s\n", BOOL_STR(isDLL));
        printf("[+] is .NET   : %s\n", BOOL_STR(isNET));

        if (!isPE) {
                CONSOLE_COLOR_ERROR;
                printf("[-] Invalid input file (signature mismatched)\n");
                return 1;
        }
        if (!is64) {
                CONSOLE_COLOR_ERROR;
                printf("[-] The packer only supports x64 PE files\n");
                return 1;
        }
        if (isNET) {
                CONSOLE_COLOR_ERROR;
                printf("[-] The packer does not support .NET\n");
                return 1;
        }

        return 0;
}

int createPEFile(char *filename)
{
        std::ofstream outputFileWriter;
        outputFileWriter.open(filename, std::ios::binary | std::ios::out);

        IMAGE_DOS_HEADER *dosHeader;
        IMAGE_NT_HEADERS *ntHeaders;
        IMAGE_SECTION_HEADER *codeSec;
        IMAGE_SECTION_HEADER *dataSec;

        createDOSHeader(&dosHeader);
        createNTHeaders(&ntHeaders);
        createCodeSection(&codeSec);
        createDataSection(&dataSec);

        outputFileWriter.write((char *)dosHeader, sizeof(*dosHeader));
        outputFileWriter.write((char *)ntHeaders, sizeof(*ntHeaders));
        outputFileWriter.write((char *)codeSec, sizeof(*codeSec));
        outputFileWriter.write((char *)dataSec, sizeof(*dataSec));

        while (outputFileWriter.tellp() != codeSec->PointerToRawData) outputFileWriter.put(0x0);

        outputFileWriter.put(0xC3);
        for (size_t i = 0; i < codeSec->SizeOfRawData - 1; i++) outputFileWriter.put(0x0);
        for (size_t i = 0; i < dataSec->SizeOfRawData; i++) outputFileWriter.put(0x0);

        outputFileWriter.close();

        return 0;
}

int createDOSHeader(IMAGE_DOS_HEADER **dosHeader)
{
        *dosHeader = new IMAGE_DOS_HEADER;
        std::memset(*dosHeader, 0, sizeof(dosHeader));

        (*dosHeader)->e_magic      = IMAGE_DOS_SIGNATURE;
        (*dosHeader)->e_cblp       = 0x0090;
        (*dosHeader)->e_cp         = 0x0003;
        (*dosHeader)->e_cparhdr    = 0x0004;
        (*dosHeader)->e_crlc       = 0x0000;
        (*dosHeader)->e_minalloc   = 0x0000;
        (*dosHeader)->e_maxalloc   = 0xFFFF;
        (*dosHeader)->e_ss         = 0x0000;
        (*dosHeader)->e_sp         = 0x00B8;
        (*dosHeader)->e_csum       = 0x0000;
        (*dosHeader)->e_ip         = 0x0000;
        (*dosHeader)->e_cs         = 0x0000;
        (*dosHeader)->e_lfarlc     = 0x0040;
        (*dosHeader)->e_ovno       = 0x0000;
        (*dosHeader)->e_oemid      = 0x0000;
        (*dosHeader)->e_oeminfo    = 0x0000;
        (*dosHeader)->e_lfanew     = 0x0040;

        return 0;
}

int createNTHeaders(IMAGE_NT_HEADERS **ntHeaders)
{
        *ntHeaders = new IMAGE_NT_HEADERS;
        auto _ntHeaders = (*ntHeaders);
        std::memset(_ntHeaders, 0, sizeof(IMAGE_NT_HEADERS));

        _ntHeaders->Signature                                   = IMAGE_NT_SIGNATURE;

        _ntHeaders->FileHeader.Machine                          = IMAGE_FILE_MACHINE_AMD64;
        _ntHeaders->FileHeader.NumberOfSections                 = 2;
        _ntHeaders->FileHeader.TimeDateStamp                    = 0x00000000; // update
        _ntHeaders->FileHeader.PointerToSymbolTable             = 0x0;
        _ntHeaders->FileHeader.NumberOfSymbols                  = 0x0;
        _ntHeaders->FileHeader.SizeOfOptionalHeader             = 0x00F0;
        _ntHeaders->FileHeader.Characteristics                  = 0x0022;     // update

        _ntHeaders->OptionalHeader.Magic                        = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        _ntHeaders->OptionalHeader.MajorLinkerVersion           = 10;
        _ntHeaders->OptionalHeader.MinorImageVersion            = 0x05;
        _ntHeaders->OptionalHeader.SizeOfCode                   = 0x00000200; // update
        _ntHeaders->OptionalHeader.SizeOfInitializedData        = 0x00000200; // update
        _ntHeaders->OptionalHeader.AddressOfEntryPoint          = 0x00001000; // update
        _ntHeaders->OptionalHeader.BaseOfCode                   = 0x00001000;
        _ntHeaders->OptionalHeader.ImageBase                    = 0x00000001400000000;
        _ntHeaders->OptionalHeader.SectionAlignment             = 0x00001000;
        _ntHeaders->OptionalHeader.FileAlignment                = 0x00000200;
        _ntHeaders->OptionalHeader.MajorOperatingSystemVersion  = 0x0;
        _ntHeaders->OptionalHeader.MinorOperatingSystemVersion  = 0x0;
        _ntHeaders->OptionalHeader.MajorImageVersion            = 0x0000;
        _ntHeaders->OptionalHeader.MinorImageVersion            = 0x0000;
        _ntHeaders->OptionalHeader.MajorSubsystemVersion        = 0x0006;
        _ntHeaders->OptionalHeader.MinorSubsystemVersion        = 0x0000;
        _ntHeaders->OptionalHeader.Win32VersionValue            = 0x0;
        _ntHeaders->OptionalHeader.SizeOfImage                  = 0x00003000; // update
        _ntHeaders->OptionalHeader.SizeOfHeaders                = 0x00000200;
        _ntHeaders->OptionalHeader.CheckSum                     = 0xFFFFFFFF; // update
        _ntHeaders->OptionalHeader.Subsystem                    = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        _ntHeaders->OptionalHeader.DllCharacteristics           = 0x0120;
        _ntHeaders->OptionalHeader.SizeOfStackReserve           = 0x0000000000100000;
        _ntHeaders->OptionalHeader.SizeOfStackCommit            = 0x0000000000001000;
        _ntHeaders->OptionalHeader.SizeOfHeapReserve            = 0x0000000000100000;
        _ntHeaders->OptionalHeader.SizeOfHeapCommit             = 0x0000000000001000;
        _ntHeaders->OptionalHeader.LoaderFlags                  = 0x00000000;
        _ntHeaders->OptionalHeader.NumberOfRvaAndSizes          = 0x00000010;

        return 0;
}

int createCodeSection(IMAGE_SECTION_HEADER **codeSec)
{
        *codeSec = new IMAGE_SECTION_HEADER;
        auto _codeSec = (*codeSec);
        std::memset(_codeSec, 0, sizeof(IMAGE_SECTION_HEADER));

        _codeSec->Name[0] = '['; _codeSec->Name[1] = '.';
        _codeSec->Name[2] = 't'; _codeSec->Name[3] = 'e';
        _codeSec->Name[4] = 'x'; _codeSec->Name[5] = 't';
        _codeSec->Name[6] = ']'; _codeSec->Name[7] = 0;
        _codeSec->Misc.VirtualSize      = 0x00001000;
        _codeSec->VirtualAddress        = 0x00001000;
        _codeSec->SizeOfRawData         = 0x00000600;
        _codeSec->PointerToRawData      = 0x00000200;
        _codeSec->PointerToRelocations  = 0x00000000;
        _codeSec->PointerToLinenumbers  = 0x00000000;
        _codeSec->NumberOfRelocations   = 0x00000000;
        _codeSec->NumberOfRelocations   = 0x00000000;
        _codeSec->Characteristics       = IMAGE_SCN_MEM_EXECUTE |
                                          IMAGE_SCN_MEM_READ    |
                                          IMAGE_SCN_CNT_CODE;
        return 0;
}

int createDataSection(IMAGE_SECTION_HEADER **dataSec)
{
        *dataSec = new IMAGE_SECTION_HEADER;
        auto _dataSec = (*dataSec);
        std::memset(_dataSec, 0, sizeof(IMAGE_SECTION_HEADER));

        _dataSec->Name[0] = '['; _dataSec->Name[1] = '.';
        _dataSec->Name[2] = 'd'; _dataSec->Name[3] = 'a';
        _dataSec->Name[4] = 't'; _dataSec->Name[5] = 'a';
        _dataSec->Name[6] = ']'; _dataSec->Name[7] = 0;
        _dataSec->Misc.VirtualSize      = 0x00000200;
        _dataSec->VirtualAddress        = 0x00002000;
        _dataSec->SizeOfRawData         = 0x00000200;
        _dataSec->PointerToRawData      = 0x00000800;
        _dataSec->PointerToRelocations  = 0x00000000;
        _dataSec->PointerToLinenumbers  = 0x00000000;
        _dataSec->NumberOfRelocations   = 0x00000000;
        _dataSec->NumberOfRelocations   = 0x00000000;
        _dataSec->Characteristics       = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

        return 0;
}