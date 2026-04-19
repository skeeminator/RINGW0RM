#pragma once

typedef int BOOL;
typedef unsigned __int64 QWORD;
typedef unsigned long   DWORD;
typedef unsigned short  WORD;
typedef unsigned char   BYTE;

typedef long                LONG;
typedef unsigned long       ULONG;
typedef __int64             LONGLONG;
typedef unsigned __int64    ULONGLONG;

typedef unsigned char      UINT8, * PUINT8;
typedef unsigned short     USHORT, * PUSHORT;
typedef unsigned int       UINT, * PUINT;
typedef unsigned long      ULONG, * PULONG;
typedef unsigned short     UINT16, * PUINT16;
typedef unsigned int       UINT32, * PUINT32;
typedef unsigned __int64   UINT64, * PUINT64;

typedef char               CHAR, * PCHAR;
typedef short              SHORT, * PSHORT;
typedef int                INT, * PINT;
typedef long               LONG, * PLONG;
typedef __int64            INT64, * PINT64;

typedef void* PVOID;
typedef unsigned __int64 ULONG_PTR;

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE                 0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x454C      // LE
#define IMAGE_VXD_SIGNATURE                 0x454C      // LE
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#define IMAGE_FIRST_SECTION64( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)ntheader +                                                  \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS64)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)ntheader +                                                  \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS32)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_FIRST_SECTION(ntheader)       IMAGE_FIRST_SECTION64(ntheader)
#else
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_FIRST_SECTION(ntheader)       IMAGE_FIRST_SECTION32(ntheader)
#endif

#define IMAGE_DIRECTORY_ENTRY_EXPORT       0
#define IMAGE_DIRECTORY_ENTRY_IMPORT       1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE     2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION    3
#define IMAGE_DIRECTORY_ENTRY_SECURITY     4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC    5
#define IMAGE_DIRECTORY_ENTRY_DEBUG        6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR    8
#define IMAGE_DIRECTORY_ENTRY_TLS          9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT          12

typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Type;
    DWORD SizeOfData;
    DWORD AddressOfRawData;
    DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN        0   // Unknown format
#define IMAGE_DEBUG_TYPE_COFF           1   // COFF debugging information (symbol table, line numbers)
#define IMAGE_DEBUG_TYPE_CODEVIEW       2   // CodeView PDB information (RSDS/NB10)
#define IMAGE_DEBUG_TYPE_FPO            3   // Frame Pointer Omission (FPO) info
#define IMAGE_DEBUG_TYPE_MISC           4   // Miscellaneous info (e.g., image name)
#define IMAGE_DEBUG_TYPE_EXCEPTION      5   // Exception info (function table)
#define IMAGE_DEBUG_TYPE_FIXUP          6   // Fixup info (obsolete)
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC    7   // OMAP converted from Microsoft source
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  8   // OMAP converted to Microsoft source
#define IMAGE_DEBUG_TYPE_BORLAND        9   // Borland debug information
#define IMAGE_DEBUG_TYPE_RESERVED10    10   // Reserved
#define IMAGE_DEBUG_TYPE_CLSID         11   // Class ID (GUID)
#define IMAGE_DEBUG_TYPE_REPRO         16   // Reproducible build info (MISC-like)

#define WINLOAD_PATH_SIGNATURE         0x5F64616F6C6E6977

__declspec(align(1))
typedef struct _RSDS_DEBUG_FORMAT {
    DWORD Signature;
    GUID Guid;
    DWORD Age;
    UINT64 Path;
} RSDS_DEBUG_FORMAT, * PRSDS_DEBUG_FORMAT;

#define PE_PDB_RSDS_SIGNATURE 0x53445352 // SDSR
