#ifndef PEB_H
#define PEB_H

#if defined(_WIN64) || defined(WIN64) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define _WINDOWS
#elif defined(__linux__) || defined(__ANDROID__)
#define _LINUX
#endif

// Create custom sections on both clang & msc++
#if defined(_MSC_VER)
    #define SECTION_CODE(x) __declspec(code_seg(x))
    #define SECTION_FLD(x) __declspec(allocate(x))
#else
    #define SECTION_CODE(x) __attribute__((section(x)))
    #define SECTION_FLD(x) __attribute__((section(x)))
#endif

#if defined(_MSC_VER) && !defined(__llvm__)
    #define INLINE __forceinline // Visual C++
#else
    #define INLINE __attribute__((always_inline)) inline // GCC/G++/CLANG
#endif

#ifdef _MSC_VER
    #ifdef defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
        #define NAKED __declspec (naked)
    #else // no naked on x64 w0mp w0mp
        #define NAKED
    #endif
#else
    #define NAKED __attribute__((naked))
#endif

// Prevents functions from inlining forcefully
#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#else 
    #define NOINLINE __attribute__((noinline))
#endif

// On windows we use PEB & TEB, on linux we'll use inline syscalls for shellcoding
#ifdef _WINDOWS 

#include <windows.h>

#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ...

} PEB, * PPEB;

#endif //__NTDLL_H__

template <typename T, T value>
INLINE constexpr T ensure_constexpr() { return value; }
#define CONSTEXPR(x) ensure_constexpr<decltype(x), x>()

INLINE constexpr int adler32(const char* data) {
    long kModulus = 65521, a = 1, b = 0;
    for (int i = 0; data[i] != 0; i++) {
        a = (a + data[i]) % kModulus;
        b = (b + a) % kModulus;
    }
    return (b << 16) | a;
}

#define HASH(x) CONSTEXPR(adler32(x))

INLINE LPVOID get_proc_address(WCHAR* module_name) {
    PPEB peb = NULL;
    #if defined(_WIN64)
        peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    #else
        peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
    #endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0)
            return curr_module->BaseAddress;
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

INLINE LPVOID get_module_handle(LPVOID module, int hash) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(exportsDir->VirtualAddress + (ULONG_PTR)module);

    // Iterate through names
    for (SIZE_T i = 0; i < exp->NumberOfNames; i++) {
        DWORD* nameRVA = (DWORD*)((exp->AddressOfNames + (BYTE*)module) + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)((exp->AddressOfNameOrdinals + (BYTE*)module) + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)((exp->AddressOfFunctions + (BYTE*)module) + (*nameIndex) * sizeof(DWORD));
        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);

        if (adler32(curr_name) == hash) return (BYTE*)module + (*funcRVA);
    }
    return NULL;
}

/* 
int dump_pe_section(char* file, char* section, char* output) {
    FILE* inputFile = fopen(file, "rb");
    if (inputFile == NULL) {
        printf("Unable to open input file.\n");
        return 1;
    }

    FILE* outputFile = fopen(output, "wb");
    if (outputFile == NULL) {
        printf("Unable to open output file.\n");
        fclose(inputFile);
        return 2;
    }

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, inputFile);

    fseek(inputFile, dosHeader.e_lfanew, SEEK_SET);

    IMAGE_NT_HEADERS ntHeader;
    fread(&ntHeader, sizeof(IMAGE_NT_HEADERS), 1, inputFile);

    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) {
        fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, inputFile);
        if (strncmp((char*)sectionHeader.Name, section, 8) == 0) {
            char* buffer = (char*)malloc(sectionHeader.SizeOfRawData);
            fseek(inputFile, sectionHeader.PointerToRawData, SEEK_SET);
            fread(buffer, sectionHeader.SizeOfRawData, 1, inputFile);
            fwrite(buffer, sectionHeader.SizeOfRawData, 1, outputFile);
            free(buffer);
            fclose(outputFile);
            fclose(inputFile);
            return 0;
        }
    }
    fclose(outputFile);
    fclose(inputFile);
    return 3;
}*/

#endif

#endif