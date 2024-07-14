#ifndef PEB_H
#define PEB_H

#if defined(_WIN64) || defined(WIN64) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #define _WINDOWS
#elif defined(__linux__) || defined(__ANDROID__)
    #define _LINUX
#endif

#ifdef _WINDOWS
    #include <windows.h>
#elif defined(_LINUX)
    #include <unistd.h>
    #include <sys/syscall.h>
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

// Prevents functions from inlining forcefully
#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#else 
    #define NOINLINE __attribute__((noinline))
#endif

#ifdef _MSC_VER
    #ifdef defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
        #define NAKED __declspec (naked)
    #else // no naked on x64 w0mp w0mp (note that's the reason why it will crash)
        #define NAKED
    #endif
#else
    #define NAKED __attribute__((naked))
#endif

#ifndef TO_LOWERCASE
    #define TO_LOWERCASE(c1) (c1 <= (char)'Z' && c1 >= (char)'A' ? (c1 - (char)'A') + (char)'a' : c1)
#endif

// We can hash in compile-time to avoid using string comparing in the shellcode. That saves time & space
template <typename T, T value>
INLINE constexpr T ensure_constexpr() { return value; }
#define CONSTEXPR(x) ensure_constexpr<decltype(x), x>()

template <typename T>
INLINE constexpr int adler32(const T* data) {
    long kModulus = 65521, a = 1, b = 0;
    for (int i = 0; data[i] != 0; i++) {
        a = (a + data[i]) % kModulus;
        b = (b + a) % kModulus;
    }
    return (b << 16) | a;
}

#define HASH(x) CONSTEXPR(adler32(x))

// On windows we use PEB & TEB
#ifdef _WINDOWS 
    #include <windows.h>

    #ifndef __NTDLL_H__

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

    INLINE LPVOID get_module_handle(int hash) {
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

            WCHAR temp[64];
            for (volatile int i = 0; i < curr_module->BaseDllName.Length; i++)
                temp[i] = TO_LOWERCASE(curr_module->BaseDllName.Buffer[i]);

            if (adler32(temp) == hash)
                return curr_module->BaseAddress;

            curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
        }
        return NULL;
    }

    INLINE LPVOID get_proc_address(LPVOID module, int hash) {
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

#elif defined(_LINUX)

    #define SYSCALL(...) inline_syscall(__VA_ARGS__)

    INLINE long inline_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5) {
        long ret;
    #if defined(__x86_64__)
        __asm__ volatile (
            "mov %1, %%rax;"
            "mov %2, %%rdi;"
            "mov %3, %%rsi;"
            "mov %4, %%rdx;"
            "mov %5, %%r10;"
            "mov %6, %%r8;"
            "syscall;"
            "mov %%rax, %0;"
            : "=m" (ret)
            : "g" (syscall_number), "g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5)
            : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8"
            );
    #elif defined(__i386__)
        __asm__ volatile (
            "mov %1, %%eax;"
            "mov %2, %%ebx;"
            "mov %3, %%ecx;"
            "mov %4, %%edx;"
            "mov %5, %%esi;"
            "mov %6, %%edi;"
            "int $0x80;"
            "mov %%eax, %0;"
            : "=m" (ret)
            : "g" (syscall_number), "g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5)
            : "%eax", "%ebx", "%ecx", "%edx", "%esi", "%edi"
            );
    #elif defined(__arm__)
        __asm__ volatile (
            "mov r7, %1;"
            "mov r0, %2;"
            "mov r1, %3;"
            "mov r2, %4;"
            "mov r3, %5;"
            "mov r4, %6;"
            "swi 0;"
            "mov %0, r0;"
            : "=r" (ret)
            : "r" (syscall_number), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5)
            : "r0", "r1", "r2", "r3", "r4", "r7"
            );
    #elif defined(__aarch64__)
        __asm__ volatile (
            "mov x8, %1;"
            "mov x0, %2;"
            "mov x1, %3;"
            "mov x2, %4;"
            "mov x3, %5;"
            "mov x4, %6;"
            "svc 0;"
            "mov %0, x0;"
            : "=r" (ret)
            : "r" (syscall_number), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5)
            : "x0", "x1", "x2", "x3", "x4", "x8"
            );
    #else
    #error "Unsupported architecture"
    #endif
        return ret;
    }
#endif

#endif