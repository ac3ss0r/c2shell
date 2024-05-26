#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
#endif
#include "shcutils.h"

#ifdef _MSC_VER
    #pragma warning(disable:4996)
    #pragma section("shcode", execute)
#endif

// This method should be fully inline. No use of static fields & external methods is allowed since the shellcode
// Is supposed to be fully inline & offset independent (use PEB for windows & syscalls for linux)
SECTION_CODE("shcode") NOINLINE int /*_fastcall*/ shellcode() {
    #ifdef _WINDOWS
        // Typedefs for all the required methods
        typedef void* (*LoadLibraryA_t)(char*);
        typedef void* (*MessageBoxA_t)(int, char*, char*, int);

        // Some compilers insert the strings into the .data no matter what you do. So we need to trick em
        volatile wchar_t k32[30]; volatile int i = 0;
        k32[i++] = 'k'; k32[i++] = 'e'; k32[i++] = 'r'; k32[i++] = 'n'; k32[i++] = 'e'; k32[i++] = 'l'; k32[i++] = '3'; k32[i++] = '2'; k32[i++] = '.';
        k32[i++] = 'd'; k32[i++] = 'l'; k32[i++] = 'l'; k32[i++] = '\0'; 
        volatile char u32[30]; i = 0;
        u32[i++] = 'u';  u32[i++] = 's';  u32[i++] = 'e';  u32[i++] = 'r';  u32[i++] = '3';  u32[i++] = '2'; 
        u32[i++] = '.';  u32[i++] = 'd';  u32[i++] = 'l';  u32[i++] = 'l', u32[i++] = '\0';
        volatile char msg[30]; i = 0;
        msg[i++] = 't'; msg[i++] = 'e'; msg[i++] = 's'; msg[i++] = 't', msg[i++] = '\0';

        /*This DOESN'T work on clang/g++ sadly. Goes to data :broken_heart:
        volatile wchar_t k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
        volatile char u32[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
        volatile char msg[] = { 'R','e','a','l', 0};
        */
  
        void* base = get_module_handle((wchar_t*)&k32);
        if (base) {
            LoadLibraryA_t LoadLibA = (LoadLibraryA_t) get_proc_address(base, HASH("LoadLibraryA"));
            if (LoadLibA) {
                void* handle = LoadLibA((char*)u32);
                if (handle) {
                    MessageBoxA_t MsgBoxA = (MessageBoxA_t) get_proc_address(handle, HASH("MessageBoxA"));
                    MsgBoxA(0, (char*)msg, (char*)msg, MB_OK);
                    return 0;
                }
            }
        }
    #elif defined(_LINUX)
        volatile char msg[30]; volatile int i = 0;
        msg[i++] = 'H'; msg[i++] = 'e'; msg[i++] = 'l'; msg[i++] = 'l' , msg[i++] = 'o',  msg[i++] = ' ', 
        msg[i++] = 'f',  msg[i++] = 'r', msg[i++] = 'o', msg[i++] = 'm', msg[i++] = ' ', msg[i++] = 's',  msg[i++] = 'h', msg[i++] = 'e', msg[i++] = 'l', msg[i++] = 'l',
        msg[i++] = '!',  msg[i++] = '\n' , msg[i++] = '\0';
        inline_syscall(SYS_write, STDOUT_FILENO, (long)msg, i, 0, 0);
        return 0;
    #endif
    return 1;
}
// Next function goes directly after the shellcode, this allows to figure out shellcode size & dump it
SECTION_CODE("shcode") NAKED void shellcode_end(void) {}

typedef int (*shellcode_t)();

int main() {
    FILE* output_file = fopen("shellcode.bin", "wb");
    if (!output_file) {
        fprintf(stderr, "[e] Failed to open shellcode.bin\n");
        return 1;
    }
    size_t shellcode_size = (uintptr_t)shellcode_end - (uintptr_t)shellcode;
    printf("[i] Shellcode size: %lu, located at 0x%p\n", shellcode_size, shellcode);
    fwrite((char*)&shellcode, shellcode_size, 1, output_file);

    if (!fwrite((char*)&shellcode, shellcode_size, 1, output_file)) {
        fprintf(stderr, "[e] Failed to dump shellcode to disk. Check your compiler settings.\n");
        fclose(output_file);
        return 1;
    }
    fclose(output_file);
    printf("[i] Shellcode saved to file shellcode.bin.\n");

    FILE* file = fopen("shellcode.bin", "rb");
    if (!file) {
        fprintf(stderr, "[e] Failed to open shellcode.bin\n");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* shellcode_buff = (char*)malloc(fileSize);

    if (!shellcode_buff) {
        fprintf(stderr, "[e] Failed to allocate memory for shellcode\n");
        fclose(file);
        return 1;
    }
    if (fread(shellcode_buff, 1, fileSize, file) != fileSize) {
        fprintf(stderr, "[e] Failed to read shellcode\n");
    #ifdef _WIN32
            VirtualFree(shellcode_buff, 0, MEM_RELEASE);
    #else
            free(shellcode_buff);
    #endif
        fclose(file);
        return 1;
    }
    fclose(file);
    printf("[i] Loaded shellcode size: %ld\n", fileSize);

    #ifdef _WIN32
        DWORD flOldProtect;
        if (!VirtualProtect(shellcode_buff, fileSize, PAGE_EXECUTE_READWRITE, &flOldProtect)) {
            fprintf(stderr, "[e] Failed to change memory protection\n");
            VirtualFree(shellcode_buff, 0, MEM_RELEASE);
            return 1;
        }
    #else
        if (mprotect(shellcode_buff, fileSize, PROT_EXEC | PROT_READ | PROT_WRITE) == -1) {
            fprintf(stderr, "[e] Failed to change memory protection\n");
            free(shellcode_buff);
            return 1;
        }
    #endif

    shellcode_t code = (shellcode_t)shellcode_buff;
    printf("Result: %d\n", code());

    printf("Shellcode execution completed successfully.\n");
    return 0;
}