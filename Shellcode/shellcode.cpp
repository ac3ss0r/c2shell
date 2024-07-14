#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
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
        volatile char u32[30]; volatile int i = 0;
        u32[i++] = 'u';  u32[i++] = 's';  u32[i++] = 'e';  u32[i++] = 'r';  u32[i++] = '3';  u32[i++] = '2'; 
        u32[i++] = '.';  u32[i++] = 'd';  u32[i++] = 'l';  u32[i++] = 'l', u32[i++] = '\0';
        volatile char msg[30]; i = 0;
        msg[i++] = 't'; msg[i++] = 'e'; msg[i++] = 's'; msg[i++] = 't', msg[i++] = '\0';

        /* Note that any definitions should remain stack only. Otherwise the shellcode will be invalid
       
        // This gets stored to .data section 100%
        char s1[] = "test";

        // This gets stored to .data section 50/50 on different compilers
        char s2[] = {'t', 'e', 's', 't', 0};

        // This is stored to stack in 100% cases. Allows to trick the compiler
        char s3[32]; int i = 0;
        s3[i++] = 't', s3[i++] = 'e', s3[i++] = 's', s3[i++] = 't',s3[i++] = '\0';

        */
        
        void* base = get_module_handle(HASH("kernel32.dll"));

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