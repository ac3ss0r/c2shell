#include <stdio.h>
#include "shcutils.h"

#ifdef _MSC_VER
    #pragma warning(disable:4996)
    #pragma section("shcode", execute)
#endif

// This method should be fully inline. No use of static fields & external methods is allowed since the shellcode
// Is supposed to be fully inline & offset independent (use PEB for windows & syscalls for linux)
SECTION_CODE("shcode") NOINLINE int _fastcall shellcode() {
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
    
  
    void* base = get_proc_address((wchar_t*)&k32);
    if (base) {
        LoadLibraryA_t LoadLibA = (LoadLibraryA_t) get_module_handle(base, HASH("LoadLibraryA"));
        if (LoadLibA) {
            void* handle = LoadLibA((char*)u32);
            if (handle) {
                MessageBoxA_t MsgBoxA = (MessageBoxA_t) get_module_handle(handle, HASH("MessageBoxA"));
                MsgBoxA(0, (char*)msg, (char*)msg, MB_OK);
                return 0;
            }
        }
    }
    return 1;
}
// Next function goes directly after the shellcode, this allows to figure out shellcode size & dump it
SECTION_CODE("shcode") NAKED void shellcode_end(void) {}

typedef int (*shellcode_t)();

int main() {
    // We attempt to dump the shellcode directly from memory by substracting pointers
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

    // Load it up and execute to test if it works
    FILE* file = fopen("shellcode.bin", "rb");
    if (!file) {
        fprintf(stderr, "[e] Failed to open shellcode.bin\n");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* shellcode_buff = (char*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!shellcode_buff) {
        fprintf(stderr, "[e] Failed to allocate memory for shellcode\n");
        fclose(file);
        return 1;
    }
    if (fread(shellcode_buff, 1, fileSize, file) != fileSize) {
        fprintf(stderr, "[e] Failed to read shellcode\n");
        VirtualFree(shellcode_buff, 0, MEM_RELEASE);
        fclose(file);
        return 1;
    }
    fclose(file);
    printf("[i] Loaded shellcode size: %ld\n", fileSize);
    DWORD flOldProtect;
    if (!VirtualProtect(shellcode_buff, fileSize, PAGE_EXECUTE_READWRITE, &flOldProtect)) {
        fprintf(stderr, "[e] Failed to change memory protection\n");
        VirtualFree(shellcode_buff, 0, MEM_RELEASE);
        return 1;
    }
    shellcode_t code = (shellcode_t) shellcode_buff;
    printf("Result: %d\n", code());
    VirtualFree(shellcode_buff, 0, MEM_RELEASE);
    printf("Shellcode execution completed successfully.\n");
    return 0;
}