/* безликий */
#pragma once

#include <ntifs.h>
#include <ntimage.h>

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Padding0;
    ULONGLONG Mutant;
    ULONGLONG ImageBaseAddress;
    ULONGLONG Ldr;
} PEB64, *PPEB64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    ULONGLONG DllBase;
    ULONGLONG EntryPoint;
    ULONG SizeOfImage;
    ULONG __pad;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;
