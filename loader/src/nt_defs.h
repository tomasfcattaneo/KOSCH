/* безликий
 *
 * Undocumented NT types for usermode. NTSTATUS and NTAPI aren't
 * reliably available in C mode without winternl.h, so we define them.
 */
#pragma once

#include <windows.h>
#include <stdint.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef LONG(__stdcall *PNtQuerySystemInformation)(ULONG SystemInformationClass,
                                                   PVOID SystemInformation,
                                                   ULONG SystemInformationLength,
                                                   PULONG ReturnLength);

typedef LONG(__stdcall *PRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable,
                                             BOOLEAN CurrentThread, PBOOLEAN WasEnabled);

#define SE_DEBUG_PRIVILEGE       20
#define SE_LOAD_DRIVER_PRIVILEGE 10
