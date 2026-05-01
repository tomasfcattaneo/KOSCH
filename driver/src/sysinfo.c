/* безликий */
#include "sysinfo.h"
#include "globals.h"
#include <ntimage.h>

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION_K
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
} RTL_PROCESS_MODULE_INFORMATION_K;

typedef struct _RTL_PROCESS_MODULES_K
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_K Modules[1];
} RTL_PROCESS_MODULES_K;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass,
                                                 PVOID SystemInformation,
                                                 ULONG SystemInformationLength,
                                                 PULONG ReturnLength);

NTSTATUS Sx_Init(void)
{
    ULONG len       = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH || len == 0) return STATUS_UNSUCCESSFUL;

    RTL_PROCESS_MODULES_K *mods = (RTL_PROCESS_MODULES_K *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, len, POOL_TAG_COMMS);
    if (!mods) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemModuleInformation, mods, len, &len);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(mods, POOL_TAG_COMMS);
        return status;
    }

    if (mods->NumberOfModules > 0) {
        g_NtosBase = mods->Modules[0].ImageBase;
    }

    ExFreePoolWithTag(mods, POOL_TAG_COMMS);

    if (!g_NtosBase) return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}

PEPROCESS Sx_FindProcess(HANDLE pid)
{
    PEPROCESS proc = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc))) return proc;
    return NULL;
}

static UINT32 fnv1a_k(const char *s)
{
    UINT32 h = 0x811C9DC5u;
    while (*s) {
        h ^= (UCHAR)*s++;
        h *= 0x01000193u;
    }
    return h;
}

PVOID Sx_FindKernelExport(UINT32 name_hash)
{
    UCHAR *base = (UCHAR *)g_NtosBase;
    if (!base) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0 || exp_dir->Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)(base + exp_dir->VirtualAddress);
    ULONG *names    = (ULONG *)(base + exports->AddressOfNames);
    USHORT *ordinals = (USHORT *)(base + exports->AddressOfNameOrdinals);
    ULONG *funcs    = (ULONG *)(base + exports->AddressOfFunctions);

    for (ULONG i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (fnv1a_k(name) == name_hash)
            return base + funcs[ordinals[i]];
    }
    return NULL;
}
