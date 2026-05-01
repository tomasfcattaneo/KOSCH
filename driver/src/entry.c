/* безликий */
#include "globals.h"
#include "dispatch.h"
#include "dkom.h"
#include "memory.h"
#include "sysinfo.h"
#include "offsets.h"
#include "stealth.h"
#include <ntimage.h>

#define MZ_SCAN_MAX_PAGES 256

static volatile LONG g_BridgeCleared = 0;

NTSTATUS Dx_Entry(UINT64 cmd_buf_va)
{
    if (InterlockedCompareExchange(&g_BridgeCleared, 1, 0) == 0) {
        g_CommsBootstrap.sentinel1   = 0;
        g_CommsBootstrap.sentinel2   = 0;
        g_CommsBootstrap.dispatch_va = 0;
    }

    DX_HDR *hdr = (DX_HDR *)(ULONG_PTR)cmd_buf_va;
    if (hdr->magic != NX_MAGIC) return STATUS_ACCESS_DENIED;
    if (hdr->size > DX_BUF_SIZE || hdr->size < sizeof(DX_HDR))
        return STATUS_INVALID_PARAMETER;
    return Dx_Route((PVOID)(ULONG_PTR)cmd_buf_va, hdr->size);
}

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = Sx_Init();
    if (!NT_SUCCESS(status)) return status;

    status = Sx_ResolveOffsets();
    if (!NT_SUCCESS(status)) return status;

    Ox_Init();

    status = Vx_Init();
    if (!NT_SUCCESS(status)) return status;

    g_ImageBase = (PVOID)((ULONG_PTR)&g_CommsBootstrap & ~0xFFFULL);
    for (ULONG i = 0; i < MZ_SCAN_MAX_PAGES; i++) {
        if (g_ImageBase <= (PVOID)0x10000) break;
        if (*(USHORT *)g_ImageBase == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS64 nt =
                (PIMAGE_NT_HEADERS64)((UCHAR *)g_ImageBase +
                                      ((PIMAGE_DOS_HEADER)g_ImageBase)->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
                g_ImageSize = nt->OptionalHeader.SizeOfImage;
            break;
        }
        g_ImageBase = (PVOID)((ULONG_PTR)g_ImageBase - PAGE_SIZE);
    }

    g_CommsBootstrap.dispatch_va = (UINT64)(ULONG_PTR)Dx_Entry;

    Ex_ZeroHeaders();
    InterlockedExchange(&g_Initialized, 1);
    return STATUS_SUCCESS;
}
