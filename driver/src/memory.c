/* безликий */
#include "memory.h"
#include "globals.h"
#include "sysinfo.h"

#define HK_MmCopyVirtualMemory 0x9232E176u

typedef NTSTATUS(NTAPI *PMmCopyVirtualMemory)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T,
                                              KPROCESSOR_MODE, PSIZE_T);

static PMmCopyVirtualMemory g_MmCopy = NULL;

NTSTATUS Vx_Init(void)
{
    g_MmCopy = (PMmCopyVirtualMemory)Sx_FindKernelExport(HK_MmCopyVirtualMemory);
    if (!g_MmCopy) return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}

NTSTATUS Vx_Attach(HANDLE pid, PEPROCESS *proc, KAPC_STATE *apc)
{
    PEPROCESS p = Sx_FindProcess(pid);
    if (!p) return STATUS_NOT_FOUND;
    KeStackAttachProcess(p, apc);
    *proc = p;
    return STATUS_SUCCESS;
}

void Vx_Detach(PEPROCESS proc, KAPC_STATE *apc)
{
    KeUnstackDetachProcess(apc);
    ObDereferenceObject(proc);
}

UINT64 Vx_GetCr3(PEPROCESS proc)
{
    return *(UINT64 *)((UCHAR *)proc + g_Offsets.eprocess_cr3);
}

NTSTATUS Vx_Read(HANDLE pid, UINT64 address, PVOID buffer, ULONG length)
{
    PEPROCESS target = Sx_FindProcess(pid);
    if (!target) return STATUS_NOT_FOUND;

    SIZE_T bytes    = 0;
    NTSTATUS status = g_MmCopy(target, (PVOID)(ULONG_PTR)address, PsGetCurrentProcess(),
                               buffer, (SIZE_T)length, KernelMode, &bytes);

    ObDereferenceObject(target);
    return (bytes == length) ? STATUS_SUCCESS : status;
}

NTSTATUS Vx_Write(HANDLE pid, UINT64 address, PVOID buffer, ULONG length)
{
    PEPROCESS target = Sx_FindProcess(pid);
    if (!target) return STATUS_NOT_FOUND;

    SIZE_T bytes    = 0;
    NTSTATUS status = g_MmCopy(PsGetCurrentProcess(), buffer, target,
                               (PVOID)(ULONG_PTR)address, (SIZE_T)length, KernelMode,
                               &bytes);

    ObDereferenceObject(target);
    return (bytes == length) ? STATUS_SUCCESS : status;
}

NTSTATUS Vx_Translate(HANDLE pid, UINT64 va, UINT64 *pa)
{
    PEPROCESS proc = Sx_FindProcess(pid);
    if (!proc) return STATUS_NOT_FOUND;

    UINT64 cr3 = Vx_GetCr3(proc);
    ObDereferenceObject(proc);

    if (!cr3) return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS phys_cr3;
    phys_cr3.QuadPart = (LONGLONG)(cr3 & ~0xFFFULL);

    PVOID pml4_map = MmMapIoSpace(phys_cr3, PAGE_SIZE, MmNonCached);
    if (!pml4_map) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 pml4_idx = (va >> 39) & 0x1FF;
    UINT64 pml4e    = ((UINT64 *)pml4_map)[pml4_idx];
    MmUnmapIoSpace(pml4_map, PAGE_SIZE);

    if (!(pml4e & 1)) return STATUS_NOT_FOUND;

    PHYSICAL_ADDRESS pdpt_pa;
    pdpt_pa.QuadPart = (LONGLONG)(pml4e & 0x000FFFFFFFFFF000ULL);
    PVOID pdpt_map   = MmMapIoSpace(pdpt_pa, PAGE_SIZE, MmNonCached);
    if (!pdpt_map) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 pdpt_idx = (va >> 30) & 0x1FF;
    UINT64 pdpte    = ((UINT64 *)pdpt_map)[pdpt_idx];
    MmUnmapIoSpace(pdpt_map, PAGE_SIZE);

    if (!(pdpte & 1)) return STATUS_NOT_FOUND;
    if (pdpte & 0x80) {
        *pa = (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
        return STATUS_SUCCESS;
    }

    PHYSICAL_ADDRESS pd_pa;
    pd_pa.QuadPart = (LONGLONG)(pdpte & 0x000FFFFFFFFFF000ULL);
    PVOID pd_map   = MmMapIoSpace(pd_pa, PAGE_SIZE, MmNonCached);
    if (!pd_map) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 pd_idx = (va >> 21) & 0x1FF;
    UINT64 pde    = ((UINT64 *)pd_map)[pd_idx];
    MmUnmapIoSpace(pd_map, PAGE_SIZE);

    if (!(pde & 1)) return STATUS_NOT_FOUND;
    if (pde & 0x80) {
        *pa = (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
        return STATUS_SUCCESS;
    }

    PHYSICAL_ADDRESS pt_pa;
    pt_pa.QuadPart = (LONGLONG)(pde & 0x000FFFFFFFFFF000ULL);
    PVOID pt_map   = MmMapIoSpace(pt_pa, PAGE_SIZE, MmNonCached);
    if (!pt_map) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 pt_idx = (va >> 12) & 0x1FF;
    UINT64 pte    = ((UINT64 *)pt_map)[pt_idx];
    MmUnmapIoSpace(pt_map, PAGE_SIZE);

    if (!(pte & 1)) return STATUS_NOT_FOUND;

    *pa = (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return STATUS_SUCCESS;
}
