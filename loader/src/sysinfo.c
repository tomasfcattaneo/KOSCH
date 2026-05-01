/* безликий */
#include "sysinfo.h"
#include "nt_defs.h"
#include "peb.h"
#include "crypt.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

Result Sx_Init(SxInfo *info)
{
    memset(info, 0, sizeof(*info));

    void *ntdll = Peb_FindModule(H_ntdll_dll);
    PNtQuerySystemInformation query =
        (PNtQuerySystemInformation)Peb_FindExport(ntdll, H_NtQuerySystemInformation);
    if (!query)
        return ERR(STATUS_ERR_NTOS_NOT_FOUND, EMSG("sysinfo query resolve failed"));

    ULONG needed = 0;
    query(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0) return ERR(STATUS_ERR_NTOS_NOT_FOUND, EMSG("module query empty"));

    RTL_PROCESS_MODULES *mods = (RTL_PROCESS_MODULES *)calloc(1, needed);
    if (!mods) return ERR(STATUS_ERR_ALLOC_FAILED, EMSG("module buffer alloc"));

    LONG status = query(SystemModuleInformation, mods, needed, &needed);
    if (status < 0) {
        free(mods);
        return ERR(STATUS_ERR_NTOS_NOT_FOUND, EMSG("sysinfo query failed"));
    }

    info->module_count = mods->NumberOfModules;
    info->modules      = (SxModule *)calloc(info->module_count, sizeof(SxModule));
    if (!info->modules) {
        free(mods);
        return ERR(STATUS_ERR_ALLOC_FAILED, EMSG("module array alloc"));
    }

    for (uint32_t i = 0; i < info->module_count; i++) {
        RTL_PROCESS_MODULE_INFORMATION *m = &mods->Modules[i];
        const char *fname = (const char *)m->FullPathName + m->OffsetToFileName;
        strncpy(info->modules[i].name, fname, sizeof(info->modules[i].name) - 1);
        info->modules[i].base = (VirtAddr)m->ImageBase;
        info->modules[i].size = m->ImageSize;

        if (i == 0) {
            info->ntos_base = info->modules[i].base;
            info->ntos_size = info->modules[i].size;
            LOG_INF("ntoskrnl: %s @ 0x%llX (0x%X)", info->modules[i].name,
                    info->ntos_base, info->ntos_size);
        }
    }

    free(mods);
    return OK_VOID;
}

Result Sx_ResolveNtosPhys(SxInfo *info, ZvCtx *tbt)
{
    PhysAddr pa;
    TRY(Zv_VirtToPhys(tbt, info->ntos_base, &pa));
    info->ntos_phys = pa;
    LOG_INF("ntoskrnl phys: 0x%llX", info->ntos_phys);

    uint16_t mz = 0;
    TRY(Zv_PhysRead(tbt, pa, &mz, 2));
    if (mz != 0x5A4D)
        return ERR(STATUS_ERR_NTOS_NOT_FOUND, EMSG("MZ mismatch at phys base"));

    return OK_VOID;
}

void Sx_Free(SxInfo *info)
{
    free(info->modules);
    memset(info, 0, sizeof(*info));
}
