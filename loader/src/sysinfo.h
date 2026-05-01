/* безликий */
#pragma once

#include "types.h"
#include "tbt.h"

typedef struct
{
    char name[256];
    VirtAddr base;
    uint32_t size;
} SxModule;

typedef struct
{
    VirtAddr ntos_base;
    uint32_t ntos_size;
    PhysAddr ntos_phys;
    SxModule *modules;
    uint32_t module_count;
} SxInfo;

Result Sx_Init(SxInfo *info);
Result Sx_ResolveNtosPhys(SxInfo *info, ZvCtx *tbt);
void Sx_Free(SxInfo *info);
