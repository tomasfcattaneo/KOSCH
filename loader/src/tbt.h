/* безликий */
#pragma once

#include "types.h"
#include "svc.h"
#include <windows.h>

#define ZV_IOCTL_PHYS_READ    0x2220CC
#define ZV_IOCTL_PHYS_WRITE   0x2220D0
#define ZV_IOCTL_VIRT_TO_PHYS 0x2220C0
#define ZV_IOCTL_ALLOC_CONTIG 0x2220C4
#define ZV_IOCTL_FREE_CONTIG  0x2220C8

typedef struct
{
    HANDLE device;
    IoCtx svc;
    char tmp_path[MAX_PATH];
    uint32_t ioctl_count;
} ZvCtx;

Result Zv_Init(ZvCtx *ctx);
Result Zv_Cleanup(ZvCtx *ctx);

Result Zv_PhysRead(ZvCtx *ctx, PhysAddr pa, void *buf, uint32_t size);
Result Zv_PhysWrite(ZvCtx *ctx, PhysAddr pa, const void *buf, uint32_t size);

Result Zv_VirtToPhys(ZvCtx *ctx, VirtAddr va, PhysAddr *pa);

Result Zv_AllocContig(ZvCtx *ctx, uint32_t size, VirtAddr *va, PhysAddr *pa);
Result Zv_FreeContig(ZvCtx *ctx, VirtAddr va);
