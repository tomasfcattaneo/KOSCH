/* безликий
 *
 * Per-thread NtClose gate for calling arbitrary kernel functions.
 * No persistent hook — install/remove per call (~150us overhead).
 */
#pragma once

#include "types.h"
#include "tbt.h"
#include "sysinfo.h"

typedef struct
{
    ZvCtx *tbt;
    VirtAddr nt_close_va;
    PhysAddr nt_close_pa;
    VirtAddr gate_va;
    PhysAddr gate_pa;
    VirtAddr kthread;
    VirtAddr last_target;
    uint8_t original_bytes[32];
    bool ready;
} NkCtx;

Result Nk_Init(NkCtx *ctx, ZvCtx *tbt, SxInfo *ki);
Result Nk_Call(NkCtx *ctx, VirtAddr target, uint64_t arg1, uint64_t arg2,
                 uint64_t arg3, uint64_t *ret);
Result Nk_Cleanup(NkCtx *ctx);

VirtAddr Nk_ResolveExport(SxInfo *ki, uint32_t name_hash);
