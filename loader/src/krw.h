/* безликий */
#pragma once

#include "types.h"
#include "tbt.h"

Result Px_Read(ZvCtx *tbt, VirtAddr va, void *buf, uint32_t size);
Result Px_Write(ZvCtx *tbt, VirtAddr va, const void *buf, uint32_t size);

Result Px_ReadU8(ZvCtx *tbt, VirtAddr va, uint8_t *out);
Result Px_ReadU16(ZvCtx *tbt, VirtAddr va, uint16_t *out);
Result Px_ReadU32(ZvCtx *tbt, VirtAddr va, uint32_t *out);
Result Px_ReadU64(ZvCtx *tbt, VirtAddr va, uint64_t *out);
Result Px_ReadPtr(ZvCtx *tbt, VirtAddr va, VirtAddr *out);
