/* безликий */
#include "krw.h"

Result Px_Read(ZvCtx *tbt, VirtAddr va, void *buf, uint32_t size)
{
    uint8_t *dst       = (uint8_t *)buf;
    uint32_t remaining = size;
    VirtAddr cursor    = va;

    while (remaining > 0) {
        uint32_t page_off = (uint32_t)(cursor & 0xFFF);
        uint32_t chunk    = 0x1000 - page_off;
        if (chunk > remaining) chunk = remaining;

        PhysAddr pa;
        TRY(Zv_VirtToPhys(tbt, cursor, &pa));
        TRY(Zv_PhysRead(tbt, pa, dst, chunk));

        dst += chunk;
        cursor += chunk;
        remaining -= chunk;
    }
    return OK_VOID;
}

Result Px_Write(ZvCtx *tbt, VirtAddr va, const void *buf, uint32_t size)
{
    const uint8_t *src = (const uint8_t *)buf;
    uint32_t remaining = size;
    VirtAddr cursor    = va;

    while (remaining > 0) {
        uint32_t page_off = (uint32_t)(cursor & 0xFFF);
        uint32_t chunk    = 0x1000 - page_off;
        if (chunk > remaining) chunk = remaining;

        PhysAddr pa;
        TRY(Zv_VirtToPhys(tbt, cursor, &pa));
        TRY(Zv_PhysWrite(tbt, pa, src, chunk));

        src += chunk;
        cursor += chunk;
        remaining -= chunk;
    }
    return OK_VOID;
}

Result Px_ReadU8(ZvCtx *t, VirtAddr va, uint8_t *o)
{
    return Px_Read(t, va, o, 1);
}

Result Px_ReadU16(ZvCtx *t, VirtAddr va, uint16_t *o)
{
    return Px_Read(t, va, o, 2);
}

Result Px_ReadU32(ZvCtx *t, VirtAddr va, uint32_t *o)
{
    return Px_Read(t, va, o, 4);
}

Result Px_ReadU64(ZvCtx *t, VirtAddr va, uint64_t *o)
{
    return Px_Read(t, va, o, 8);
}

Result Px_ReadPtr(ZvCtx *t, VirtAddr va, VirtAddr *o)
{
    return Px_Read(t, va, o, 8);
}
