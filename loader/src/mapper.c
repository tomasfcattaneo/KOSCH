/* безликий */
#include "mapper.h"
#include "krw.h"
#include "resolve.h"
#include "crypt.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <intrin.h>

static uint32_t rva_to_file(LxImage *pe, uint32_t rva)
{
    for (uint32_t i = 0; i < pe->section_count; i++) {
        uint32_t s = pe->sections[i].va;
        uint32_t e = s + pe->sections[i].virt_size;
        if (rva >= s && rva < e) return pe->sections[i].raw_offset + (rva - s);
    }
    return 0;
}

static Result copy_sections(ZvCtx *tbt, VirtAddr base, const uint8_t *raw, LxImage *pe)
{
    uint8_t zero_page[0x1000];
    memset(zero_page, 0, sizeof(zero_page));

    for (uint32_t i = 0; i < pe->section_count; i++) {
        LxSection *s = &pe->sections[i];
        if (s->raw_size == 0) continue;

        uint32_t copy = s->raw_size < s->virt_size ? s->raw_size : s->virt_size;
        VirtAddr dest = base + s->va;

        TRY(Px_Write(tbt, dest, raw + s->raw_offset, copy));

        if (s->virt_size > s->raw_size) {
            uint32_t bss       = s->virt_size - s->raw_size;
            VirtAddr bss_dest  = dest + copy;
            uint32_t remaining = bss;
            while (remaining > 0) {
                uint32_t chunk = remaining > 0x1000 ? 0x1000 : remaining;
                TRY(Px_Write(tbt, bss_dest, zero_page, chunk));
                bss_dest += chunk;
                remaining -= chunk;
            }
        }
    }
    return OK_VOID;
}

static Result apply_relocs(ZvCtx *tbt, VirtAddr base, LxImage *pe)
{
    int64_t delta = (int64_t)base - (int64_t)pe->image_base;
    if (delta == 0) return OK_VOID;

    for (uint32_t i = 0; i < pe->reloc_count; i++) {
        VirtAddr addr = base + pe->relocs[i].rva;

        if (pe->relocs[i].type == IMAGE_REL_BASED_DIR64) {
            uint64_t val;
            TRY(Px_Read(tbt, addr, &val, 8));
            val += delta;
            TRY(Px_Write(tbt, addr, &val, 8));
        }
        else if (pe->relocs[i].type == IMAGE_REL_BASED_HIGHLOW) {
            uint32_t val;
            TRY(Px_Read(tbt, addr, &val, 4));
            val = (uint32_t)((int64_t)val + delta);
            TRY(Px_Write(tbt, addr, &val, 4));
        }
    }
    LOG_INF("  applied %u relocations (delta=0x%llX)", pe->reloc_count, (uint64_t)delta);
    return OK_VOID;
}

static Result patch_iat(ZvCtx *tbt, VirtAddr base, const uint8_t *raw, size_t raw_size,
                        LxImage *pe, SxInfo *ki)
{
    for (uint32_t i = 0; i < pe->import_count; i++) {
        LxImportDesc *imp = &pe->imports[i];

        uint32_t thunk_foff = rva_to_file(pe, imp->thunk_rva);
        if (!thunk_foff) return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("thunk RVA invalid"));

        VirtAddr iat_cursor        = base + imp->iat_rva;
        const uint8_t *hint_cursor = raw + thunk_foff;

        for (;;) {
            uint64_t thunk_val;
            if (hint_cursor + 8 > raw + raw_size) break;
            memcpy(&thunk_val, hint_cursor, 8);
            if (thunk_val == 0) break;

            if (thunk_val & (1ULL << 63))
                return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("ordinal import"));

            uint32_t hint_rva  = (uint32_t)(thunk_val & 0x7FFFFFFF);
            uint32_t name_foff = rva_to_file(pe, hint_rva);
            if (!name_foff || name_foff + 2 >= raw_size)
                return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("hint name OOB"));

            const char *func_name = (const char *)(raw + name_foff + 2);

            VirtAddr resolved;
            TRY(Rx_Import(ki, imp->dll, func_name, &resolved));
            TRY(Px_Write(tbt, iat_cursor, &resolved, 8));

            iat_cursor += 8;
            hint_cursor += 8;
        }
    }
    return OK_VOID;
}

static Result fix_security_cookie(ZvCtx *tbt, VirtAddr base, LxImage *pe)
{
    if (pe->cookie_rva == 0) return OK_VOID;

    uint64_t cookie = __rdtsc() | 0x0000200000000000ULL;
    TRY(Px_Write(tbt, base + pe->cookie_rva, &cookie, 8));
    return OK_VOID;
}

Result Mx_Map(ZvCtx *tbt, SxInfo *ki, const uint8_t *raw, size_t raw_size, LxImage *pe,
              MxImage *out)
{
    memset(out, 0, sizeof(*out));

    VirtAddr pool_va;
    PhysAddr pool_pa;
    TRY(Zv_AllocContig(tbt, pe->image_size, &pool_va, &pool_pa));
    LOG_INF("  image pool: VA=0x%llX PA=0x%llX size=0x%X", pool_va, pool_pa,
            pe->image_size);

    uint32_t hdr_size = pe->section_count > 0 ? pe->sections[0].va : 0x1000;
    if (hdr_size > raw_size) hdr_size = (uint32_t)raw_size;

    Result r = Px_Write(tbt, pool_va, raw, hdr_size);
    if (IS_ERR(r)) goto fail;

    r = copy_sections(tbt, pool_va, raw, pe);
    if (IS_ERR(r)) goto fail;
    LOG_INF("  sections copied");

    r = apply_relocs(tbt, pool_va, pe);
    if (IS_ERR(r)) goto fail;

    r = patch_iat(tbt, pool_va, raw, raw_size, pe, ki);
    if (IS_ERR(r)) goto fail;
    LOG_INF("  IAT patched (%u import descriptors)", pe->import_count);

    r = fix_security_cookie(tbt, pool_va, pe);
    if (IS_ERR(r)) goto fail;

    out->base  = pool_va;
    out->size  = pe->image_size;
    out->entry = pool_va + pe->entry_rva;

    LOG_INF("  mapped: base=0x%llX entry=0x%llX", out->base, out->entry);
    return OK_VOID;

fail:
    Zv_FreeContig(tbt, pool_va);
    return r;
}
