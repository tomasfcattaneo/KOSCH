/* безликий */
#include "cleanup.h"
#include "krw.h"
#include "crypt.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>

typedef struct
{
    uint16_t name_length;
    uint16_t name_max_length;
    uint32_t _pad;
    uint64_t name_buffer;
    uint64_t module_start;
    uint64_t module_end;
    uint64_t unload_time;
} UnloadedDriverEntry;

#define MM_UNLOADED_MAX 50

static bool wchar_match_i(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? *a + 32 : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? *b + 32 : *b;
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == *b;
}

typedef struct
{
    const uint8_t *pre;
    uint32_t pre_len;
    const uint8_t *post;
    uint32_t post_len;
    uint32_t disp_offset;
    VirtAddr result;
} PatternQuery;

static bool match_pattern(const uint8_t *page, uint32_t pos, uint32_t chunk,
                          PatternQuery *q)
{
    uint32_t total = q->pre_len + 4 + q->post_len;
    if (pos + total > chunk) return false;
    if (memcmp(&page[pos], q->pre, q->pre_len) != 0) return false;
    if (q->post_len > 0 && memcmp(&page[pos + q->pre_len + 4], q->post, q->post_len) != 0)
        return false;
    return true;
}

static void scan_text_multi(ZvCtx *tbt, SxInfo *ki, PatternQuery *queries, uint32_t count)
{
    VirtAddr text_base = ki->ntos_base + 0x1000;
    uint32_t text_size = ki->ntos_size - 0x1000;
    if (text_size > 0x1400000) text_size = 0x1400000;

    uint8_t page[0x1000];
    uint32_t found = 0;

    for (uint32_t off = 0; off < text_size && found < count; off += 0x1000) {
        uint32_t chunk = text_size - off;
        if (chunk > 0x1000) chunk = 0x1000;
        if (IS_ERR(Px_Read(tbt, text_base + off, page, chunk))) continue;

        for (uint32_t i = 0; i < chunk && found < count; i++) {
            for (uint32_t q = 0; q < count; q++) {
                if (queries[q].result != 0) continue;
                if (!match_pattern(page, i, chunk, &queries[q])) continue;

                int32_t disp;
                memcpy(&disp, &page[i + queries[q].disp_offset], 4);
                VirtAddr rip      = text_base + off + i + queries[q].disp_offset + 4;
                queries[q].result = rip + disp;
                found++;
            }
        }
    }
}

static Result cx_mm_unloaded(ZvCtx *tbt, VirtAddr mm_unloaded_va,
                             const wchar_t *driver_name)
{
    if (!mm_unloaded_va)
        return ERR(STATUS_ERR_CLEANUP, EMSG("MmUnloadedDrivers not found"));

    VirtAddr array_va;
    TRY(Px_Read(tbt, mm_unloaded_va, &array_va, 8));
    if (!array_va) return OK_VOID;

    uint32_t cleaned = 0;

    for (uint32_t i = 0; i < MM_UNLOADED_MAX; i++) {
        UnloadedDriverEntry entry;
        VirtAddr entry_va = array_va + i * sizeof(UnloadedDriverEntry);
        TRY(Px_Read(tbt, entry_va, &entry, sizeof(entry)));

        if (entry.name_length == 0 || entry.name_buffer == 0) continue;

        uint32_t char_count = entry.name_length / sizeof(wchar_t);
        if (char_count > 260) continue;

        wchar_t name_buf[261];
        memset(name_buf, 0, sizeof(name_buf));
        TRY(Px_Read(tbt, entry.name_buffer, name_buf, char_count * sizeof(wchar_t)));

        if (wchar_match_i(name_buf, driver_name)) {
            uint16_t zero = 0;
            TRY(Px_Write(tbt, entry_va, &zero, 2));
            cleaned++;
        }
    }

    LOG_INF("  MmUnloadedDrivers: cleaned %u entries", cleaned);
    return OK_VOID;
}

static Result piddb_walk_and_clean(ZvCtx *tbt, VirtAddr node, const wchar_t *driver_name,
                                   uint32_t *cleaned, uint32_t depth)
{
    if (!node || depth > 32) return OK_VOID;

    VirtAddr left, right;
    TRY(Px_Read(tbt, node + 0x00, &left, 8));
    TRY(Px_Read(tbt, node + 0x08, &right, 8));

    if (left) TRY(piddb_walk_and_clean(tbt, left, driver_name, cleaned, depth + 1));

    uint16_t name_len;
    VirtAddr name_buf;
    TRY(Px_Read(tbt, node + 0x28, &name_len, 2));
    TRY(Px_Read(tbt, node + 0x30, &name_buf, 8));

    if (name_len > 0 && name_buf != 0) {
        uint32_t char_count = name_len / sizeof(wchar_t);
        if (char_count <= 260) {
            wchar_t buf[261];
            memset(buf, 0, sizeof(buf));
            TRY(Px_Read(tbt, name_buf, buf, char_count * sizeof(wchar_t)));
            if (wchar_match_i(buf, driver_name)) {
                uint64_t zero = 0;
                TRY(Px_Write(tbt, node + 0x38, &zero, 8));
                (*cleaned)++;
            }
        }
    }

    if (right) TRY(piddb_walk_and_clean(tbt, right, driver_name, cleaned, depth + 1));
    return OK_VOID;
}

static Result cx_piddb(ZvCtx *tbt, VirtAddr piddb_va, const wchar_t *driver_name)
{
    if (!piddb_va) {
        LOG_WRN("  PiDDBCacheTable not found — skipping");
        return OK_VOID;
    }

    VirtAddr root;
    TRY(Px_Read(tbt, piddb_va + 0x08, &root, 8));
    if (!root) return OK_VOID;

    uint32_t cleaned = 0;
    TRY(piddb_walk_and_clean(tbt, root, driver_name, &cleaned, 0));
    LOG_INF("  PiDDBCacheTable: cleaned %u entries", cleaned);
    return OK_VOID;
}

Result Cx_All(ZvCtx *tbt, SxInfo *ki, const wchar_t *driver_name)
{
    LOG_INF("cleaning forensic traces");

    static const uint8_t mm_pre[]  = {0x4C, 0x8B, 0x0D};
    static const uint8_t mm_post[] = {0x4D, 0x85, 0xC9, 0x75};
    static const uint8_t pi_pre[]  = {0x33, 0xC0, 0x48, 0x8D, 0x0D};
    static const uint8_t pi_post[] = {0x45, 0x33, 0xF6};

    PatternQuery queries[2] = {
        {mm_pre, 3, mm_post, 4, 3, 0},
        {pi_pre, 5, pi_post, 3, 5, 0},
    };

    scan_text_multi(tbt, ki, queries, 2);

    Result r1 = cx_piddb(tbt, queries[1].result, driver_name);
    Result r2 = cx_mm_unloaded(tbt, queries[0].result, driver_name);

    if (IS_ERR(r1)) LOG_WRN("  PiDDB cleanup: %s", r1.msg);
    if (IS_ERR(r2)) LOG_WRN("  MmUnloaded cleanup: %s", r2.msg);

    return (IS_ERR(r1) && IS_ERR(r2)) ? r1 : OK_VOID;
}
