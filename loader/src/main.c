/* безликий */
#include "types.h"
#include "log.h"
#include "constants.h"
#include "nt_defs.h"
#include "tbt.h"
#include "sysinfo.h"
#include "krw.h"
#include "gate.h"
#include "pe.h"
#include "mapper.h"
#include "cleanup.h"
#include "xor.h"
#include "peb.h"
#include "crypt.h"
#include "test.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>

#include "koshchei_drv.h"

int SendDriverCommand(int cmd, void* req, size_t req_size, void* rsp)
{
    if (!g_cmd_buf || !g_dispatch_va) return -1;

    DX_HDR* hdr = (DX_HDR*)g_cmd_buf;
    hdr->magic = NX_MAGIC;
    hdr->cmd = cmd;
    hdr->size = sizeof(DX_HDR) + (uint32_t)req_size;

    memcpy((uint8_t*)g_cmd_buf + sizeof(DX_HDR), req, req_size);

    uint64_t ret = 0;
    Result r = Nk_Call(&g_gate, g_dispatch_va, (uint64_t)(uintptr_t)g_cmd_buf, 0, 0, &ret);
    if (IS_ERR(r)) return -1;

    memcpy(rsp, g_cmd_buf, sizeof(DX_RSP) + (((DX_RSP*)g_cmd_buf)->value ? DX_BUF_SIZE - sizeof(DX_RSP) : 0));
    return 0;
}

static void secure_free(void *ptr, size_t len)
{
    if (ptr) {
        memset(ptr, 0, len);
        free(ptr);
    }
}

static Result enable_privileges(void)
{
    void *ntdll = Peb_FindModule(H_ntdll_dll);
    PRtlAdjustPrivilege adjust =
        (PRtlAdjustPrivilege)Peb_FindExport(ntdll, H_RtlAdjustPrivilege);
    if (!adjust) return ERR(STATUS_ERR_PRIVILEGE, EMSG("privilege adjust failed"));

    BOOLEAN prev;
    adjust(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &prev);
    adjust(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &prev);
    return OK_VOID;
}

static Result check_hypervisor(void)
{
    int info[4] = {0};
    __cpuid(info, 1);
    if ((info[2] >> 31) & 1)
        return ERR(STATUS_ERR_HYPERVISOR, EMSG("hypervisor present"));
    return OK_VOID;
}

static Result prefill_bootstrap(ZvCtx *tbt, MxImage *img, LxImage *pe, const uint8_t *raw,
                                void *cmd_buf)
{
    uint32_t data_raw = 0, data_rva = 0, data_size = 0;
    for (uint32_t i = 0; i < pe->section_count; i++) {
        if (memcmp(pe->sections[i].name, ".data", 5) == 0) {
            data_raw  = pe->sections[i].raw_offset;
            data_rva  = pe->sections[i].va;
            data_size = pe->sections[i].raw_size;
            break;
        }
    }
    if (!data_size)
        return ERR(STATUS_ERR_BOOTSTRAP_NOT_FOUND, EMSG("data section missing"));

    uint32_t offset = 0;
    bool found      = false;
    for (uint32_t i = 0; i + 16 <= data_size; i += 8) {
        const uint64_t *p = (const uint64_t *)(raw + data_raw + i);
        if (p[0] == NX_SENTINEL1 && p[1] == NX_SENTINEL2) {
            offset = i;
            found  = true;
            break;
        }
    }
    if (!found) return ERR(STATUS_ERR_BOOTSTRAP_NOT_FOUND, EMSG("sentinel missing"));

    VirtAddr bootstrap_va = img->base + data_rva + offset;

    uint8_t payload[32];
    uint64_t s1  = NX_SENTINEL1;
    uint64_t s2  = NX_SENTINEL2;
    uint64_t va  = (uint64_t)(uintptr_t)cmd_buf;
    uint32_t pid = GetCurrentProcessId();
    uint32_t flg = 1;

    memcpy(payload + 0, &s1, 8);
    memcpy(payload + 8, &s2, 8);
    memcpy(payload + 16, &va, 8);
    memcpy(payload + 24, &pid, 4);
    memcpy(payload + 28, &flg, 4);

    TRY(Px_Write(tbt, bootstrap_va, payload, 32));
    LOG_INF("  bootstrap written at 0x%llX (pid=%u)", bootstrap_va, pid);
    return OK_VAL(bootstrap_va);
}

void* g_cmd_buf = NULL;
uint64_t g_dispatch_va = 0;
NkCtx g_gate;

int main(void)
{
#ifndef KOSHCHEI_RELEASE
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif
    void *cmd_buf  = NULL;
    bool driver_ok = false;
    LOG_INF("=== init ===");

    LOG_INF("[Step 0] privilege + environment checks");
    Result r = enable_privileges();
    if (IS_ERR(r)) {
        LOG_ERR("privileges: %s", r.msg);
        return 1;
    }

    r = check_hypervisor();
    if (IS_ERR(r)) LOG_WRN("hypervisor detected");

    LOG_INF("[Step 1] enumerating kernel modules");
    SxInfo ki;
    r = Sx_Init(&ki);
    if (IS_ERR(r)) {
        LOG_ERR("sysinfo: %s", r.msg);
        return 1;
    }

    LOG_INF("[Step 2] loading driver");
    ZvCtx tbt;
    r = Zv_Init(&tbt);
    if (IS_ERR(r)) {
        LOG_ERR("Zv_Init: %s", r.msg);
        Sx_Free(&ki);
        return 1;
    }

    LOG_INF("[Step 3] discovering ntoskrnl physical base");
    r = Sx_ResolveNtosPhys(&ki, &tbt);
    if (IS_ERR(r)) {
        LOG_ERR("ntos phys: %s", r.msg);
        goto cleanup;
    }

    LOG_INF("[Step 4] verifying kernel R/W");
    {
        uint16_t mz = 0;
        r           = Px_ReadU16(&tbt, ki.ntos_base, &mz);
        if (IS_ERR(r) || mz != 0x5A4D) {
            LOG_ERR("kernel R/W verification failed (mz=0x%04X)", mz);
            goto cleanup;
        }
        LOG_INF("  ntoskrnl MZ verified via VA read");
    }

    LOG_INF("[Step 5] installing NtClose gate");
    NkCtx gate;
    r = Nk_Init(&gate, &tbt, &ki);
    if (IS_ERR(r)) {
        LOG_ERR("Nk_Init: %s", r.msg);
        goto cleanup;
    }

    LOG_INF("[Step 6] parsing driver PE");
    uint8_t *driver_raw = xor_decrypt(koshchei_drv_data, koshchei_drv_size);
    if (!driver_raw) {
        LOG_ERR("driver decrypt failed");
        goto cleanup_gate;
    }

    LxImage pe;
    r = Lx_Parse(driver_raw, koshchei_drv_size, &pe);
    if (IS_ERR(r)) {
        LOG_ERR("Lx_Parse: %s", r.msg);
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    LOG_INF("[Step 7] mapping driver into kernel");
    MxImage img;
    r = Mx_Map(&tbt, &ki, driver_raw, koshchei_drv_size, &pe, &img);
    if (IS_ERR(r)) {
        LOG_ERR("mapper: %s", r.msg);
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    LOG_INF("[Step 8] pre-filling NX_BRIDGE");
    cmd_buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!cmd_buf) {
        LOG_ERR("cmd buffer alloc failed");
        secure_free(driver_raw, koshchei_drv_size);
        goto cleanup_gate;
    }

    r = prefill_bootstrap(&tbt, &img, &pe, driver_raw, cmd_buf);
    secure_free(driver_raw, koshchei_drv_size);
    if (IS_ERR(r)) {
        LOG_ERR("bootstrap: %s", r.msg);
        goto cleanup_gate;
    }
    VirtAddr bootstrap_va = r.value;

    LOG_INF("[Step 9] calling DriverEntry");
    {
        uint64_t entry_ret = 0;
        r                  = Nk_Call(&gate, img.entry, 0, 0, 0, &entry_ret);
        if (IS_ERR(r)) {
            LOG_ERR("Nk_Call DriverEntry: %s", r.msg);
            goto cleanup_gate;
        }
        LOG_INF("  DriverEntry returned 0x%llX", entry_ret);
        if ((int64_t)entry_ret < 0) {
            LOG_ERR("  DriverEntry failed with NTSTATUS 0x%08X", (uint32_t)entry_ret);
            goto cleanup_gate;
        }
    }

    {
        uint64_t dispatch_va = 0;
        r                    = Px_ReadU64(&tbt, bootstrap_va + 32, &dispatch_va);
        if (IS_ERR(r) || dispatch_va == 0) {
            LOG_ERR("dispatch_va not found");
            goto cleanup_gate;
        }
        LOG_INF("[Step 10] dispatch_va=0x%llX", (unsigned long long)dispatch_va);

        uint64_t ping_ret = 0;
        memset(cmd_buf, 0, 4096);
        uint32_t magic = NX_MAGIC;
        uint32_t cmd   = 0;
        uint32_t size  = 12;
        memcpy((uint8_t *)cmd_buf + 0, &magic, 4);
        memcpy((uint8_t *)cmd_buf + 4, &cmd, 4);
        memcpy((uint8_t *)cmd_buf + 8, &size, 4);

        r = Nk_Call(&gate, dispatch_va, (uint64_t)(uintptr_t)cmd_buf, 0, 0, &ping_ret);
        if (IS_ERR(r)) {
            LOG_ERR("ping failed: %s", r.msg);
            goto cleanup_gate;
        }

        uint32_t resp_magic = 0, resp_status = 0;
        uint64_t resp_value = 0;
        memcpy(&resp_magic, (uint8_t *)cmd_buf + 0, 4);
        memcpy(&resp_status, (uint8_t *)cmd_buf + 4, 4);
        memcpy(&resp_value, (uint8_t *)cmd_buf + 8, 8);

        if (resp_magic == NX_MAGIC && resp_status == 0 &&
            resp_value == (uint64_t)NX_SEED) {
            LOG_INF("  ping OK");
        }
        else {
            LOG_ERR("  ping mismatch");
            goto cleanup_gate;
        }
    }

    LOG_INF("[INF] Testing memory read of hl.exe...");
    DWORD pid = FindProcessId(L"hl.exe");
    if (pid) {
        LOG_INF("[INF] hl.exe PID: %lu", pid);
        UINT64 client = GetModuleBase(pid, L"client.dll");
        if (client) {
            LOG_INF("[INF] client.dll @ 0x%llx", client);
            int health = 0;
            if (ReadMemory(pid, client + 0x187704, &health, sizeof(health))) {
                LOG_INF("[INF] Player health = %d", health);
            } else {
                LOG_ERR("[ERR] Failed to read health");
            }
        } else {
            LOG_ERR("[ERR] client.dll not found");
        }
    } else {
        LOG_WRN("[WRN] hl.exe not running");
    }

    driver_ok = true;
    LOG_INF("[Step 11] cleaning traces");

    static const wchar_t drv_name[] = L"TBT_Force_Power_Control_Access64.sys";
    Cx_All(&tbt, &ki, drv_name);

    LOG_INF("[Step 12] cleanup, hold");

cleanup_gate:
    Nk_Cleanup(&gate);

cleanup:
    Zv_Cleanup(&tbt);
    Sx_Free(&ki);

    if (driver_ok && cmd_buf) {
        while (1) Sleep(60000);
    }

    return IS_OK(r) ? 0 : 1;
}
