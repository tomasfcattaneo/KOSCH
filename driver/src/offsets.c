/* безликий */
#include "offsets.h"
#include "globals.h"
#include "sysinfo.h"

KernelOffsets g_Offsets = {0};

#define HK_PsGetProcessId            0x2DD638D8u
#define HK_PsGetProcessPeb           0x5D5EE8ACu
#define HK_PsGetProcessImageFileName 0x79F53F8Fu

static ULONG scan_rcx_disp(const UCHAR *code, ULONG len, UCHAR opcode)
{
    for (ULONG i = 0; i + 7 <= len; i++) {
        if (code[i] != 0x48 || code[i + 1] != opcode) continue;

        UCHAR modrm = code[i + 2];
        UCHAR mod   = modrm >> 6;
        UCHAR rm    = modrm & 7;

        if (rm != 1) continue;

        if (mod == 1 && i + 4 <= len) return (ULONG)(CHAR)code[i + 3];

        if (mod == 2 && i + 7 <= len) return *(ULONG *)&code[i + 3];
    }
    return 0;
}

NTSTATUS Sx_ResolveOffsets(void)
{
    g_Offsets.eprocess_cr3 = 0x028;

    UCHAR *ps_pid = (UCHAR *)Sx_FindKernelExport(HK_PsGetProcessId);
    if (ps_pid) {
        g_Offsets.eprocess_pid = scan_rcx_disp(ps_pid, 32, 0x8B);
        if (g_Offsets.eprocess_pid)
            g_Offsets.eprocess_active_links = g_Offsets.eprocess_pid + 8;
    }

    UCHAR *ps_peb = (UCHAR *)Sx_FindKernelExport(HK_PsGetProcessPeb);
    if (ps_peb) g_Offsets.eprocess_peb = scan_rcx_disp(ps_peb, 32, 0x8B);

    UCHAR *ps_name = (UCHAR *)Sx_FindKernelExport(HK_PsGetProcessImageFileName);
    if (ps_name) g_Offsets.eprocess_image_name = scan_rcx_disp(ps_name, 32, 0x8D);

    if (!g_Offsets.eprocess_pid || !g_Offsets.eprocess_peb ||
        !g_Offsets.eprocess_image_name)
        return STATUS_NOT_FOUND;

    PEPROCESS proc  = PsGetCurrentProcess();
    HANDLE real_pid = PsGetCurrentProcessId();
    HANDLE read_pid = *(HANDLE *)((UCHAR *)proc + g_Offsets.eprocess_pid);
    if (read_pid != real_pid) return STATUS_REVISION_MISMATCH;

    return STATUS_SUCCESS;
}
