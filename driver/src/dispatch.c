/* безликий */
#include "dispatch.h"
#include "globals.h"
#include <stddef.h>
#include "memory.h"
#include "dkom.h"
#include "sysinfo.h"
#include "ntdefs.h"

static void write_response(PVOID buffer, UINT32 status_code, UINT64 value)
{
    DX_RSP *resp = (DX_RSP *)buffer;
    resp->magic  = NX_MAGIC;
    resp->status = status_code;
    resp->value  = value;
}

static NTSTATUS handle_ping(PVOID buffer)
{
    write_response(buffer, 0, (UINT64)NX_SEED);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_read_memory(PVOID buffer, ULONG size)
{
    DX_READ *req = (DX_READ *)buffer;
    if (size < sizeof(DX_READ)) return STATUS_INVALID_PARAMETER;
    if (req->length > DX_BUF_SIZE - offsetof(DX_RSP, data))
        return STATUS_INVALID_PARAMETER;

    DX_RSP *resp    = (DX_RSP *)buffer;
    NTSTATUS status = Vx_Read((HANDLE)(ULONG_PTR)req->pid, req->address, resp->data,
                              req->length);

    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, req->length);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_write_memory(PVOID buffer, ULONG size)
{
    DX_WRITE *req = (DX_WRITE *)buffer;
    if (size < offsetof(DX_WRITE, data)) return STATUS_INVALID_PARAMETER;
    if (req->length > size - offsetof(DX_WRITE, data)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Vx_Write((HANDLE)(ULONG_PTR)req->pid, req->address, req->data,
                               req->length);

    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, req->length);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_get_module_base(PVOID buffer, ULONG size)
{
    DX_MODBASE *req = (DX_MODBASE *)buffer;
    if (size < sizeof(DX_MODBASE)) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc;
    KAPC_STATE apc;
    if (!NT_SUCCESS(Vx_Attach((HANDLE)(ULONG_PTR)req->pid, &proc, &apc))) {
        write_response(buffer, 1, 0);
        return STATUS_SUCCESS;
    }

    UINT64 result = 0;

    __try {
        UINT64 peb_addr = *(UINT64 *)((UCHAR *)proc + g_Offsets.eprocess_peb);
        if (!peb_addr) goto done;

        PEB64 peb;
        RtlCopyMemory(&peb, (PVOID)(ULONG_PTR)peb_addr, sizeof(peb));
        if (!peb.Ldr) goto done;

        PEB_LDR_DATA ldr;
        RtlCopyMemory(&ldr, (PVOID)(ULONG_PTR)peb.Ldr, sizeof(ldr));

        UINT64 head_addr = peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList);
        UINT64 cur_addr  = (UINT64)(ULONG_PTR)ldr.InLoadOrderModuleList.Flink;

        for (ULONG i = 0; i < 256 && cur_addr != head_addr; i++) {
            LDR_DATA_TABLE_ENTRY64 entry;
            RtlCopyMemory(&entry, (PVOID)(ULONG_PTR)cur_addr, sizeof(entry));

            if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
                WCHAR name[128];
                RtlZeroMemory(name, sizeof(name));
                USHORT copy_len = min(entry.BaseDllName.Length, sizeof(name) - 2);
                RtlCopyMemory(name, (PVOID)(ULONG_PTR)entry.BaseDllName.Buffer, copy_len);

                UNICODE_STRING us_name, us_target;
                RtlInitUnicodeString(&us_name, name);
                RtlInitUnicodeString(&us_target, req->module_name);
                if (RtlEqualUnicodeString(&us_name, &us_target, TRUE)) {
                    result = entry.DllBase;
                    goto done;
                }
            }
            cur_addr = (UINT64)(ULONG_PTR)entry.InLoadOrderLinks.Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

done:
    Vx_Detach(proc, &apc);
    write_response(buffer, result ? 0 : 1, result);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_get_peb(PVOID buffer, ULONG size)
{
    DX_PEB *req = (DX_PEB *)buffer;
    if (size < sizeof(DX_PEB)) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = Sx_FindProcess((HANDLE)(ULONG_PTR)req->pid);
    if (!proc) {
        write_response(buffer, 1, 0);
        return STATUS_SUCCESS;
    }

    UINT64 peb = *(UINT64 *)((UCHAR *)proc + g_Offsets.eprocess_peb);
    ObDereferenceObject(proc);

    write_response(buffer, peb ? 0 : 1, peb);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_hide_process(PVOID buffer, ULONG size)
{
    DX_HIDE *req = (DX_HIDE *)buffer;
    if (size < sizeof(DX_HIDE)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Ox_HideProcess((HANDLE)(ULONG_PTR)req->pid);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_unhide_process(PVOID buffer, ULONG size)
{
    DX_HIDE *req = (DX_HIDE *)buffer;
    if (size < sizeof(DX_HIDE)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = Ox_UnhideProcess((HANDLE)(ULONG_PTR)req->pid);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_translate_va(PVOID buffer, ULONG size)
{
    DX_XLATE *req = (DX_XLATE *)buffer;
    if (size < sizeof(DX_XLATE)) return STATUS_INVALID_PARAMETER;

    UINT64 pa       = 0;
    NTSTATUS status = Vx_Translate((HANDLE)(ULONG_PTR)req->pid, req->address, &pa);
    write_response(buffer, NT_SUCCESS(status) ? 0 : 1, pa);
    return STATUS_SUCCESS;
}

static NTSTATUS handle_query_state(PVOID buffer)
{
    write_response(buffer, 0, (UINT64)InterlockedOr(&g_Initialized, 0));
    return STATUS_SUCCESS;
}

NTSTATUS Dx_Route(PVOID buffer, ULONG size)
{
    DX_HDR *hdr = (DX_HDR *)buffer;
    if (size < sizeof(DX_HDR)) return STATUS_INVALID_PARAMETER;
    if (hdr->magic != NX_MAGIC) return STATUS_ACCESS_DENIED;
    if (hdr->cmd >= CMD_MAX) {
        write_response(buffer, 1, 0);
        return STATUS_INVALID_PARAMETER;
    }

    switch (hdr->cmd) {
    case CMD_PING: return handle_ping(buffer);
    case CMD_READ_MEMORY: return handle_read_memory(buffer, size);
    case CMD_WRITE_MEMORY: return handle_write_memory(buffer, size);
    case CMD_GET_MODULE_BASE: return handle_get_module_base(buffer, size);
    case CMD_GET_PEB: return handle_get_peb(buffer, size);
    case CMD_HIDE_PROCESS: return handle_hide_process(buffer, size);
    case CMD_UNHIDE_PROCESS: return handle_unhide_process(buffer, size);
    case CMD_HIDE_DRIVER: write_response(buffer, 1, 0); return STATUS_SUCCESS;
    case CMD_TRANSLATE_VA: return handle_translate_va(buffer, size);
    case CMD_QUERY_STATE: return handle_query_state(buffer);
    default: write_response(buffer, 1, 0); return STATUS_INVALID_PARAMETER;
    }
}
