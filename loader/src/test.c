/* безликий */
#include "constants.h"
#include "test.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL found = FALSE;
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                found = TRUE;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

extern NkCtx g_gate;
extern uint64_t g_dispatch_va;
extern void* g_cmd_buf;

UINT64 GetModuleBase(DWORD pid, const wchar_t* mod) {
    DX_MODBASE req = { .pid = pid };
    wcscpy_s(req.module_name, 64, mod);
    DX_RSP rsp = {0};
    if (SendDriverCommand(CMD_GET_MODULE_BASE, &req, sizeof(req), &rsp) == 0 && rsp.status == 0)
        return rsp.value;
    return 0;
}

BOOL ReadMemory(DWORD pid, UINT64 addr, void* buf, SIZE_T size) {
    DX_READ req = { .pid = pid, .address = addr, .length = (UINT32)size };
    DX_RSP rsp = {0};
    if (SendDriverCommand(CMD_READ_MEMORY, &req, sizeof(req), &rsp) != 0 || rsp.status != 0)
        return FALSE;
    memcpy(buf, rsp.data, size);
    return TRUE;
}