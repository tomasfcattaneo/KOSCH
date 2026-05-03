/* безликий */
#pragma once

#include <windows.h>
#include "gate.h"

extern void* g_cmd_buf;
extern uint64_t g_dispatch_va;
extern NkCtx g_gate;

int SendDriverCommand(int cmd, void* req, size_t req_size, void* rsp);

DWORD FindProcessId(const wchar_t* name);
UINT64 GetModuleBase(DWORD pid, const wchar_t* mod);
BOOL ReadMemory(DWORD pid, UINT64 addr, void* buf, SIZE_T size);