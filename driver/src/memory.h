/* безликий */
#pragma once

#include <ntifs.h>

NTSTATUS Vx_Init(void);

NTSTATUS Vx_Attach(HANDLE pid, PEPROCESS *proc, KAPC_STATE *apc);
void Vx_Detach(PEPROCESS proc, KAPC_STATE *apc);

NTSTATUS Vx_Read(HANDLE pid, UINT64 address, PVOID buffer, ULONG length);
NTSTATUS Vx_Write(HANDLE pid, UINT64 address, PVOID buffer, ULONG length);
NTSTATUS Vx_Translate(HANDLE pid, UINT64 va, UINT64 *pa);
NTSTATUS Vx_GetModuleBase(HANDLE pid, PCWSTR module_name, UINT64 *base);
UINT64 Vx_GetCr3(PEPROCESS proc);
