/* безликий */
#pragma once

#include <ntifs.h>

NTSTATUS Sx_Init(void);
PEPROCESS Sx_FindProcess(HANDLE pid);
PVOID Sx_FindKernelExport(UINT32 name_hash);
