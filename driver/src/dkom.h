/* безликий */
#pragma once

#include <ntifs.h>

void Ox_Init(void);
NTSTATUS Ox_HideProcess(HANDLE pid);
NTSTATUS Ox_UnhideProcess(HANDLE pid);
