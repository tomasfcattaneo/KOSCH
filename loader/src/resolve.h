/* безликий */
#pragma once

#include "types.h"
#include "sysinfo.h"

Result Rx_Import(SxInfo *ki, const char *dll, const char *func_name,
                 VirtAddr *out);
