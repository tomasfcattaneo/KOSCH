/* безликий */
#pragma once

#include "types.h"
#include "pe.h"
#include "tbt.h"
#include "sysinfo.h"

Result Mx_Map(ZvCtx *tbt, SxInfo *ki, const uint8_t *raw, size_t raw_size, LxImage *pe,
              MxImage *out);
