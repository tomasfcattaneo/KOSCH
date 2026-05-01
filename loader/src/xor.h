/* безликий */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "constants.h"

static inline uint8_t *xor_decrypt(const uint8_t *data, size_t len)
{
    uint8_t *out = (uint8_t *)malloc(len);
    if (!out) return NULL;
    uint64_t key = XOR_KEY_VAL;
    const uint8_t *k = (const uint8_t *)&key;
    for (size_t i = 0; i < len; i++) out[i] = data[i] ^ k[i % 8];
    return out;
}
