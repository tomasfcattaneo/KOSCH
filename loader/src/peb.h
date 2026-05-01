/* безликий */
#pragma once

#include <stdint.h>
#include <windows.h>

void *Peb_FindModule(uint32_t name_hash);
void *Peb_FindExport(void *module_base, uint32_t func_hash);
void *Peb_LoadImage(const wchar_t *path);
void Peb_UnloadImage(void *base);
