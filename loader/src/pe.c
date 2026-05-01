/* безликий */

#include "pe.h"
#include "crypt.h"
#include "log.h"
#include <string.h>

static inline bool Lx_Bounds(size_t raw_size, uint32_t off, uint32_t len)
{
    return (uint64_t)off + len <= raw_size;
}

static Result parse_sections(const uint8_t *raw, size_t raw_size, IMAGE_NT_HEADERS64 *nt,
                             LxImage *pe)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    uint32_t n                = nt->FileHeader.NumberOfSections;
    if (n > LX_MAX_SECTIONS) return ERR(STATUS_ERR_PE_INVALID, EMSG("too many sections"));

    for (uint32_t i = 0; i < n; i++) {
        if (!Lx_Bounds(raw_size, (uint32_t)((uint8_t *)&sec[i] - raw),
                       sizeof(IMAGE_SECTION_HEADER)))
            return ERR(STATUS_ERR_PE_INVALID, EMSG("section header OOB"));

        LxSection *s = &pe->sections[i];
        memcpy(s->name, sec[i].Name, 8);
        s->va              = sec[i].VirtualAddress;
        s->virt_size       = sec[i].Misc.VirtualSize;
        s->raw_offset      = sec[i].PointerToRawData;
        s->raw_size        = sec[i].SizeOfRawData;
        s->characteristics = sec[i].Characteristics;
    }
    pe->section_count = n;
    return OK_VOID;
}

static Result parse_relocs(const uint8_t *raw, size_t raw_size, IMAGE_NT_HEADERS64 *nt,
                           LxImage *pe)
{
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return OK_VOID;

    uint32_t file_off = 0;
    for (uint32_t i = 0; i < pe->section_count; i++) {
        if (pe->sections[i].va <= dir->VirtualAddress &&
            dir->VirtualAddress < pe->sections[i].va + pe->sections[i].virt_size) {
            file_off = pe->sections[i].raw_offset +
                       (dir->VirtualAddress - pe->sections[i].va);
            break;
        }
    }
    if (!file_off) return OK_VOID;
    if (!Lx_Bounds(raw_size, file_off, dir->Size))
        return ERR(STATUS_ERR_PE_INVALID, EMSG("reloc directory OOB"));

    const uint8_t *ptr = raw + file_off;
    const uint8_t *end = ptr + dir->Size;
    uint32_t count     = 0;

    while (ptr + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)ptr;
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if (ptr + block->SizeOfBlock > end) break;

        uint32_t n_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                             sizeof(uint16_t);
        uint16_t *entries = (uint16_t *)(ptr + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < n_entries; i++) {
            uint16_t type = entries[i] >> 12;
            uint16_t off  = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64 && type != IMAGE_REL_BASED_HIGHLOW)
                continue;

            if (count >= LX_MAX_RELOCS)
                return ERR(STATUS_ERR_PE_INVALID, EMSG("too many relocations"));

            pe->relocs[count].rva  = block->VirtualAddress + off;
            pe->relocs[count].type = type;
            count++;
        }
        ptr += block->SizeOfBlock;
    }
    pe->reloc_count = count;
    return OK_VOID;
}

static Result parse_imports(const uint8_t *raw, size_t raw_size, IMAGE_NT_HEADERS64 *nt,
                            LxImage *pe)
{
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return OK_VOID;

    uint32_t file_off = 0;
    for (uint32_t i = 0; i < pe->section_count; i++) {
        if (pe->sections[i].va <= dir->VirtualAddress &&
            dir->VirtualAddress < pe->sections[i].va + pe->sections[i].virt_size) {
            file_off = pe->sections[i].raw_offset +
                       (dir->VirtualAddress - pe->sections[i].va);
            break;
        }
    }
    if (!file_off) return OK_VOID;

    const uint8_t *base = raw + file_off;
    uint32_t count      = 0;

    for (uint32_t i = 0;; i++) {
        uint32_t desc_off = i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!Lx_Bounds(raw_size, file_off + desc_off, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
            break;

        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + desc_off);
        if (imp->Name == 0 && imp->FirstThunk == 0) break;
        if (count >= LX_MAX_IMPORTS)
            return ERR(STATUS_ERR_PE_INVALID, EMSG("too many import descriptors"));

        LxImportDesc *d = &pe->imports[count];

        uint32_t name_file = 0;
        for (uint32_t j = 0; j < pe->section_count; j++) {
            if (pe->sections[j].va <= imp->Name &&
                imp->Name < pe->sections[j].va + pe->sections[j].virt_size) {
                name_file = pe->sections[j].raw_offset + (imp->Name - pe->sections[j].va);
                break;
            }
        }
        if (name_file && Lx_Bounds(raw_size, name_file, 1)) {
            strncpy(d->dll, (const char *)(raw + name_file), sizeof(d->dll) - 1);
        }

        d->iat_rva   = imp->FirstThunk;
        d->thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                               : imp->FirstThunk;
        count++;
    }
    pe->import_count = count;
    return OK_VOID;
}

static void parse_load_config(const uint8_t *raw, size_t raw_size, IMAGE_NT_HEADERS64 *nt,
                              LxImage *pe)
{
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return;

    uint32_t file_off = 0;
    for (uint32_t i = 0; i < pe->section_count; i++) {
        if (pe->sections[i].va <= dir->VirtualAddress &&
            dir->VirtualAddress < pe->sections[i].va + pe->sections[i].virt_size) {
            file_off = pe->sections[i].raw_offset +
                       (dir->VirtualAddress - pe->sections[i].va);
            break;
        }
    }
    if (!file_off || !Lx_Bounds(raw_size, file_off, 112)) return;

    IMAGE_LOAD_CONFIG_DIRECTORY64 *cfg =
        (IMAGE_LOAD_CONFIG_DIRECTORY64 *)(raw + file_off);
    if (cfg->SecurityCookie) {
        uint64_t cookie_va = cfg->SecurityCookie;
        pe->cookie_rva     = (uint32_t)(cookie_va - pe->image_base);
    }
}

Result Lx_Parse(const uint8_t *raw, size_t raw_size, LxImage *out)
{
    memset(out, 0, sizeof(*out));

    if (raw_size < sizeof(IMAGE_DOS_HEADER))
        return ERR(STATUS_ERR_PE_INVALID, EMSG("too small for DOS header"));

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return ERR(STATUS_ERR_PE_INVALID, EMSG("bad DOS signature"));

    if (!Lx_Bounds(raw_size, dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64)))
        return ERR(STATUS_ERR_PE_INVALID, EMSG("NT headers OOB"));

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return ERR(STATUS_ERR_PE_INVALID, EMSG("bad NT signature"));
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return ERR(STATUS_ERR_PE_INVALID, EMSG("not x64"));
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return ERR(STATUS_ERR_PE_INVALID, EMSG("not PE64"));

    out->image_base = nt->OptionalHeader.ImageBase;
    out->image_size = nt->OptionalHeader.SizeOfImage;
    out->entry_rva  = nt->OptionalHeader.AddressOfEntryPoint;

    TRY(parse_sections(raw, raw_size, nt, out));
    TRY(parse_relocs(raw, raw_size, nt, out));
    TRY(parse_imports(raw, raw_size, nt, out));
    parse_load_config(raw, raw_size, nt, out);

    LOG_INF("PE: base=0x%llX size=0x%X entry=0x%X sects=%u relocs=%u imports=%u",
            out->image_base, out->image_size, out->entry_rva, out->section_count,
            out->reloc_count, out->import_count);
    return OK_VOID;
}
