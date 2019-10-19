/**
 *
 *
 */
#include <loading.h>
#include <string.h>
#include <sam.h>
#include <SEGGER_RTT.h>

extern void invoke_pic(uint32_t sp, void *entry, uint32_t got);

extern void delay(uint32_t ms);

extern uint32_t __cm_ram_origin;
extern uint32_t __heap_top;
extern uint32_t __data_start__;

static uint8_t has_valid_signature(void *ptr);
static fkb_symbol_t *get_symbol_by_index(fkb_header_t *header, uint32_t symbol);
static fkb_symbol_t *get_first_symbol(fkb_header_t *header);
static fkb_relocation_t *get_first_relocation(fkb_header_t *header);
static uint32_t aligned_on(uint32_t value, uint32_t on);
static uint32_t bytes_to_hex(char *buffer, size_t buffer_length, uint8_t *ptr, size_t size);

fkb_header_t *fkb_try_header(void *ptr) {
    if (!has_valid_signature(ptr)) {
        return NULL;
    }

    return (fkb_header_t *)ptr;
}

uint32_t fkb_verify_exec_state(fkb_header_t *fkbh, fkb_exec_state_t *fkes) {
    uint32_t *vtor = (uint32_t *)((uint8_t *)fkbh + fkbh->firmware.vtor_offset);

    fkes->vtor = vtor;
    fkes->sp = (uint32_t *)*vtor;
    fkes->entry = (uint32_t *)*(vtor + 1);
    fkes->got = (uint32_t *)((uint8_t *)&__cm_ram_origin + fkbh->firmware.got_offset);

    /* Make sure vector table address of app is aligned. */
    if (((uint32_t)(vtor) & ~SCB_VTOR_TBLOFF_Msk) != 0x00) {
        fkb_external_println("bl: [0x%08x] no vector table", fkbh);
        return FKB_EXEC_STATE_BAD_VTOR;
    }

    /* Do nothing if vector pointer is erased. */
    if ((uint32_t)fkes->sp == 0xFFFFFFFF) {
        fkb_external_println("bl: [0x%08x] erased cell", fkbh);
        return FKB_EXEC_STATE_BAD_SP;
    }

    /* Do nothing if SP is invalid. */
    if ((uint32_t)fkes->sp <= (uint32_t)&__cm_ram_origin) {
        fkb_external_println("bl: [0x%08x] invalid SP value (0x%08x)", fkbh, fkes->sp);
        return FKB_EXEC_STATE_BAD_SP;
    }

    return FKB_EXEC_STATE_OK;
}

uint32_t fkb_try_launch(fkb_header_t *fkbh) {
    fkb_exec_state_t fkes;

    if (fkb_verify_exec_state(fkbh, &fkes) != FKB_EXEC_STATE_OK) {
        return 0;
    }

    /* Ok, so we're doing this! */
    fkb_external_println("bl: [0x%08x] executing (sp=0x%p) (entry=0x%p) (got=0x%x)", fkbh, fkes.sp, fkes.entry, fkes.got);

    SCB->VTOR = ((uint32_t)fkes.vtor & SCB_VTOR_TBLOFF_Msk);

    invoke_pic((uint32_t)fkes.sp, (void *)fkes.entry, (uint32_t)fkes.got);

    return 0;
}

typedef struct allocation_t {
    uint32_t allocated;
    void *ptr;
} allocation_t;

uint8_t get_symbol_address(fkb_header_t *header, fkb_symbol_t *symbol, allocation_t *alloc) {
    uint8_t *top = (uint8_t *)&__heap_top;

    alloc->ptr = NULL;
    alloc->allocated = 0;

    if (strcmp(symbol->name, "_SEGGER_RTT") == 0) {
        alloc->ptr = (void *)&_SEGGER_RTT;
        return 0;
    }

    if (strcmp(symbol->name, "fkb_launch_info") == 0) {
        alloc->ptr = (void *)&fkb_launch_info;
        return 0;
    }

    return 0;
}

uint8_t is_valid_pointer(uint32_t *p) {
    return (uint32_t)p >= 0x20000000 && (uint32_t)p < 0x20000000 + 0x00040000;
}

uint32_t analyse_table(fkb_header_t *header) {
    uint8_t *base = (uint8_t *)header;
    uint8_t *ptr = base + sizeof(fkb_header_t);

    fkb_symbol_t *syms = get_first_symbol(header);
    fkb_relocation_t *r = get_first_relocation(header);
    uint8_t *end_of_binary = (uint8_t *)(r + header->number_relocations);

    fkb_external_println("bl: [0x%08x] number-syms=%d number-rels=%d got=0x%x data=0x%x", base,
                         header->number_symbols, header->number_relocations,
                         header->firmware.got_offset, &__data_start__);
    fkb_external_println("bl: [0x%08x] first-sym=0x%x first-relocation=0x%x end-of-binary=0x%x", base, syms, r, end_of_binary);

    if (0) {
        fkb_symbol_t *s = syms;
        for (uint32_t i = 0; i < header->number_symbols; ++i) {
            fkb_external_println("bl: [0x%08x] symbol #%6d addr=0x%8x size=0x%4x '%s'", base, i, s->address, /*s->size*/0, s->name);
            s++;
        }
    }

    for (uint32_t i = 0; i < header->number_relocations; ++i) {
        fkb_symbol_t *sym = &syms[r->symbol];
        uint32_t *rel = (uint32_t *)(((uint8_t *)&__cm_ram_origin) + r->offset + header->firmware.got_offset);
        allocation_t alloc;

        if (!is_valid_pointer(rel)) {
            if (0) {
                fkb_external_println("bl: [0x%08x] relocation #6%d r.offset=0x%8x rel=%s allocated=0x%8x s.size=0x%4x s.addr=0x%8x of='%s'",
                                     base, i, r->offset, "<invalid>", alloc.ptr, /*sym->size*/0, sym->address, sym->name);
            }
            r++;
            continue;
        }

        get_symbol_address(header, sym, &alloc);

        uint32_t old_value = *rel;

        if (0) {
            fkb_external_println("bl: [0x%08x] relocation #6%d r.offset=0x%8x rel=0x%8x allocated=0x%8x s.size=0x%4x s.addr=0x%8x old=0x%8x of='%s'",
                                 base, i, r->offset, rel, alloc.ptr, /*sym->size*/0, sym->address, old_value, sym->name);
        }

        *rel = (uint32_t)sym->address;

        r++;
    }

    return 0;
}

uint32_t fkb_find_and_launch(void *ptr) {
    fkb_header_t *selected = NULL;

    while (1) {
        fkb_external_println("bl: [0x%08p] checking for header", ptr);

        fkb_header_t *fkbh = fkb_try_header(ptr);
        if (fkbh == NULL) {
            break;
        }

        selected = fkbh;

        fkb_external_println("bl: [0x%08p] found '%s' / #%lu '%s' flags=0x%x size=%lu data=%lu bss=%lu got=%lu vtor=0x%x", ptr,
                             fkbh->firmware.name, fkbh->firmware.number, fkbh->firmware.version,
                             fkbh->firmware.flags, fkbh->firmware.binary_size,
                             fkbh->firmware.data_size, fkbh->firmware.bss_size, fkbh->firmware.got_size,
                             fkbh->firmware.vtor_offset);

        char hex_hash[(fkbh->firmware.hash_size * 2) + 1];
        bytes_to_hex(hex_hash, sizeof(hex_hash), fkbh->firmware.hash, fkbh->firmware.hash_size);

        fkb_external_println("bl: [0x%08p] hash='%s' timestamp=%lu", ptr,
                             hex_hash, fkbh->firmware.timestamp);

        analyse_table(fkbh);

        ptr += aligned_on(fkbh->firmware.binary_size, 0x1000);
    }

    if (selected == NULL) {
        return 0;
    }

    return fkb_try_launch(selected);
}

static uint8_t has_valid_signature(void *ptr) {
    fkb_header_t *fkbh = (fkb_header_t *)ptr;
    return strcmp(fkbh->signature, "FKB") == 0;
}


static uint32_t sizeof_symbols(fkb_header_t *header) {
    return sizeof(fkb_symbol_t) * header->number_symbols;
}

static uint32_t sizeof_relocations(fkb_header_t *header) {
    return sizeof(fkb_relocation_t) * header->number_relocations;
}

static fkb_symbol_t *get_symbol_by_index(fkb_header_t *header, uint32_t symbol) {
    uint8_t *base = (uint8_t *)header + header->firmware.binary_size - sizeof_symbols(header) - sizeof_relocations(header);
    return (fkb_symbol_t *)(base + sizeof(fkb_symbol_t) * symbol);
}

static fkb_symbol_t *get_first_symbol(fkb_header_t *header) {
    return get_symbol_by_index(header, 0);
}

static fkb_relocation_t *get_first_relocation(fkb_header_t *header) {
    uint8_t *base = (uint8_t *)header + header->firmware.binary_size - sizeof_relocations(header);
    return (fkb_relocation_t *)base;
}

static uint32_t aligned_on(uint32_t value, uint32_t on) {
    return ((value % on != 0) ? (value + (on - (value % on))) : value);
}

static uint32_t bytes_to_hex(char *buffer, size_t buffer_length, uint8_t *ptr, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        buffer[i * 2    ] = "0123456789abcdef"[ptr[i] >> 4];
        buffer[i * 2 + 1] = "0123456789abcdef"[ptr[i] & 0x0F];
    }

    buffer[size * 2] = 0;

    return 0;
}
