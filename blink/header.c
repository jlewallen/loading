#include <loading.h>

#if defined(FKB_ENABLE_HEADER)

__attribute__((section(".fkbh")))
const struct fkb_header_t fkb_header = {
    .signature   = "FKB",
    .version     = 1,
    .header_size = sizeof(fkb_header_t),
    .name        = "blink-8770a491-f537-4375-a074-682571d2dd55.bin",
    .flags       = 0,
    .vtor_offset = 0,
    .binary_size = 0,
    .code_size   = 0,
    .data_size   = 0,
    .bss_size    = 0
};

#endif
