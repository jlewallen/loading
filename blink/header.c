#include <loading.h>

#if defined(FKB_ENABLE_HEADER)

__attribute__((section(".fkbh")))
const struct fkb_header_t fkb_header = {
    .signature          = FKB_HEADER_SIGNATURE(),
    .version            = 1,
    .size               = sizeof(fkb_header_t),
    .firmware           = {
        .flags          = 0,
        .timestamp      = 0,
        .binary_size    = 0,
        .vtor_offset    = 0,
        .name           = "blink-8770a491-f537-4375-a074-682571d2dd55.bin",
        .hash           = ""
    }
};

#endif
