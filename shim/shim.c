#include <stdlib.h>
#include <stdint.h>

typedef struct fkb_header_t {
    uint8_t signature[4];
    uint32_t version;
    uint32_t header_size;
    uint32_t flags;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t bss_size;
} fkb_header_t;

uint32_t shim() {
    fkb_header_t *fkb = NULL;

    volatile uint32_t i = 0;
    while (1) {
        i++;
    }

    /* Rebase the Stack Pointer */
    // __set_MSP( (uint32_t)(__sketch_vectors_ptr) );

    /* Rebase the vector table base address */
    // SCB->VTOR = ((uint32_t)(&__sketch_vectors_ptr) & SCB_VTOR_TBLOFF_Msk);
    // asm("bx %0"::"r"(*pulSketch_Start_Address));

    return 0;
}
