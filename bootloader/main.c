/**
 *
 *
 *
 */
#include <loading.h>
#include <cortex.h>

extern void board_initialize(void);

extern uint32_t __cm_app_vectors_ptr;

uint32_t launch() {
    fkb_header_t *fkb = NULL;

    /* Do nothing if vector pointer is erased. */
    if (__cm_app_vectors_ptr == 0xFFFFFFFF) {
        debug_println("bl: No program: 0x%x (0x%x)", __cm_app_vectors_ptr, &__cm_app_vectors_ptr);
        return 0;
    }

    /* Check reset handler address, skip over initial SP. */
    uint32_t *app_main_ptr = &__cm_app_vectors_ptr + 1;

    /* Make sure vector table address of app is aligned. */
    if ( ((uint32_t)(&__cm_app_vectors_ptr) & ~SCB_VTOR_TBLOFF_Msk) != 0x00)
    {
        debug_println("bl: No vector table: 0x%x (0x%x)", __cm_app_vectors_ptr, &__cm_app_vectors_ptr);
        return 0;
    }

    __set_MSP( (uint32_t)(__cm_app_vectors_ptr) );

    SCB->VTOR = ((uint32_t)(&__cm_app_vectors_ptr) & SCB_VTOR_TBLOFF_Msk);

    asm("bx %0"::"r"(*app_main_ptr));

}

uint32_t main() {
    board_initialize();

    launch();

    /* If we're here then no launching occurred. */

    volatile uint32_t i = 0;
    while (1) {
        i++;
    }

    return 0;
}

void cm_dummy_handler() {
    volatile uint32_t i = 0;
    while (1) {
        i++;
    }
}

void cm_nmi() {
    volatile uint32_t i = 0;
    while (1) {
        i++;
    }
}

void cm_hard_fault() {
    volatile uint32_t i = 0;
    while (1) {
        i++;
    }
}

void cm_svc() {
    volatile uint32_t i = 0;
    while (1) {
        i++;
    }
}

void cm_pendsv() {
    volatile uint32_t i = 0;
    while (1) {
        i++;
    }
}

void cm_systick() {
}

extern uint32_t __cm_stack_top;

__attribute__((section(".isr_vector")))
const struct cm_vector_table_t vector_table = {
    .stack               = (void *)(&__cm_stack_top),
    .reset_handler       = (void *)main,
    .nmi_handler         = (void *)cm_nmi,
    .hard_fault_handler  = (void *)cm_hard_fault,
    .reserved_m12        = (void *)(0UL),
    .reserved_m11        = (void *)(0UL),
    .reserved_m10        = (void *)(0UL),
    .reserved_m9         = (void *)(0UL),
    .reserved_m8         = (void *)(0UL),
    .reserved_m7         = (void *)(0UL),
    .reserved_m6         = (void *)(0UL),
    .svc_handler         = (void *)cm_svc,
    .reserved_m4         = (void *)(0UL),
    .reserved_m3         = (void *)(0UL),
    .pendsv_handler      = (void *)cm_pendsv,
    .systick_handler     = (void *)cm_systick,
};

