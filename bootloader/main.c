/**
 *
 *
 *
 */
#include <loading.h>
#include <cortex.h>

uint32_t main() {
    fkb_header_t *fkb = NULL;

    volatile uint32_t i = 0;
    while (1) {
        i++;
    }

    // __set_MSP( (uint32_t)(__sketch_vectors_ptr) );
    // SCB->VTOR = ((uint32_t)(&__sketch_vectors_ptr) & SCB_VTOR_TBLOFF_Msk);
    // asm("bx %0"::"r"(*pulSketch_Start_Address));

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
