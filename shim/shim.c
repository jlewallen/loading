/**
 *
 *
 *
 */
#include <stdlib.h>
#include <stdint.h>

typedef struct cm_vector_table_t {
    void *pvStack;
    void *pfnReset_Handler;
    void *pfnNMI_Handler;
    void *pfnHardFault_Handler;
    void *pfnReservedM12;
    void *pfnReservedM11;
    void *pfnReservedM10;
    void *pfnReservedM9;
    void *pfnReservedM8;
    void *pfnReservedM7;
    void *pfnReservedM6;
    void *pfnSVC_Handler;
    void *pfnReservedM4;
    void *pfnReservedM3;
    void *pfnPendSV_Handler;
    void *pfnSysTick_Handler;
} cm_vector_table_t;

typedef struct fkb_header_t {
    uint8_t signature[4];
    uint32_t version;
    uint32_t header_size;
    uint32_t flags;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t bss_size;
} fkb_header_t;

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

extern uint32_t __StackTop;

__attribute__ ((section(".isr_vector")))
const struct cm_vector_table_t vector_table = {
  .pvStack               = (void *)(&__StackTop),
  .pfnReset_Handler      = (void *)main,
  .pfnNMI_Handler        = (void *)cm_dummy_handler,
  .pfnHardFault_Handler  = (void *)cm_dummy_handler,
  .pfnReservedM12        = (void *)(0UL), /* Reserved */
  .pfnReservedM11        = (void *)(0UL), /* Reserved */
  .pfnReservedM10        = (void *)(0UL), /* Reserved */
  .pfnReservedM9         = (void *)(0UL), /* Reserved */
  .pfnReservedM8         = (void *)(0UL), /* Reserved */
  .pfnReservedM7         = (void *)(0UL), /* Reserved */
  .pfnReservedM6         = (void *)(0UL), /* Reserved */
  .pfnSVC_Handler        = (void *)cm_dummy_handler,
  .pfnReservedM4         = (void *)(0UL), /* Reserved */
  .pfnReservedM3         = (void *)(0UL), /* Reserved */
  .pfnPendSV_Handler     = (void *)cm_dummy_handler,
  .pfnSysTick_Handler    = (void *)cm_dummy_handler,
};
