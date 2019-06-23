/**
 *
 *
 *
 */
#include <loading.h>
#include <cortex.h>
#include <string.h>

extern void memory_initialize(void);
extern void board_initialize(void);

extern uint32_t __cm_app_vectors_ptr;

void delay(uint32_t ms);

uint32_t launch() {
    debug_println("bl: looking for executable...");

    /* Look for FKB headers... */
    if (fkb_find_and_launch((void *)&__cm_app_vectors_ptr)) {
        return 0;
    }

    /* Fall back on a regular old firmware launch */
    return fkb_try_launch(&__cm_app_vectors_ptr, 0);
}

uint32_t main() {
    memory_initialize();

    SEGGER_RTT_Init();

    debug_println("");
    debug_println("bl: starting!");

    SysTick_Config(F_CPU / 1000);

    board_initialize();

    debug_println("bl: board ready");

    launch();

    /* If we're here then no launching occurred! */

    debug_println("bl: delay before trying again.");

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

volatile uint32_t system_ticks = 0;

void cm_systick() {
    system_ticks++;
}

void delay(uint32_t ms) {
    uint32_t end = system_ticks + ms;
    while (system_ticks < end) {
        /* yield */
    }
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
