/**
 *
 *
 *
 *
 *
 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x00004000
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00008000
}

ENTRY(main)

SECTIONS
{
  .vectors ALIGN(0x2000) :
  {
    KEEP(*(.isr_vector))
  } > FLASH

  .text ALIGN(0x4) :
  {
    *(.text*)
		*(.rodata*)

    /* These are usually zero in this situation, eliminates warnings, though. */
    *(.glue_7)
    *(.glue_7t)
    *(.vfp11_veneer)
    *(.v4_bx)
    *(.dyn)
    *(.iplt)
    *(.rel.dyn)
    *(.rel.iplt)
  } > FLASH

  .ARM.extab :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } > FLASH

  __exidx_start = .;
  .ARM.exidx :
  {
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } > FLASH
  __exidx_end = .;

	__etext = .;

	.data : AT (__etext)
	{
    __data_start__ = .;
    *(.data*)
    . = ALIGN(4);
    __data_end__ = .;
  } > RAM

  .bss :
  {
    . = ALIGN(4);
    __bss_start__ = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end__ = .;
  } > RAM

	.heap (COPY):
	{
    __end__ = .;
    PROVIDE(end = .);
    *(.heap*)
    __heap_top = .;
	} > RAM

	.stack (COPY):
	{
    *(.stack*)
	} > RAM

  PROVIDE(__cm_app_vectors_ptr = ORIGIN(FLASH) + LENGTH(FLASH));

  __cm_ram_end__ = ORIGIN(RAM) + LENGTH(RAM) -1 ;
  __cm_stack_top = ORIGIN(RAM) + LENGTH(RAM);
  __cm_stack_max = __cm_stack_top - SIZEOF(.stack);

	ASSERT(__cm_stack_max >= __heap_top, "Region RAM overflowed with stack")
}
