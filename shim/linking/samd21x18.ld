/**
 *
 *
 *
 *
 *
 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x00040000 - 0x2000
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00008000
}

/* If I leave this out, nothing ends up in the file, even with KEEP. I think if
 * you're missing any .text or executable code then everything is dropped. */
ENTRY(main)

SECTIONS
{
  .shim_vectors :
  {
    KEEP(*(.shim_isr_vector))
  } > FLASH

  .text.shim :
  {
    KEEP(*(.shim_text))
  } > FLASH

  .text : ALIGN(0x4)
  {
    KEEP(*(.text))
  } > FLASH

  __cm_shim_stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
