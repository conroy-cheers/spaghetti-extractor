OUTPUT_FORMAT(binary)
ENTRY(_start)
SECTIONS
{
  . = 0x7c00;
  .text : { *(.text) }
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
