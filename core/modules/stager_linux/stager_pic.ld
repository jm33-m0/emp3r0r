/* Tight section packing for lld (zig cc), which does not implement GNU ld's
 * --nmagic/--omagic. objcopy extracts .init/.text/.rodata/.data in vaddr order,
 * so .init (holding _start) has to be placed first and the sections must follow
 * without page-alignment gaps. The stage load address is supplied separately via
 * --image-base by the Makefile. */
SECTIONS {
  .init   : { *(.init) }
  .text   : { *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
  .data   : { *(.data) *(.data.*) }
  .bss    : { *(.bss) *(.bss.*) *(COMMON) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
