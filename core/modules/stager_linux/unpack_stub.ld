/* Pack the stub's sections tightly (no alignment gaps) so objcopy extraction
 * preserves the exact vaddr layout that RIP-relative references expect. */
SECTIONS {
  . = 0;
  .init   : { *(.init) }
  .text   : { *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
  .data   : { *(.data) *(.data.*) }
  /DISCARD/ : { *(*) }
}
