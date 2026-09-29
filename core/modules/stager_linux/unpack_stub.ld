/* Pack the stub's sections tightly (no alignment gaps) so objcopy extraction
 * preserves the exact vaddr layout that RIP-relative references expect.
 * .unpack_header is read-only and comes last so the packed payload appended
 * after the stub sits immediately after the header (`h + 1`). */
SECTIONS {
  . = 0;
  .init   : { *(.init) }
  .text   : { *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
  .unpack_header : { *(.unpack_header) }
  /DISCARD/ : { *(*) }
}
