/* Pack the stub's sections tightly (no alignment gaps) so objcopy extraction
 * preserves the exact vaddr layout that RIP-relative references expect.
 * .unpack_header is read-only and comes last so the packed payload appended
 * after the stub sits immediately after the header (`h + 1`).
 *
 * Only non-alloc sections are discarded: lld refuses to drop required sections
 * such as .shstrtab (which objcopy does not emit into the flat binary), and
 * listing the discardable ones explicitly works for GNU ld as well. */
SECTIONS {
  . = 0;
  .init   : { *(.init) }
  .text   : { *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
  .unpack_header : { *(.unpack_header) }
  /DISCARD/ : {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
    *(.debug*)
    *(.symtab)
    *(.strtab)
  }
}
