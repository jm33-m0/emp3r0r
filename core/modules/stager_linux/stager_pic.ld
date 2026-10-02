/* Tight section packing for lld (zig cc), which does not implement GNU ld's
 * --nmagic/--omagic. objcopy extracts .init/.text/.rodata/.data in vaddr order,
 * so .init (holding _start) has to be placed first and the sections must follow
 * without page-alignment gaps. The stage load address is supplied separately via
 * --image-base by the Makefile.
 *
 * Segments are assigned explicitly: if .text (RX) and .rodata (R) land in the
 * same page, the kernel applies both mappings and the read-only one wins,
 * dropping execute and faulting on the first instruction. .rodata is therefore
 * folded into the executable segment (it only holds the XOR-encoded config and
 * the encrypted downloader blob). A separate RW segment carries any .data/.bss
 * a future stage may grow. */
PHDRS {
  text PT_LOAD FLAGS(5); /* PF_R | PF_X */
  data PT_LOAD FLAGS(6); /* PF_R | PF_W */
}

SECTIONS {
  .init   : { *(.init) } :text
  .text   : { *(.text) *(.text.*) } :text
  .rodata : { *(.rodata) *(.rodata.*) } :text
  .data   : { *(.data) *(.data.*) } :data
  .bss    : { *(.bss) *(.bss.*) *(COMMON) } :data
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
