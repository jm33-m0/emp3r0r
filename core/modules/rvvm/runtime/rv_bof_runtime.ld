/*
 * rv_bof_runtime.ld — link the guest BOF runtime at a fixed address above the
 * BOF's own image.
 *
 * Layout in guest RAM:
 *   0x80000000  BOF object sections (max 512 KiB)
 *   0x80080000  this runtime (code, data, 1 MiB heap)
 *   0x801ff000  host-call mailbox
 *   0x80800000  stack top
 */

ENTRY(rv_bof_invoke)

SECTIONS
{
  . = 0x80080000;

  .text : {
    *(.text.entry)
    *(.text*)
  }

  .rodata : {
    *(.rodata*)
    *(.srodata*)
  }

  .data : {
    *(.data*)
    *(.sdata*)
  }

  .bss : {
    *(.bss*)
    *(.sbss*)
    *(COMMON)
  }

  /DISCARD/ : {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
    *(.riscv.attributes)
    *(.debug*)
  }
}
