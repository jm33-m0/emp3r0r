ENTRY(_start)
SECTIONS {
  . = 0x80080000;
  /* Argument handoff reserved by the guest entry shim; see main.c. The
   * interpreter finds it by section name and writes the argument pointer and
   * length before starting the guest. */
  .rvhdr : { *(.rvhdr) }
  .text : { *(.text*) }
  .rodata : { *(.rodata*) *(.eh_frame*) *(.eh_frame_hdr) }
  .tdata : { *(.tdata*) }
  .data : { *(.data*) }
  .tbss : { *(.tbss*) }
  .bss : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.debug*) *(.comment) *(.riscv.attributes) }
}
