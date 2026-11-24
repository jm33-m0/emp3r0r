/* Place everything we need in a single output .text section so we can extract
 * it as a flat blob with `zig objcopy -O binary -j .text`.
 *
 * Keep the msda header at the very end so the payload can be appended directly
 * after it with no additional metadata scanning at runtime.
 */

ENTRY(_start)

SECTIONS
{
  .text : {
    /* Force the entrypoint to the beginning of the extracted blob. */
    *(.text._start)

    /* Everything else (helpers + embedded strings). */
    *(.text*)

    /* Compiler-generated constants (jump tables, etc). */
    *(.rodata*)

    /* Must be last. */
    *(.msda)
  }
}
