void jump_start(void *init, void *exit_func, void *entry)
{
	register long r3 __asm__("3") = 0;
	register long r4 __asm__("4") = (long) entry;
	register long sp __asm__("sp") = (long) init;

	__asm__ __volatile__(
		"mtlr %0;\n"
		"blr;\n"
		:
		: "r" (r4), "r" (sp), "r" (r3)
		:
	);
}

