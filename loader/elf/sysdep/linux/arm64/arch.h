void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("sp") = (long) init;
	register long x0 __asm__("x0") = (long) exit_func;

	__asm__ __volatile__(
		"blr %0;\n"
		:
		: "r" (entry), "r" (sp), "r" (x0)
		:
	);
}

