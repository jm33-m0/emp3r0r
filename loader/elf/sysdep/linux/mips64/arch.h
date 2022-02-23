void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("sp") = (long) init;
	register long v0 __asm__("v0") = (long) exit_func;

	__asm__ __volatile__(
		"j %0;\n"
		:
		: "r" (entry), "r" (sp), "r" (v0)
		:
	);
}

