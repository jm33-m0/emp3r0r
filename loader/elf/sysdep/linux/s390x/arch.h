void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("r15") = (long) init;
	register long r0 __asm__("r0") = (long) exit_func;

	__asm__ __volatile__(
		"br %0;\n"
		:
		: "r" (entry), "r" (r0), "r" (sp)
		:
	);
}

