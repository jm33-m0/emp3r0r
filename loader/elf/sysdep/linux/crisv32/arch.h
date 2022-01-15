void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("sp") = (long)init;

	__asm__ __volatile__(
		"move %1, $srp;\n"
		"jump %0;\n"
		"nop;\n"
		:
		: "r" (entry), "r" (exit_func), "r" (sp)
		:
	);

}

