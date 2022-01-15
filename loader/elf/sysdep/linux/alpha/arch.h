void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("30") = (long)init;
	register long v0 __asm__("0") = (long)exit_func;

	__asm__ __volatile__(
		"jmp (%0);\n"
		:
		: "r" (entry), "r" (v0), "r" (sp)
		:
	);

}

