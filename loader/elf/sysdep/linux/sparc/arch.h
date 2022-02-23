void jump_start(void *init, void *exit_func, void *entry)
{
	register long g1 __asm__("g1") = (long)exit_func;
	register long sp __asm__("sp") = (long)(init - 16 * 4);

	__asm__ __volatile__(
			"jmp %0\n"
			"nop;\n"
		:
		: "r" (entry), "r" (g1), "r" (sp)
		:
	);
}

