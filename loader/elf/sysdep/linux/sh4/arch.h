void jump_start(void *init, void *exit_func, void *entry)
{
	register long r4 __asm__("r4") = (long) exit_func;
	register long r3 __asm__("r3") = (long) entry;
	register long sp __asm__("r15") = (long) init;

	__asm__ __volatile__(
		"jsr @%0;\n"
		"nop;\n"
		:
		: "r" (r3), "r" (r4), "r" (sp)
		:
	);
}

