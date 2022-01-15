void jump_start(void *init, void *exit_func, void *entry)
{
	register long sp __asm__("r1") = (long) init;
	register long r5 __asm__("r5") = (long) entry;

	__asm__ __volatile__(
		"bra %0;\n"
		:
		: "r" (r5), "r" (sp)
		:
	);
}

