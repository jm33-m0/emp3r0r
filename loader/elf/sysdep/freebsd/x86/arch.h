// Keep *BSD toolchains happy
char *environ;
char *__progname;

void jump_start(void *init, void *exit_func, void *entry)
{
	register long esp __asm__("esp") = init;
	register long edx __asm__("edx") = 0;

	__asm__ __volatile__(
		"jmp *(%0)\n"
		:
		: "r" (entry), "r" (esp), "r" (edx)
		:
	);
}

