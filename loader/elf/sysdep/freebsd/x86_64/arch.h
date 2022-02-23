// Keep *BSD toolchains happy
char *environ;
char *__progname;

void jump_start(void *init, void *exit_func, void *entry)
{
	register long rsp __asm__("rsp") = init;
	register long rdx __asm__("rdx") = 0;

	__asm__ __volatile__(
		"jmp *(%0)\n"
		:
		: "r" (entry), "r" (rsp), "r" (rdx)
		:
	);
}


