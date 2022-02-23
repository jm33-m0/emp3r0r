// Keep *BSD toolchains happy
char *environ;
char *__progname;

struct ps_strings { 
	char	**ps_argvstr;   /* first of 0 or more argument strings */ 
	int	ps_nargvstr;    /* the number of argument strings */
	char	**ps_envstr;    /* first of 0 or more environment strings */
	int	ps_nenvstr;     /* the number of environment strings */
}; 

void jump_start(long *init, void *exit_func, void *entry)
{
	int argc = *init;
	int envc = 0;

	char **argv = &init[1];
	char **env = &init[1+argc+1];
	
	// Place the ps_strings struct inside the reserved area on the stack
	struct ps_strings *p = init - 0x1000;

	// Count envs
	while(env[envc])
		envc++;

	p->ps_argvstr = argv;
	p->ps_nargvstr = argc;

	p->ps_envstr = env;
	p->ps_nenvstr = envc;
		
	register long rax __asm__("rax") = entry;
	register long rsp __asm__("rsp") = init;
	register long rbx __asm__("rbx") = p;
	__asm__ __volatile__(
		"jmp %0\n"
		:
		: "r" (rax), "r" (rsp), "r" (rbx)
		:
	);
}


