#include <stdio.h>
#include <stdlib.h>

enum {
    SIGINVIS = 31,
    SIGSUPER = 64,
    SIGMODINVIS = 63,
};

const char* HIDE_ME = "emp";
int SHM_FD = 0;
