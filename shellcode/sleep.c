/*
 * This program is used to check shellcode injection
 * */

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    time_t rawtime;
    struct tm* timeinfo;

    while (1) {
        sleep(1);
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        printf("%s: sleeping", asctime(timeinfo));
    }
    return 0;
}
