/*
 * This program is used to check shellcode injection
 * */

#include <stdio.h>
#include <string.h>
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
        char* timestr = asctime(timeinfo);
        timestr[strlen(timestr) - 1] = '\0';

        printf("%s: sleeping\n", timestr);
    }
    return 0;
}
