#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    void* handle = dlopen("./loader.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    printf("hello from test");
    return 0;
}
