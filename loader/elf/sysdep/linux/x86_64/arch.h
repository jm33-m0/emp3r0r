void jump_start(void* init, void* exit_func, void* entry)
{
    register long rsp __asm__("rsp") = (long)init;
    register long rdx __asm__("rdx") = (long)exit_func;

    __asm__ __volatile__(
        "jmp *%0\n"
        :
        : "r"(entry), "r"(rsp), "r"(rdx)
        :);
}
