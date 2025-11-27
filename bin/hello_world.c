/* hello.c */

/* Direct wrapper for the 'write' syscall */
void my_print(const char *str, int len) {
    /* * Syscall 4 = write
     * Arguments: 
     * %o0 = file descriptor (1 = stdout)
     * %o1 = buffer pointer
     * %o2 = length
     * %g1 = syscall number
     */
    asm volatile (
        "mov 1, %%o0\n\t"        /* fd = stdout */
        "mov %0, %%o1\n\t"       /* buf = str */
        "mov %1, %%o2\n\t"       /* len = len */
        "mov 4, %%g1\n\t"        /* syscall #4 (write) */
        "ta  0x10\n\t"           /* trap to kernel */
        : /* no outputs */
        : "r" (str), "r" (len)
        : "o0", "o1", "o2", "g1" /* clobbered registers */
    );
}

int kernel_main() {
    my_print("Hello, world!\n", 14);
    return 0; // Returns to %o0, which start.S uses as exit code
}
