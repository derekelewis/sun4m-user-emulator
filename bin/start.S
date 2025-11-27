/* start.S */
.global _start

_start:
    /* * SPARC V8 Application Binary Interface (ABI) note:
     * The kernel/emulator initializes %sp (stack pointer).
     * We just need to call main.
     */
    call    kernel_main     ! Call C function
    nop                     ! Delay slot (executed before the call takes effect)

    /* Exit system call */
    mov     %o0, %o0        ! Move return value from main (in %o0) to arg0
    mov     1, %g1          ! Syscall number 1 = exit (Linux SPARC)
    ta      0x10            ! Trap to kernel (Software Interrupt)
