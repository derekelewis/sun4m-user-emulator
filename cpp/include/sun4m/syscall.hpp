#pragma once

#include <cstdint>
#include <string>
#include <sys/stat.h>

namespace sun4m {

// Forward declaration
class CpuState;

/// Handles Linux syscalls for the emulated SPARC process.
///
/// Syscall calling convention:
/// - Syscall number in %g1 (register 1)
/// - Arguments in %o0-%o5 (registers 8-13)
/// - Return value in %o0 (register 8)
/// - Carry flag (ICC.c) indicates error:
///   - Success: carry clear, %o0 = result
///   - Error: carry set, %o0 = errno (positive value)
class Syscall {
public:
    explicit Syscall(CpuState& cpu);

    /// Dispatch and handle the current syscall.
    void handle();

private:
    CpuState& cpu_;

    /// Return success with value in %o0, clear carry.
    void return_success(uint32_t value);

    /// Return error with errno in %o0, set carry.
    void return_error(int errno_val);

    /// Read a null-terminated string from guest memory.
    [[nodiscard]] std::string read_string(uint32_t addr, size_t max_len = 4096);

    // Syscall implementations
    void syscall_exit();
    void syscall_read();
    void syscall_write();
    void syscall_open();
    void syscall_close();
    void syscall_brk();
    void syscall_lseek();
    void syscall_llseek();
    void syscall_ioctl();
    void syscall_mmap();
    void syscall_mmap2();
    void syscall_munmap();
    void syscall_mprotect();
    void syscall_stat64();
    void syscall_fstat64();
    void syscall_lstat64();
    void syscall_access();
    void syscall_getdents64();
    void syscall_poll();
    void syscall_getrandom();
    void syscall_dup2();
    void syscall_openat();
    void syscall_readlink();
    void syscall_readlinkat();
    void syscall_mkdir();
    void syscall_fchmod();
    void syscall_sendfile64();
    void syscall_unlink();
    void syscall_chdir();
    void syscall_getuid();
    void syscall_getgid();
    void syscall_geteuid();
    void syscall_getegid();
    void syscall_setuid();
    void syscall_setgid();
    void syscall_umask();
    void syscall_exit_group();
    void syscall_set_tid_address();
    void syscall_set_robust_list();
    void syscall_rt_sigaction();
    void syscall_rt_sigprocmask();
    void syscall_prlimit64();
    void syscall_fchown();
    void syscall_chown();
    void syscall_statx();
    void syscall_utimensat();

    // Helper for mmap
    void do_mmap(uint32_t addr, uint32_t length, uint32_t prot,
                 uint32_t flags, int fd, uint64_t offset);

    // Structure writers
    void write_stat64(uint32_t addr, const struct ::stat& st);
    void write_statx(uint32_t addr, const struct ::stat& st);
};

} // namespace sun4m
