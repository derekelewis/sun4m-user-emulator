#include "sun4m/syscall.hpp"
#include "sun4m/cpu.hpp"
#include "sun4m/endian.hpp"

#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <dirent.h>
#include <utime.h>
#include <sys/sysmacros.h>

namespace sun4m {

// SPARC Linux syscall numbers (prefixed to avoid conflicts with host macros)
constexpr int SPARC_SYS_exit = 1;
constexpr int SPARC_SYS_read = 3;
constexpr int SPARC_SYS_write = 4;
constexpr int SPARC_SYS_open = 5;
constexpr int SPARC_SYS_close = 6;
constexpr int SPARC_SYS_unlink = 10;
constexpr int SPARC_SYS_chdir = 12;
constexpr int SPARC_SYS_brk = 17;
constexpr int SPARC_SYS_lseek = 19;
constexpr int SPARC_SYS_access = 33;
constexpr int SPARC_SYS_stat = 38;
constexpr int SPARC_SYS_getuid = 44;
constexpr int SPARC_SYS_getgid = 47;
constexpr int SPARC_SYS_geteuid = 49;
constexpr int SPARC_SYS_getegid = 50;
constexpr int SPARC_SYS_getgid32 = 53;  // 32-bit version, same as getgid
constexpr int SPARC_SYS_ioctl = 54;
constexpr int SPARC_SYS_mmap2 = 56;
constexpr int SPARC_SYS_umask = 60;
constexpr int SPARC_SYS_fstat = 62;
constexpr int SPARC_SYS_mmap = 71;
constexpr int SPARC_SYS_munmap = 73;
constexpr int SPARC_SYS_mprotect = 74;
constexpr int SPARC_SYS_lstat = 84;
constexpr int SPARC_SYS_setuid = 87;
constexpr int SPARC_SYS_setgid = 89;
constexpr int SPARC_SYS_dup2 = 90;
constexpr int SPARC_SYS_rt_sigaction = 102;
constexpr int SPARC_SYS_rt_sigprocmask = 103;
constexpr int SPARC_SYS_fchmod = 124;
constexpr int SPARC_SYS_mkdir = 136;
constexpr int SPARC_SYS_sendfile64 = 140;
constexpr int SPARC_SYS_poll = 153;
constexpr int SPARC_SYS_getdents64 = 154;
constexpr int SPARC_SYS_set_tid_address = 166;
constexpr int SPARC_SYS_exit_group = 188;
constexpr int SPARC_SYS_readlink = 85;
constexpr int SPARC_SYS_stat64 = 215;
constexpr int SPARC_SYS_fstat64 = 28;
constexpr int SPARC_SYS_llseek = 236;
constexpr int SPARC_SYS_openat = 284;
constexpr int SPARC_SYS_readlinkat = 294;
constexpr int SPARC_SYS_set_robust_list = 300;
constexpr int SPARC_SYS_prlimit64 = 331;
constexpr int SPARC_SYS_fchown = 32;
constexpr int SPARC_SYS_chown32 = 35;
constexpr int SPARC_SYS_getrandom = 347;
constexpr int SPARC_SYS_statx = 360;
constexpr int SPARC_SYS_utimensat = 412;

// SPARC termios ioctl numbers (prefixed to avoid conflicts with host macros)
constexpr uint32_t SPARC_TCGETS = 0x40245408;
constexpr uint32_t SPARC_TCSETS = 0x80245409;
constexpr uint32_t SPARC_TCSETSW = 0x8024540A;
constexpr uint32_t SPARC_TCSETSF = 0x8024540B;
constexpr uint32_t SPARC_TIOCGWINSZ = 0x40087468;
constexpr uint32_t SPARC_TIOCSWINSZ = 0x80087467;

Syscall::Syscall(CpuState& cpu) : cpu_(cpu) {}

void Syscall::return_success(uint32_t value) {
    cpu_.registers.write_register(8, value);
    cpu_.icc.c = false;
}

void Syscall::return_error(int errno_val) {
    cpu_.registers.write_register(8, static_cast<uint32_t>(errno_val));
    cpu_.icc.c = true;
}

std::string Syscall::read_string(uint32_t addr, size_t max_len) {
    std::string result;
    result.reserve(256);
    for (size_t i = 0; i < max_len; ++i) {
        auto byte_result = cpu_.memory->read(addr + i, 1);
        if (!byte_result || (*byte_result)[0] == 0) {
            break;
        }
        result.push_back(static_cast<char>((*byte_result)[0]));
    }
    return result;
}

void Syscall::handle() {
    uint32_t syscall_num = cpu_.registers.read_register(1);  // %g1

    switch (syscall_num) {
        case SPARC_SYS_exit: syscall_exit(); break;
        case SPARC_SYS_read: syscall_read(); break;
        case SPARC_SYS_write: syscall_write(); break;
        case SPARC_SYS_open: syscall_open(); break;
        case SPARC_SYS_close: syscall_close(); break;
        case SPARC_SYS_brk: syscall_brk(); break;
        case SPARC_SYS_lseek: syscall_lseek(); break;
        case SPARC_SYS_llseek: syscall_llseek(); break;
        case SPARC_SYS_ioctl: syscall_ioctl(); break;
        case SPARC_SYS_mmap: syscall_mmap(); break;
        case SPARC_SYS_mmap2: syscall_mmap2(); break;
        case SPARC_SYS_munmap: syscall_munmap(); break;
        case SPARC_SYS_mprotect: syscall_mprotect(); break;
        case SPARC_SYS_stat64: syscall_stat64(); break;
        case SPARC_SYS_stat: syscall_stat64(); break;  // stat uses same impl as stat64
        case SPARC_SYS_fstat64: syscall_fstat64(); break;
        case SPARC_SYS_fstat: syscall_fstat64(); break;  // fstat uses same impl as fstat64
        case SPARC_SYS_lstat: syscall_lstat64(); break;
        case SPARC_SYS_access: syscall_access(); break;
        case SPARC_SYS_getdents64: syscall_getdents64(); break;
        case SPARC_SYS_poll: syscall_poll(); break;
        case SPARC_SYS_getrandom: syscall_getrandom(); break;
        case SPARC_SYS_dup2: syscall_dup2(); break;
        case SPARC_SYS_openat: syscall_openat(); break;
        case SPARC_SYS_readlink: syscall_readlink(); break;
        case SPARC_SYS_readlinkat: syscall_readlinkat(); break;
        case SPARC_SYS_mkdir: syscall_mkdir(); break;
        case SPARC_SYS_fchmod: syscall_fchmod(); break;
        case SPARC_SYS_sendfile64: syscall_sendfile64(); break;
        case SPARC_SYS_unlink: syscall_unlink(); break;
        case SPARC_SYS_chdir: syscall_chdir(); break;
        case SPARC_SYS_getuid: syscall_getuid(); break;
        case SPARC_SYS_getgid: syscall_getgid(); break;
        case SPARC_SYS_getgid32: syscall_getgid(); break;  // 32-bit version
        case SPARC_SYS_geteuid: syscall_geteuid(); break;
        case SPARC_SYS_getegid: syscall_getegid(); break;
        case SPARC_SYS_setuid: syscall_setuid(); break;
        case SPARC_SYS_setgid: syscall_setgid(); break;
        case SPARC_SYS_umask: syscall_umask(); break;
        case SPARC_SYS_exit_group: syscall_exit_group(); break;
        case SPARC_SYS_set_tid_address: syscall_set_tid_address(); break;
        case SPARC_SYS_set_robust_list: syscall_set_robust_list(); break;
        case SPARC_SYS_rt_sigaction: syscall_rt_sigaction(); break;
        case SPARC_SYS_rt_sigprocmask: syscall_rt_sigprocmask(); break;
        case SPARC_SYS_prlimit64: syscall_prlimit64(); break;
        case SPARC_SYS_fchown: syscall_fchown(); break;
        case SPARC_SYS_chown32: syscall_chown(); break;
        case SPARC_SYS_statx: syscall_statx(); break;
        case SPARC_SYS_utimensat: syscall_utimensat(); break;
        default:
            std::cerr << "Unimplemented syscall: " << syscall_num << "\n";
            return_error(38);  // ENOSYS
    }
}

void Syscall::syscall_exit() {
    uint32_t code = cpu_.registers.read_register(8);  // %o0
    cpu_.halted = true;
    cpu_.exit_code = static_cast<int>(code);
}

void Syscall::syscall_exit_group() {
    syscall_exit();
}

void Syscall::syscall_read() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t buf_ptr = cpu_.registers.read_register(9);
    uint32_t count = cpu_.registers.read_register(10);

    auto result = cpu_.fd_table.read(fd, count);
    if (!result) {
        return_error(-result.error());
    } else {
        if (!result->empty()) {
            (void)cpu_.memory->write(buf_ptr, *result);
        }
        return_success(static_cast<uint32_t>(result->size()));
    }
}

void Syscall::syscall_write() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t buf_ptr = cpu_.registers.read_register(9);
    uint32_t count = cpu_.registers.read_register(10);

    auto data_result = cpu_.memory->read(buf_ptr, count);
    if (!data_result) {
        return_error(14);  // EFAULT
        return;
    }

    auto result = cpu_.fd_table.write(fd, *data_result);
    if (!result) {
        return_error(-result.error());
    } else {
        return_success(static_cast<uint32_t>(*result));
    }
}

void Syscall::syscall_open() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    int flags = static_cast<int>(cpu_.registers.read_register(9));
    int mode = static_cast<int>(cpu_.registers.read_register(10));

    std::string path = read_string(path_ptr);
    int result = cpu_.fd_table.open(path, flags, mode);
    if (result < 0) {
        return_error(-result);
    } else {
        return_success(static_cast<uint32_t>(result));
    }
}

void Syscall::syscall_close() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    int result = cpu_.fd_table.close(fd);
    if (result < 0) {
        return_error(-result);
    } else {
        return_success(0);
    }
}

void Syscall::syscall_brk() {
    uint32_t new_brk = cpu_.registers.read_register(8);

    if (new_brk == 0) {
        return_success(cpu_.brk);
        return;
    }

    if (new_brk > cpu_.brk) {
        uint32_t size = new_brk - cpu_.brk;
        cpu_.memory->allocate_at(cpu_.brk, size, Prot::Read | Prot::Write, "heap");
    }
    cpu_.brk = new_brk;
    return_success(cpu_.brk);
}

void Syscall::syscall_lseek() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    int32_t offset = static_cast<int32_t>(cpu_.registers.read_register(9));
    int whence = static_cast<int>(cpu_.registers.read_register(10));

    auto result = cpu_.fd_table.lseek(fd, offset, whence);
    if (!result) {
        return_error(-result.error());
    } else {
        return_success(static_cast<uint32_t>(*result));
    }
}

void Syscall::syscall_llseek() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t offset_high = cpu_.registers.read_register(9);
    uint32_t offset_low = cpu_.registers.read_register(10);
    uint32_t result_ptr = cpu_.registers.read_register(11);
    int whence = static_cast<int>(cpu_.registers.read_register(12));

    int64_t offset = (static_cast<int64_t>(offset_high) << 32) | offset_low;
    auto result = cpu_.fd_table.lseek(fd, offset, whence);
    if (!result) {
        return_error(-result.error());
    } else {
        std::array<uint8_t, 8> buf;
        write_be64(buf, static_cast<uint64_t>(*result));
        (void)cpu_.memory->write(result_ptr, buf);
        return_success(0);
    }
}

void Syscall::syscall_ioctl() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t request = cpu_.registers.read_register(9);
    uint32_t arg = cpu_.registers.read_register(10);

    // Only handle terminal ioctls on stdin/stdout/stderr
    if (fd > 2) {
        return_error(25);  // ENOTTY
        return;
    }

    switch (request) {
        case SPARC_TCGETS: {
            // Get terminal attributes from host and write as SPARC termios
            std::array<uint8_t, 36> buf{};
            if (::isatty(fd)) {
                struct termios host_termios;
                if (::tcgetattr(fd, &host_termios) == 0) {
                    write_be32({buf.data() + 0, 4}, host_termios.c_iflag);
                    write_be32({buf.data() + 4, 4}, host_termios.c_oflag);
                    write_be32({buf.data() + 8, 4}, host_termios.c_cflag);
                    write_be32({buf.data() + 12, 4}, host_termios.c_lflag);
                    buf[16] = 0;  // c_line
                    // Copy c_cc with translation from host to SPARC indices
                    // SPARC has 17 c_cc entries, host (Linux) has 32
                    // Key difference: VMIN is at index 6 on host, index 4 on SPARC (shared with VEOF)
                    // VEOL is at index 11 on host, index 5 on SPARC
                    for (int i = 0; i < 17; ++i) {
                        buf[17 + i] = 0;
                    }
                    // Direct mappings (same index on both)
                    buf[17 + 0] = host_termios.c_cc[VINTR];
                    buf[17 + 1] = host_termios.c_cc[VQUIT];
                    buf[17 + 2] = host_termios.c_cc[VERASE];
                    buf[17 + 3] = host_termios.c_cc[VKILL];
                    buf[17 + 8] = host_termios.c_cc[VSTART];
                    buf[17 + 9] = host_termios.c_cc[VSTOP];
                    buf[17 + 10] = host_termios.c_cc[VSUSP];
                    buf[17 + 12] = host_termios.c_cc[VREPRINT];
                    buf[17 + 13] = host_termios.c_cc[VDISCARD];
                    buf[17 + 14] = host_termios.c_cc[VWERASE];
                    buf[17 + 15] = host_termios.c_cc[VLNEXT];
                    // SPARC index 4/5 depend on canonical mode
                    if (!(host_termios.c_lflag & ICANON)) {
                        // Non-canonical: VMIN/VTIME at indices 4/5
                        buf[17 + 4] = host_termios.c_cc[VMIN];
                        buf[17 + 5] = host_termios.c_cc[VTIME];
                    } else {
                        // Canonical: VEOF/VEOL at indices 4/5
                        buf[17 + 4] = host_termios.c_cc[VEOF];
                        buf[17 + 5] = host_termios.c_cc[VEOL];
                    }
                    (void)cpu_.memory->write(arg, buf);
                    return_success(0);
                    return;
                }
            }
            // Return defaults if not a tty or tcgetattr failed
            write_be32({buf.data() + 0, 4}, 0x2D02);   // c_iflag
            write_be32({buf.data() + 4, 4}, 0x0005);   // c_oflag
            write_be32({buf.data() + 8, 4}, 0x00BF);   // c_cflag
            write_be32({buf.data() + 12, 4}, 0x8A3B);  // c_lflag
            (void)cpu_.memory->write(arg, buf);
            return_success(0);
            break;
        }
        case SPARC_TCSETS:
        case SPARC_TCSETSW:
        case SPARC_TCSETSF: {
            // Read SPARC termios and apply to host
            if (::isatty(fd)) {
                auto sparc_buf = cpu_.memory->read(arg, 36);
                if (sparc_buf) {
                    struct termios host_termios;
                    if (::tcgetattr(fd, &host_termios) == 0) {
                        host_termios.c_iflag = read_be32({sparc_buf->data() + 0, 4});
                        host_termios.c_oflag = read_be32({sparc_buf->data() + 4, 4});
                        host_termios.c_cflag = read_be32({sparc_buf->data() + 8, 4});
                        host_termios.c_lflag = read_be32({sparc_buf->data() + 12, 4});
                        // Translate c_cc from SPARC to host indices
                        host_termios.c_cc[VINTR] = (*sparc_buf)[17 + 0];
                        host_termios.c_cc[VQUIT] = (*sparc_buf)[17 + 1];
                        host_termios.c_cc[VERASE] = (*sparc_buf)[17 + 2];
                        host_termios.c_cc[VKILL] = (*sparc_buf)[17 + 3];
                        host_termios.c_cc[VSTART] = (*sparc_buf)[17 + 8];
                        host_termios.c_cc[VSTOP] = (*sparc_buf)[17 + 9];
                        host_termios.c_cc[VSUSP] = (*sparc_buf)[17 + 10];
                        host_termios.c_cc[VREPRINT] = (*sparc_buf)[17 + 12];
                        host_termios.c_cc[VDISCARD] = (*sparc_buf)[17 + 13];
                        host_termios.c_cc[VWERASE] = (*sparc_buf)[17 + 14];
                        host_termios.c_cc[VLNEXT] = (*sparc_buf)[17 + 15];
                        // Handle VMIN/VTIME vs VEOF/VEOL based on mode
                        if (!(host_termios.c_lflag & ICANON)) {
                            // Non-canonical: SPARC 4/5 are VMIN/VTIME
                            host_termios.c_cc[VMIN] = (*sparc_buf)[17 + 4];
                            host_termios.c_cc[VTIME] = (*sparc_buf)[17 + 5];
                        } else {
                            // Canonical: SPARC 4/5 are VEOF/VEOL
                            host_termios.c_cc[VEOF] = (*sparc_buf)[17 + 4];
                            host_termios.c_cc[VEOL] = (*sparc_buf)[17 + 5];
                        }
                        int when = TCSANOW;
                        if (request == SPARC_TCSETSW) when = TCSADRAIN;
                        else if (request == SPARC_TCSETSF) when = TCSAFLUSH;
                        (void)::tcsetattr(fd, when, &host_termios);
                    }
                }
            }
            return_success(0);
            break;
        }
        case SPARC_TIOCGWINSZ: {
            // Try to get real window size from host terminal
            std::array<uint8_t, 8> buf{};
            if (::isatty(fd)) {
                struct winsize ws;
                if (::ioctl(fd, TIOCGWINSZ, &ws) == 0) {
                    write_be16({buf.data() + 0, 2}, ws.ws_row);
                    write_be16({buf.data() + 2, 2}, ws.ws_col);
                    write_be16({buf.data() + 4, 2}, ws.ws_xpixel);
                    write_be16({buf.data() + 6, 2}, ws.ws_ypixel);
                    (void)cpu_.memory->write(arg, buf);
                    return_success(0);
                    return;
                }
            }
            // Try stored window size
            if (cpu_.window_size) {
                auto [rows, cols, xpix, ypix] = *cpu_.window_size;
                write_be16({buf.data() + 0, 2}, rows);
                write_be16({buf.data() + 2, 2}, cols);
                write_be16({buf.data() + 4, 2}, xpix);
                write_be16({buf.data() + 6, 2}, ypix);
            } else {
                // Default 24x80
                write_be16({buf.data() + 0, 2}, 24);
                write_be16({buf.data() + 2, 2}, 80);
            }
            (void)cpu_.memory->write(arg, buf);
            return_success(0);
            break;
        }
        case SPARC_TIOCSWINSZ: {
            // Store window size
            auto buf = cpu_.memory->read(arg, 8);
            if (buf) {
                uint16_t rows = read_be16({buf->data() + 0, 2});
                uint16_t cols = read_be16({buf->data() + 2, 2});
                uint16_t xpix = read_be16({buf->data() + 4, 2});
                uint16_t ypix = read_be16({buf->data() + 6, 2});
                cpu_.window_size = {rows, cols, xpix, ypix};
            }
            return_success(0);
            break;
        }
        default:
            return_error(25);  // ENOTTY
    }
}

void Syscall::do_mmap(uint32_t addr, uint32_t length, uint32_t prot,
                      uint32_t flags, int fd, uint64_t offset) {
    constexpr uint32_t SPARC_MAP_FIXED = 0x10;
    constexpr uint32_t SPARC_MAP_ANONYMOUS = 0x20;

    bool fixed = (flags & SPARC_MAP_FIXED) != 0;
    bool anonymous = (flags & SPARC_MAP_ANONYMOUS) != 0;

    Prot cpp_prot = Prot::None;
    if (prot & 0x1) cpp_prot |= Prot::Read;
    if (prot & 0x2) cpp_prot |= Prot::Write;
    if (prot & 0x4) cpp_prot |= Prot::Exec;

    if (anonymous || fd < 0) {
        auto* seg = cpu_.memory->allocate_at(addr, length, cpp_prot, "mmap", fixed);
        if (seg) {
            return_success(seg->start);
        } else {
            return_error(12);  // ENOMEM
        }
    } else {
        // File-backed mapping
        auto* file_desc = cpu_.fd_table.get(fd);
        if (!file_desc) {
            return_error(9);  // EBADF
            return;
        }
        auto* seg = cpu_.memory->allocate_at(addr, length, cpp_prot, "mmap", fixed);
        if (!seg) {
            return_error(12);  // ENOMEM
            return;
        }
        // Save current position, seek to offset, read, restore position
        auto orig_pos = cpu_.fd_table.lseek(fd, 0, SEEK_CUR);  // Get current position
        if (orig_pos) {
            (void)cpu_.fd_table.lseek(fd, static_cast<int64_t>(offset), SEEK_SET);
            auto data = cpu_.fd_table.read(fd, length);
            if (data && !data->empty()) {
                std::copy(data->begin(), data->end(), seg->buffer.begin());
            }
            (void)cpu_.fd_table.lseek(fd, *orig_pos, SEEK_SET);  // Restore position
        }
        return_success(seg->start);
    }
}

void Syscall::syscall_mmap() {
    uint32_t addr = cpu_.registers.read_register(8);
    uint32_t length = cpu_.registers.read_register(9);
    uint32_t prot = cpu_.registers.read_register(10);
    uint32_t flags = cpu_.registers.read_register(11);
    int fd = static_cast<int>(cpu_.registers.read_register(12));
    uint32_t offset = cpu_.registers.read_register(13);
    do_mmap(addr, length, prot, flags, fd, offset);
}

void Syscall::syscall_mmap2() {
    uint32_t addr = cpu_.registers.read_register(8);
    uint32_t length = cpu_.registers.read_register(9);
    uint32_t prot = cpu_.registers.read_register(10);
    uint32_t flags = cpu_.registers.read_register(11);
    int fd = static_cast<int>(cpu_.registers.read_register(12));
    uint32_t pgoffset = cpu_.registers.read_register(13);
    do_mmap(addr, length, prot, flags, fd, static_cast<uint64_t>(pgoffset) * 4096);
}

void Syscall::syscall_munmap() {
    uint32_t addr = cpu_.registers.read_register(8);
    uint32_t length = cpu_.registers.read_register(9);
    cpu_.memory->remove_segment_range(addr, length);
    return_success(0);
}

void Syscall::syscall_mprotect() {
    uint32_t addr = cpu_.registers.read_register(8);
    uint32_t length = cpu_.registers.read_register(9);
    uint32_t prot = cpu_.registers.read_register(10);

    Prot cpp_prot = Prot::None;
    if (prot & 0x1) cpp_prot |= Prot::Read;
    if (prot & 0x2) cpp_prot |= Prot::Write;
    if (prot & 0x4) cpp_prot |= Prot::Exec;

    cpu_.memory->set_permissions(addr, length, cpp_prot);
    return_success(0);
}

void Syscall::write_stat64(uint32_t addr, const struct ::stat& st) {
    std::array<uint8_t, 104> buf{};

    // SPARC stat64 structure (big-endian)
    write_be64({buf.data() + 0x00, 8}, st.st_dev);
    write_be32({buf.data() + 0x0C, 4}, static_cast<uint32_t>(st.st_ino));
    write_be32({buf.data() + 0x10, 4}, st.st_mode);
    write_be32({buf.data() + 0x14, 4}, st.st_nlink);
    write_be32({buf.data() + 0x18, 4}, st.st_uid);
    write_be32({buf.data() + 0x1C, 4}, st.st_gid);
    write_be64({buf.data() + 0x20, 8}, st.st_rdev);
    write_be64({buf.data() + 0x30, 8}, st.st_size);
    write_be32({buf.data() + 0x38, 4}, static_cast<uint32_t>(st.st_blksize));
    write_be64({buf.data() + 0x40, 8}, st.st_blocks);
    write_be32({buf.data() + 0x48, 4}, static_cast<uint32_t>(st.st_atime));
    write_be32({buf.data() + 0x50, 4}, static_cast<uint32_t>(st.st_mtime));
    write_be32({buf.data() + 0x58, 4}, static_cast<uint32_t>(st.st_ctime));

    (void)cpu_.memory->write(addr, buf);
}

void Syscall::syscall_stat64() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    uint32_t buf_ptr = cpu_.registers.read_register(9);

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    struct ::stat st;
    if (::stat(host_path.c_str(), &st) < 0) {
        return_error(errno);
    } else {
        write_stat64(buf_ptr, st);
        return_success(0);
    }
}

void Syscall::syscall_fstat64() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t buf_ptr = cpu_.registers.read_register(9);

    auto* desc = cpu_.fd_table.get(fd);
    if (!desc) {
        return_error(9);  // EBADF
        return;
    }

    struct ::stat st{};
    if (desc->is_special) {
        // Use fstat on actual host fd for stdin/stdout/stderr
        if (::fstat(desc->host_fd, &st) < 0) {
            // Fallback to dummy data if fstat fails (e.g., pipe)
            st.st_mode = S_IFCHR | 0666;
            st.st_rdev = 0x8800 + fd;  // Character device
        }
    } else if (desc->host_fd >= 0) {
        // Use the actual host fd
        if (::fstat(desc->host_fd, &st) < 0) {
            return_error(errno);
            return;
        }
    } else {
        return_error(9);  // EBADF
        return;
    }

    write_stat64(buf_ptr, st);
    return_success(0);
}

void Syscall::syscall_lstat64() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    uint32_t buf_ptr = cpu_.registers.read_register(9);

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    struct ::stat st;
    if (::lstat(host_path.c_str(), &st) < 0) {
        return_error(errno);
    } else {
        write_stat64(buf_ptr, st);
        return_success(0);
    }
}

void Syscall::syscall_access() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    int mode = static_cast<int>(cpu_.registers.read_register(9));

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    if (::access(host_path.c_str(), mode) < 0) {
        return_error(errno);
    } else {
        return_success(0);
    }
}

void Syscall::syscall_getdents64() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t dirp = cpu_.registers.read_register(9);
    uint32_t count = cpu_.registers.read_register(10);

    auto* desc = cpu_.fd_table.get(fd);
    if (!desc || !desc->is_directory || desc->host_fd < 0) {
        return_error(9);  // EBADF
        return;
    }

    // Use getdents64 on the underlying directory fd
    std::vector<uint8_t> buf(count);
    ssize_t nread = syscall(SYS_getdents64, desc->host_fd, buf.data(), count);

    if (nread < 0) {
        return_error(errno);
    } else if (nread > 0) {
        (void)cpu_.memory->write(dirp, {buf.data(), static_cast<size_t>(nread)});
        return_success(static_cast<uint32_t>(nread));
    } else {
        return_success(0);
    }
}

void Syscall::syscall_poll() {
    uint32_t fds_ptr = cpu_.registers.read_register(8);
    uint32_t nfds = cpu_.registers.read_register(9);
    int timeout = static_cast<int>(cpu_.registers.read_register(10));

    if (nfds == 0) {
        return_success(0);
        return;
    }

    // Read pollfd structures (8 bytes each: 4-byte fd, 2-byte events, 2-byte revents)
    auto fds_data = cpu_.memory->read(fds_ptr, nfds * 8);
    if (!fds_data) {
        return_error(14);  // EFAULT
        return;
    }

    std::vector<struct pollfd> host_fds(nfds);
    for (uint32_t i = 0; i < nfds; ++i) {
        uint32_t guest_fd = read_be32({fds_data->data() + i * 8, 4});
        uint16_t events = read_be16({fds_data->data() + i * 8 + 4, 2});

        // Translate guest fd to host fd
        auto* desc = cpu_.fd_table.get(static_cast<int>(guest_fd));
        if (desc && desc->host_fd >= 0) {
            host_fds[i].fd = desc->host_fd;
        } else {
            host_fds[i].fd = -1;  // Invalid - poll will return POLLNVAL
        }
        host_fds[i].events = events;
        host_fds[i].revents = 0;
    }

    int result = ::poll(host_fds.data(), nfds, timeout);

    if (result < 0) {
        return_error(errno);
    } else {
        // Write back revents
        for (uint32_t i = 0; i < nfds; ++i) {
            std::array<uint8_t, 2> revents_buf;
            write_be16(revents_buf, host_fds[i].revents);
            (void)cpu_.memory->write(fds_ptr + i * 8 + 6, revents_buf);
        }
        return_success(static_cast<uint32_t>(result));
    }
}

void Syscall::syscall_getrandom() {
    uint32_t buf_ptr = cpu_.registers.read_register(8);
    uint32_t count = cpu_.registers.read_register(9);

    std::vector<uint8_t> buf(count);

    // Use /dev/urandom for cryptographically secure random bytes
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char*>(buf.data()), count);
        size_t bytes_read = urandom.gcount();
        if (bytes_read > 0) {
            (void)cpu_.memory->write(buf_ptr, {buf.data(), bytes_read});
            return_success(static_cast<uint32_t>(bytes_read));
            return;
        }
    }

    // Fallback: return error
    return_error(5);  // EIO
}

void Syscall::syscall_dup2() {
    int oldfd = static_cast<int>(cpu_.registers.read_register(8));
    int newfd = static_cast<int>(cpu_.registers.read_register(9));

    int result = cpu_.fd_table.dup2(oldfd, newfd);
    if (result < 0) {
        return_error(-result);
    } else {
        return_success(static_cast<uint32_t>(result));
    }
}

void Syscall::syscall_openat() {
    int dirfd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t path_ptr = cpu_.registers.read_register(9);
    int flags = static_cast<int>(cpu_.registers.read_register(10));
    int mode = static_cast<int>(cpu_.registers.read_register(11));

    std::string path = read_string(path_ptr);

    // For AT_FDCWD (-100), use regular open
    if (dirfd == -100 || path[0] == '/') {
        int result = cpu_.fd_table.open(path, flags, mode);
        if (result < 0) {
            return_error(-result);
        } else {
            return_success(static_cast<uint32_t>(result));
        }
    } else {
        // Relative to dirfd - not fully implemented
        return_error(9);  // EBADF
    }
}

void Syscall::syscall_readlink() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    uint32_t buf_ptr = cpu_.registers.read_register(9);
    uint32_t bufsiz = cpu_.registers.read_register(10);

    std::string path = read_string(path_ptr);

    // Handle /proc/self/exe
    if (path == "/proc/self/exe") {
        if (!cpu_.exe_path.empty()) {
            size_t len = std::min(static_cast<size_t>(bufsiz), cpu_.exe_path.size());
            std::vector<uint8_t> buf(cpu_.exe_path.begin(), cpu_.exe_path.begin() + len);
            (void)cpu_.memory->write(buf_ptr, buf);
            return_success(static_cast<uint32_t>(len));
            return;
        }
    }

    std::string host_path = cpu_.fd_table.translate_path(path);
    std::vector<char> buf(bufsiz);
    ssize_t len = ::readlink(host_path.c_str(), buf.data(), bufsiz);

    if (len < 0) {
        return_error(errno);
    } else {
        std::vector<uint8_t> result(buf.begin(), buf.begin() + len);
        (void)cpu_.memory->write(buf_ptr, result);
        return_success(static_cast<uint32_t>(len));
    }
}

void Syscall::syscall_readlinkat() {
    int dirfd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t path_ptr = cpu_.registers.read_register(9);
    uint32_t buf_ptr = cpu_.registers.read_register(10);
    uint32_t bufsiz = cpu_.registers.read_register(11);

    std::string path = read_string(path_ptr);

    // Handle AT_FDCWD (-100) and absolute paths
    constexpr int SPARC_AT_FDCWD = -100;
    if (dirfd != SPARC_AT_FDCWD && !path.empty() && path[0] != '/') {
        return_error(9);  // EBADF - relative paths with dirfd not supported
        return;
    }

    // Handle /proc/self/exe
    if (path == "/proc/self/exe") {
        if (!cpu_.exe_path.empty()) {
            size_t len = std::min(static_cast<size_t>(bufsiz), cpu_.exe_path.size());
            std::vector<uint8_t> buf(cpu_.exe_path.begin(), cpu_.exe_path.begin() + len);
            (void)cpu_.memory->write(buf_ptr, buf);
            return_success(static_cast<uint32_t>(len));
            return;
        }
        return_error(2);  // ENOENT
        return;
    }

    std::string host_path = cpu_.fd_table.translate_path(path);
    std::vector<char> buf(bufsiz);
    ssize_t len = ::readlink(host_path.c_str(), buf.data(), bufsiz);

    if (len < 0) {
        return_error(errno);
    } else {
        std::vector<uint8_t> result(buf.begin(), buf.begin() + len);
        (void)cpu_.memory->write(buf_ptr, result);
        return_success(static_cast<uint32_t>(len));
    }
}

void Syscall::syscall_mkdir() {
    uint32_t path_ptr = cpu_.registers.read_register(8);
    int mode = static_cast<int>(cpu_.registers.read_register(9));

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    if (::mkdir(host_path.c_str(), mode) < 0) {
        return_error(errno);
    } else {
        return_success(0);
    }
}

void Syscall::syscall_fchmod() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    mode_t mode = static_cast<mode_t>(cpu_.registers.read_register(9));

    auto* desc = cpu_.fd_table.get(fd);
    if (!desc) {
        return_error(9);  // EBADF
        return;
    }

    if (desc->host_fd >= 0) {
        if (::fchmod(desc->host_fd, mode) < 0) {
            return_error(errno);
            return;
        }
    } else {
        return_error(9);  // EBADF
        return;
    }

    return_success(0);
}

void Syscall::syscall_sendfile64() {
    int out_fd = static_cast<int>(cpu_.registers.read_register(8));
    int in_fd = static_cast<int>(cpu_.registers.read_register(9));
    uint32_t offset_ptr = cpu_.registers.read_register(10);
    uint32_t count = cpu_.registers.read_register(11);

    auto* in_desc = cpu_.fd_table.get(in_fd);
    auto* out_desc = cpu_.fd_table.get(out_fd);

    if (!in_desc || !out_desc || in_desc->host_fd < 0 || out_desc->host_fd < 0) {
        return_error(9);  // EBADF
        return;
    }

    off_t offset = 0;
    off_t* offset_p = nullptr;

    if (offset_ptr != 0) {
        // Read 64-bit offset from memory (big-endian)
        auto offset_data = cpu_.memory->read(offset_ptr, 8);
        if (!offset_data) {
            return_error(14);  // EFAULT
            return;
        }
        offset = static_cast<off_t>(read_be64({offset_data->data(), 8}));
        offset_p = &offset;
    }

    ssize_t result = ::sendfile(out_desc->host_fd, in_desc->host_fd, offset_p, count);

    if (result < 0) {
        return_error(errno);
    } else {
        // Update offset in memory if provided
        if (offset_ptr != 0) {
            std::array<uint8_t, 8> buf;
            write_be64(buf, static_cast<uint64_t>(offset));
            (void)cpu_.memory->write(offset_ptr, buf);
        }
        return_success(static_cast<uint32_t>(result));
    }
}

void Syscall::syscall_unlink() {
    uint32_t path_ptr = cpu_.registers.read_register(8);

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    if (::unlink(host_path.c_str()) < 0) {
        return_error(errno);
    } else {
        return_success(0);
    }
}

void Syscall::syscall_chdir() {
    uint32_t path_ptr = cpu_.registers.read_register(8);

    std::string path = read_string(path_ptr);
    std::string host_path = cpu_.fd_table.translate_path(path);

    if (::chdir(host_path.c_str()) < 0) {
        return_error(errno);
    } else {
        return_success(0);
    }
}

void Syscall::syscall_getuid() { return_success(::getuid()); }
void Syscall::syscall_getgid() { return_success(::getgid()); }
void Syscall::syscall_geteuid() { return_success(::geteuid()); }
void Syscall::syscall_getegid() { return_success(::getegid()); }

void Syscall::syscall_setuid() {
    // Stub - return success
    return_success(0);
}

void Syscall::syscall_setgid() {
    // Stub - return success
    return_success(0);
}

void Syscall::syscall_umask() {
    int mask = static_cast<int>(cpu_.registers.read_register(8));
    int old_mask = ::umask(mask);
    return_success(static_cast<uint32_t>(old_mask));
}

void Syscall::syscall_set_tid_address() {
    // Stub - return a fake TID
    return_success(1000);
}

void Syscall::syscall_set_robust_list() {
    // Stub - return success for single-threaded programs
    return_success(0);
}

void Syscall::syscall_rt_sigaction() {
    // Stub - ignore signal handling
    return_success(0);
}

void Syscall::syscall_rt_sigprocmask() {
    // Stub - ignore signal mask
    return_success(0);
}

void Syscall::syscall_prlimit64() {
    // Stub - return success
    uint32_t new_limit_ptr = cpu_.registers.read_register(10);
    uint32_t old_limit_ptr = cpu_.registers.read_register(11);

    if (old_limit_ptr != 0) {
        // Write some reasonable defaults
        std::array<uint8_t, 16> buf{};
        write_be64({buf.data(), 8}, RLIM_INFINITY);
        write_be64({buf.data() + 8, 8}, RLIM_INFINITY);
        (void)cpu_.memory->write(old_limit_ptr, buf);
    }
    (void)new_limit_ptr;  // Ignore new limit
    return_success(0);
}

void Syscall::syscall_fchown() {
    int fd = static_cast<int>(cpu_.registers.read_register(8));
    // owner = registers[9], group = registers[10] - ignored

    auto* desc = cpu_.fd_table.get(fd);
    if (!desc) {
        return_error(9);  // EBADF
        return;
    }

    // Stub: just return success - we don't actually change ownership
    return_success(0);
}

void Syscall::syscall_chown() {
    // pathname = registers[8], owner = registers[9], group = registers[10]
    // Stub: just return success - we don't actually change ownership
    return_success(0);
}

void Syscall::write_statx(uint32_t addr, const struct ::stat& st) {
    // struct statx layout (256 bytes, big-endian for SPARC)
    std::array<uint8_t, 256> buf{};

    constexpr uint32_t STX_BASIC_STATS = 0x7ff;

    // stx_mask (4 bytes at 0x00)
    write_be32({buf.data() + 0x00, 4}, STX_BASIC_STATS);
    // stx_blksize (4 bytes at 0x04)
    write_be32({buf.data() + 0x04, 4}, static_cast<uint32_t>(st.st_blksize));
    // stx_attributes (8 bytes at 0x08)
    write_be64({buf.data() + 0x08, 8}, 0);
    // stx_nlink (4 bytes at 0x10)
    write_be32({buf.data() + 0x10, 4}, static_cast<uint32_t>(st.st_nlink));
    // stx_uid (4 bytes at 0x14)
    write_be32({buf.data() + 0x14, 4}, st.st_uid);
    // stx_gid (4 bytes at 0x18)
    write_be32({buf.data() + 0x18, 4}, st.st_gid);
    // stx_mode (2 bytes at 0x1c)
    write_be16({buf.data() + 0x1c, 2}, static_cast<uint16_t>(st.st_mode));
    // padding (2 bytes at 0x1e) - already zero
    // stx_ino (8 bytes at 0x20)
    write_be64({buf.data() + 0x20, 8}, st.st_ino);
    // stx_size (8 bytes at 0x28)
    write_be64({buf.data() + 0x28, 8}, static_cast<uint64_t>(st.st_size));
    // stx_blocks (8 bytes at 0x30)
    write_be64({buf.data() + 0x30, 8}, static_cast<uint64_t>(st.st_blocks));
    // stx_attributes_mask (8 bytes at 0x38)
    write_be64({buf.data() + 0x38, 8}, 0);
    // stx_atime (tv_sec 8 bytes at 0x40, tv_nsec 4 bytes at 0x48, pad 4 at 0x4c)
    write_be64({buf.data() + 0x40, 8}, static_cast<uint64_t>(st.st_atime));
    write_be32({buf.data() + 0x48, 4}, 0);  // nsec
    // stx_btime (birth time - use mtime as fallback) at 0x50
    write_be64({buf.data() + 0x50, 8}, static_cast<uint64_t>(st.st_mtime));
    write_be32({buf.data() + 0x58, 4}, 0);  // nsec
    // stx_ctime at 0x60
    write_be64({buf.data() + 0x60, 8}, static_cast<uint64_t>(st.st_ctime));
    write_be32({buf.data() + 0x68, 4}, 0);  // nsec
    // stx_mtime at 0x70
    write_be64({buf.data() + 0x70, 8}, static_cast<uint64_t>(st.st_mtime));
    write_be32({buf.data() + 0x78, 4}, 0);  // nsec
    // stx_rdev_major (4 bytes at 0x80), stx_rdev_minor (4 bytes at 0x84)
    write_be32({buf.data() + 0x80, 4}, major(st.st_rdev));
    write_be32({buf.data() + 0x84, 4}, minor(st.st_rdev));
    // stx_dev_major (4 bytes at 0x88), stx_dev_minor (4 bytes at 0x8c)
    write_be32({buf.data() + 0x88, 4}, major(st.st_dev));
    write_be32({buf.data() + 0x8c, 4}, minor(st.st_dev));

    (void)cpu_.memory->write(addr, buf);
}

void Syscall::syscall_statx() {
    constexpr int SPARC_AT_FDCWD = -100;
    constexpr uint32_t SPARC_AT_EMPTY_PATH = 0x1000;

    int dirfd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t pathname_ptr = cpu_.registers.read_register(9);
    uint32_t flags = cpu_.registers.read_register(10);
    // uint32_t mask = cpu_.registers.read_register(11);  // ignored
    uint32_t statxbuf = cpu_.registers.read_register(12);

    std::string pathname = read_string(pathname_ptr);
    struct ::stat st{};

    // Handle AT_EMPTY_PATH with fd - stat the fd directly
    if ((flags & SPARC_AT_EMPTY_PATH) && (pathname.empty() || pathname_ptr == 0)) {
        auto* desc = cpu_.fd_table.get(dirfd);
        if (!desc) {
            return_error(9);  // EBADF
            return;
        }
        if (desc->host_fd >= 0) {
            if (::fstat(desc->host_fd, &st) < 0) {
                return_error(errno);
                return;
            }
        } else {
            return_error(9);  // EBADF
            return;
        }
    } else if (dirfd == SPARC_AT_FDCWD || (!pathname.empty() && pathname[0] == '/')) {
        // Normal path-based stat
        std::string host_path = cpu_.fd_table.translate_path(pathname);
        if (::stat(host_path.c_str(), &st) < 0) {
            return_error(errno);
            return;
        }
    } else {
        // Relative path with dirfd - try path directly for now
        std::string host_path = cpu_.fd_table.translate_path(pathname);
        if (::stat(host_path.c_str(), &st) < 0) {
            return_error(errno);
            return;
        }
    }

    write_statx(statxbuf, st);
    return_success(0);
}

void Syscall::syscall_utimensat() {
    constexpr int SPARC_AT_FDCWD = -100;

    int dirfd = static_cast<int>(cpu_.registers.read_register(8));
    uint32_t pathname_ptr = cpu_.registers.read_register(9);
    // uint32_t times_ptr = cpu_.registers.read_register(10);  // ignored for now
    // uint32_t flags = cpu_.registers.read_register(11);      // ignored for now

    // If pathname is NULL/empty, operate on dirfd directly
    if (pathname_ptr == 0) {
        // Operating on fd directly - just return success
        // A full implementation would set the timestamps
        return_success(0);
        return;
    }

    std::string pathname = read_string(pathname_ptr);
    std::string host_path;

    if (dirfd == SPARC_AT_FDCWD || (!pathname.empty() && pathname[0] == '/')) {
        host_path = cpu_.fd_table.translate_path(pathname);
    } else {
        // Relative path with dirfd - use path directly for now
        host_path = pathname;
    }

    // Touch the file to update timestamps (simplified - ignores times array)
    if (::utime(host_path.c_str(), nullptr) < 0) {
        return_error(errno);
    } else {
        return_success(0);
    }
}

} // namespace sun4m
