from __future__ import annotations

import fcntl
import os
import select
import stat
import struct
import sys
import termios
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sun4m.cpu import CpuState

# SPARC/Linux errno values
ENOENT = 2  # No such file or directory
EBADF = 9  # Bad file descriptor
EACCES = 13  # Permission denied
EFAULT = 14  # Bad address
ENOTDIR = 20  # Not a directory
EISDIR = 21  # Is a directory
EINVAL = 22  # Invalid argument
ENOTTY = 25  # Not a typewriter (inappropriate ioctl for device)
ESPIPE = 29  # Illegal seek
ENOSYS = 38  # Function not implemented

# Page size for memory alignment
PAGE_SIZE = 4096

# Heap region configuration for brk syscall
# Starts at 256MB to avoid conflicts with PIE executables
HEAP_START = 0x10000000
HEAP_SIZE = 0x20000000  # 512MB

# Linux open flags (SPARC uses same values as generic Linux)
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 0x40
O_EXCL = 0x80
O_NOCTTY = 0x100
O_TRUNC = 0x200
O_APPEND = 0x400
O_NONBLOCK = 0x800
O_DIRECTORY = 0x10000
O_CLOEXEC = 0x80000

# AT_* constants for openat
AT_FDCWD = -100

# poll event flags
POLLIN = 0x0001
POLLPRI = 0x0002
POLLOUT = 0x0004
POLLERR = 0x0008
POLLHUP = 0x0010
POLLNVAL = 0x0020

# SPARC terminal ioctl codes
TCGETS = 0x40245408
TCSETS = 0x80245409
TCSETSW = 0x8024540A
TCSETSF = 0x8024540B
TIOCGWINSZ = 0x40087468
TIOCSWINSZ = 0x80087467

# Default termios flags for a typical cooked mode terminal
# These match standard Linux terminal defaults
TERMIOS_DEFAULT_IFLAG = 0x2D02  # ICRNL | IXON | IXOFF | IMAXBEL
TERMIOS_DEFAULT_OFLAG = 0x0005  # OPOST | ONLCR
TERMIOS_DEFAULT_CFLAG = 0x00BF  # CS8 | CREAD | CLOCAL
TERMIOS_DEFAULT_LFLAG = 0x8A3B  # ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN

# Termios c_lflag constants
ICANON = 0x2  # Canonical mode (line-buffered input)

# mmap flags
MAP_SHARED = 0x01
MAP_PRIVATE = 0x02
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x20
MAP_DENYWRITE = 0x800
MAP_EXECUTABLE = 0x1000

# mmap protection (matching memory.py)
PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

# lseek whence values
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2


class Syscall:

    def __init__(self, cpu_state: CpuState):
        self.cpu_state = cpu_state

    def _return_success(self, value: int) -> None:
        """Return success from syscall: clear carry, set %o0 to value."""
        self.cpu_state.registers.write_register(8, value & 0xFFFFFFFF)
        self.cpu_state.icc.c = False

    def _return_error(self, errno: int) -> None:
        """Return error from syscall: set carry, set %o0 to positive errno."""
        self.cpu_state.registers.write_register(8, errno & 0xFFFFFFFF)
        self.cpu_state.icc.c = True

    def _get_host_fd(self, guest_fd: int) -> int | None:
        """Map a guest file descriptor to its corresponding host file descriptor.

        Returns the host fd, or None if the guest fd is invalid or has no
        host equivalent (e.g., a closed or unsupported descriptor).
        """
        desc = self.cpu_state.fd_table.get(guest_fd)
        if desc is None:
            return None
        if desc.is_special:
            return guest_fd  # stdin/stdout/stderr map directly
        if desc.file is not None:
            return desc.file.fileno()
        if desc.is_directory and desc.dir_fd is not None:
            return desc.dir_fd
        return None

    def handle(self):
        # Get syscall number from %g1
        syscall_number: int = self.cpu_state.registers.read_register(1)

        match syscall_number:
            case 1:
                self._syscall_exit()
            case 3:
                self._syscall_read()
            case 4:
                self._syscall_write()
            case 5:
                self._syscall_open()
            case 6:
                self._syscall_close()
            case 10:
                self._syscall_unlink()
            case 12:
                self._syscall_chdir()
            case 17:
                self._syscall_brk()
            case 19:
                self._syscall_lseek()
            case 28:
                self._syscall_fstat64()
            case 32:
                self._syscall_fchown()
            case 33:
                self._syscall_access()
            case 35:
                self._syscall_chown()  # chown32
            case 38:
                self._syscall_stat()
            case 44:
                self._syscall_getuid()
            case 47:
                self._syscall_getgid()
            case 49:
                self._syscall_geteuid()
            case 50:
                self._syscall_getegid()
            case 53:
                self._syscall_getgid()  # getgid32 - same as getgid
            case 54:
                self._syscall_ioctl()
            case 60:
                self._syscall_umask()
            case 56:
                self._syscall_mmap2()  # SPARC 32-bit mmap2
            case 62:
                self._syscall_fstat()  # fstat (old version, same as fstat64)
            case 71:
                self._syscall_mmap()
            case 73:
                self._syscall_munmap()  # SPARC 32-bit munmap
            case 74:
                self._syscall_mprotect()  # SPARC mprotect
            case 84:
                self._syscall_lstat()
            case 85:
                self._syscall_readlink()
            case 87:
                self._syscall_setuid()  # setuid32
            case 89:
                self._syscall_setgid()  # setgid32
            case 90:
                self._syscall_dup2()
            case 102:
                self._syscall_rt_sigaction()
            case 103:
                self._syscall_rt_sigprocmask()
            case 124:
                self._syscall_fchmod()
            case 136:
                self._syscall_mkdir()
            case 140:
                self._syscall_sendfile64()
            case 153:
                self._syscall_poll()
            case 154:
                self._syscall_getdents64()
            case 188:
                self._syscall_exit()  # exit_group - same as exit for single-threaded
            case 215:
                self._syscall_stat64()
            case 236:
                self._syscall_llseek()
            case 284:
                self._syscall_openat()
            case 166:
                self._syscall_set_tid_address()
            case 294:
                self._syscall_readlinkat()
            case 300:
                self._syscall_set_robust_list()
            case 331:
                self._syscall_prlimit64()
            case 347:
                self._syscall_getrandom()
            case 360:
                self._syscall_statx()
            case 412:
                self._syscall_utimensat()
            case _:
                raise ValueError(f"syscall {syscall_number} not implemented")

    def _syscall_exit(self):
        """
        Exit syscall implementation
        Arguments:
          %o0 (reg 8) = exit code
        """
        exit_code = self.cpu_state.registers.read_register(8)
        self.cpu_state.exit_code = exit_code
        self.cpu_state.halted = True

    def _syscall_read(self):
        """
        Read syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = buffer pointer
          %o2 (reg 10) = count
        Returns:
          %o0 = number of bytes read, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        count = self.cpu_state.registers.read_register(10)

        result = self.cpu_state.fd_table.read(fd, count)
        if isinstance(result, int):
            # Negative value indicates error
            self._return_error(-result)
        else:
            if result:
                self.cpu_state.memory.write(buf_ptr, result)
            self._return_success(len(result))

    def _syscall_close(self):
        """
        Close syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        result = self.cpu_state.fd_table.close(fd)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(0)

    def _syscall_write(self):
        """
        Write syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = buffer pointer
          %o2 (reg 10) = length
        Returns:
          %o0 = number of bytes written, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        length = self.cpu_state.registers.read_register(10)

        data = self.cpu_state.memory.read(buf_ptr, length)
        result = self.cpu_state.fd_table.write(fd, data)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(result)

    def _syscall_brk(self):
        """
        brk syscall implementation

        Arguments:
          %o0 (reg 8) = new break address (0 = query current)
        Returns:
          %o0 = current break address, carry clear on success

        The heap starts at HEAP_START (256MB) to avoid conflicts with PIE
        executables and has a maximum size of HEAP_SIZE (512MB).
        """
        new_brk = self.cpu_state.registers.read_register(8)

        # Initialize brk if not set
        if self.cpu_state.brk == 0:
            self.cpu_state.brk = HEAP_START
            # Create a large heap segment
            self.cpu_state.memory.add_segment(HEAP_START, HEAP_SIZE)

        if new_brk == 0:
            # Query current break
            self._return_success(self.cpu_state.brk)
        elif new_brk > self.cpu_state.brk:
            # Extend the heap
            if new_brk <= HEAP_START + HEAP_SIZE:
                self.cpu_state.brk = new_brk
                self._return_success(self.cpu_state.brk)
            else:
                # Request exceeds heap limit - return current brk (failure)
                self._return_success(self.cpu_state.brk)
        else:
            # Shrink or same - just update and return
            self.cpu_state.brk = new_brk
            self._return_success(self.cpu_state.brk)

    def _syscall_umask(self):
        """
        umask syscall implementation
        Arguments:
          %o0 (reg 8) = new mask
        Returns:
          %o0 = previous mask
        """
        new_mask = self.cpu_state.registers.read_register(8)
        # Actually set the umask and return the old value
        old_mask = os.umask(new_mask & 0o777)
        self._return_success(old_mask)

    def _syscall_ioctl(self):
        """
        ioctl syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = request code
          %o2 (reg 10) = argument
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        request = self.cpu_state.registers.read_register(9)
        arg = self.cpu_state.registers.read_register(10)

        # Handle terminal ioctls for stdin/stdout/stderr
        if fd in (0, 1, 2):
            if request == TCGETS:
                # Get terminal attributes - return defaults or read from host
                if os.isatty(fd):
                    try:
                        attrs = termios.tcgetattr(fd)
                        self._write_sparc_termios(arg, attrs)
                    except termios.error:
                        # Return default termios if we can't get real ones
                        self._write_default_sparc_termios(arg)
                else:
                    self._write_default_sparc_termios(arg)
                self._return_success(0)
            elif request in (TCSETS, TCSETSW, TCSETSF):
                # Set terminal attributes - apply to host if possible
                if os.isatty(fd):
                    try:
                        attrs = self._read_sparc_termios(arg)
                        when = termios.TCSANOW
                        if request == TCSETSW:
                            when = termios.TCSADRAIN
                        elif request == TCSETSF:
                            when = termios.TCSAFLUSH
                        termios.tcsetattr(fd, when, attrs)
                    except (termios.error, OSError, IndexError, struct.error):
                        pass  # Silently ignore errors, vi will still work
                self._return_success(0)
            elif request == TIOCGWINSZ:
                # Get window size
                if os.isatty(fd):
                    try:
                        result = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\x00" * 8)
                        self.cpu_state.memory.write(arg, result)
                        self._return_success(0)
                        return
                    except OSError:
                        pass
                # Return default size
                ws = struct.pack(">HHHH", 24, 80, 0, 0)
                self.cpu_state.memory.write(arg, ws)
                self._return_success(0)
            elif request == TIOCSWINSZ:
                self._return_success(0)
            else:
                # Unknown ioctl - return success for tty fds
                self._return_success(0)
        else:
            self._return_error(ENOTTY)

    def _write_default_sparc_termios(self, addr: int) -> None:
        """Write default termios attributes for a typical terminal."""
        buf = bytearray(36)
        struct.pack_into(">I", buf, 0, TERMIOS_DEFAULT_IFLAG)
        struct.pack_into(">I", buf, 4, TERMIOS_DEFAULT_OFLAG)
        struct.pack_into(">I", buf, 8, TERMIOS_DEFAULT_CFLAG)
        struct.pack_into(">I", buf, 12, TERMIOS_DEFAULT_LFLAG)
        buf[16] = 0  # c_line
        # Default control characters
        cc_defaults = [
            0x03, 0x1C, 0x7F, 0x15, 0x04, 0x00, 0x01, 0x00,
            0x11, 0x13, 0x1A, 0x00, 0x12, 0x0F, 0x17, 0x16, 0x00
        ]
        for i, c in enumerate(cc_defaults):
            buf[17 + i] = c
        self.cpu_state.memory.write(addr, bytes(buf))

    def _write_sparc_termios(self, addr: int, attrs: list) -> None:
        """Write host termios attributes to SPARC termios structure.

        SPARC termios (36 bytes):
          c_iflag: 4 bytes
          c_oflag: 4 bytes
          c_cflag: 4 bytes
          c_lflag: 4 bytes
          c_line:  1 byte
          c_cc:    19 bytes (NCCS=19 on SPARC)
          padding: 4 bytes (to align to 36)
        """
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
        buf = bytearray(36)
        struct.pack_into(">I", buf, 0, iflag)
        struct.pack_into(">I", buf, 4, oflag)
        struct.pack_into(">I", buf, 8, cflag)
        struct.pack_into(">I", buf, 12, lflag)
        buf[16] = 0  # c_line
        # Copy control characters (up to 19)
        for i, c in enumerate(cc[:19]):
            if isinstance(c, int):
                buf[17 + i] = c
            elif isinstance(c, bytes) and len(c) > 0:
                buf[17 + i] = c[0]
        self.cpu_state.memory.write(addr, bytes(buf))

    def _read_sparc_termios(self, addr: int) -> list:
        """Read SPARC termios structure and convert to host format.

        SPARC and x86_64 have different c_cc indices. Key differences:
        - SPARC: VMIN=4, VTIME=5 (non-canonical), VEOF=4, VEOL=5 (canonical)
        - x86_64: VMIN=6, VTIME=5, VEOF=4, VEOL=11
        We need to translate these for raw mode to work correctly.
        """
        data = self.cpu_state.memory.read(addr, 36)
        iflag = struct.unpack(">I", data[0:4])[0]
        oflag = struct.unpack(">I", data[4:8])[0]
        cflag = struct.unpack(">I", data[8:12])[0]
        lflag = struct.unpack(">I", data[12:16])[0]
        # c_line at offset 16
        # c_cc at offset 17, 17 bytes on SPARC (NCCS=17)
        sparc_cc = list(data[17:34])

        # SPARC c_cc indices (from asm-sparc/termbits.h):
        # VINTR=0, VQUIT=1, VERASE=2, VKILL=3, VEOF=4, VEOL=5, VEOL2=6, VSWTC=7
        # VSTART=8, VSTOP=9, VSUSP=10, VDSUSP=11, VREPRINT=12, VDISCARD=13
        # VWERASE=14, VLNEXT=15, VMIN=VEOF=4, VTIME=VEOL=5

        # x86_64 c_cc indices (from bits/termios-c_cc.h):
        # VINTR=0, VQUIT=1, VERASE=2, VKILL=3, VEOF=4, VTIME=5, VMIN=6, VSWTC=7
        # VSTART=8, VSTOP=9, VSUSP=10, VEOL=11, VREPRINT=12, VDISCARD=13
        # VWERASE=14, VLNEXT=15

        # Create host cc array with proper mapping
        host_cc = [0] * 32
        # Direct mappings (same index on both)
        for i in [0, 1, 2, 3, 8, 9, 10, 12, 13, 14, 15]:
            if i < len(sparc_cc):
                host_cc[i] = sparc_cc[i]

        # Check if we're in non-canonical mode (ICANON not set)
        if not (lflag & ICANON):
            # Non-canonical mode: SPARC index 4 is VMIN, index 5 is VTIME
            if len(sparc_cc) > 4:
                host_cc[6] = sparc_cc[4]  # VMIN: SPARC[4] -> x86_64[6]
            if len(sparc_cc) > 5:
                host_cc[5] = sparc_cc[5]  # VTIME: same index
            # Set VEOF to default
            host_cc[4] = 0x04  # Ctrl-D
        else:
            # Canonical mode: index 4 is VEOF, index 5 is VEOL
            if len(sparc_cc) > 4:
                host_cc[4] = sparc_cc[4]  # VEOF
            if len(sparc_cc) > 5:
                host_cc[11] = sparc_cc[5]  # VEOL: SPARC[5] -> x86_64[11]

        # VEOL2 and others
        if len(sparc_cc) > 6:
            host_cc[16] = sparc_cc[6]  # VEOL2
        if len(sparc_cc) > 7:
            host_cc[7] = sparc_cc[7]  # VSWTC

        # Return in termios.tcgetattr format
        return [iflag, oflag, cflag, lflag, termios.B38400, termios.B38400, host_cc]

    def _syscall_getrandom(self):
        """
        getrandom syscall implementation
        Arguments:
          %o0 (reg 8) = buffer pointer
          %o1 (reg 9) = count
          %o2 (reg 10) = flags
        Returns:
          %o0 = number of bytes written, carry clear on success
          %o0 = errno, carry set on error
        """
        buf_ptr = self.cpu_state.registers.read_register(8)
        count = self.cpu_state.registers.read_register(9)
        if buf_ptr == 0 or count == 0:
            # NULL pointer or zero count - return 0
            self._return_success(0)
            return
        # Generate random bytes
        random_bytes = os.urandom(count)
        self.cpu_state.memory.write(buf_ptr, random_bytes)
        self._return_success(count)

    def _read_string(self, addr: int, max_len: int = 4096) -> str:
        """Read a null-terminated string from guest memory."""
        result = bytearray()
        for i in range(max_len):
            byte = self.cpu_state.memory.read(addr + i, 1)
            if byte[0] == 0:
                break
            result.append(byte[0])
        return result.decode("utf-8", errors="replace")

    def _syscall_access(self):
        """
        access syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = mode (F_OK=0, R_OK=4, W_OK=2, X_OK=1)
        Returns:
          %o0 = 0 on success, carry clear
          %o0 = errno, carry set on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        mode = self.cpu_state.registers.read_register(9)

        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        # Check if path exists first (os.access returns False for non-existent)
        if not os.path.exists(host_path):
            self._return_error(ENOENT)
            return

        # Now check the requested permissions
        if os.access(host_path, mode):
            self._return_success(0)
        else:
            self._return_error(EACCES)

    def _syscall_open(self):
        """
        open syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = flags
          %o2 (reg 10) = mode
        Returns:
          %o0 = file descriptor, carry clear on success
          %o0 = errno, carry set on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        flags = self.cpu_state.registers.read_register(9)
        mode = self.cpu_state.registers.read_register(10)

        pathname = self._read_string(pathname_ptr)
        result = self.cpu_state.fd_table.open(pathname, flags, mode)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(result)

    def _syscall_openat(self):
        """
        openat syscall implementation
        Arguments:
          %o0 (reg 8) = dirfd (AT_FDCWD for current directory)
          %o1 (reg 9) = pathname pointer
          %o2 (reg 10) = flags
          %o3 (reg 11) = mode
        Returns:
          %o0 = file descriptor, carry clear on success
          %o0 = errno, carry set on error
        """
        dirfd = self.cpu_state.registers.read_register(8)
        pathname_ptr = self.cpu_state.registers.read_register(9)
        flags = self.cpu_state.registers.read_register(10)
        mode = self.cpu_state.registers.read_register(11)

        pathname = self._read_string(pathname_ptr)

        # Handle AT_FDCWD and absolute paths
        # For simplicity, we only support AT_FDCWD (-100) and absolute paths
        if dirfd != (AT_FDCWD & 0xFFFFFFFF) and not pathname.startswith("/"):
            # Relative path with non-AT_FDCWD dirfd - not supported yet
            self._return_error(EBADF)
            return

        result = self.cpu_state.fd_table.open(pathname, flags, mode)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(result)

    def _syscall_lseek(self):
        """
        lseek syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = offset
          %o2 (reg 10) = whence (SEEK_SET=0, SEEK_CUR=1, SEEK_END=2)
        Returns:
          %o0 = new position, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        offset = self.cpu_state.registers.read_register(9)
        # Handle signed offset
        if offset & 0x80000000:
            offset = offset - 0x100000000
        whence = self.cpu_state.registers.read_register(10)

        result = self.cpu_state.fd_table.lseek(fd, offset, whence)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(result & 0xFFFFFFFF)

    def _syscall_llseek(self):
        """
        _llseek syscall implementation (64-bit seek for 32-bit systems)
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = offset high 32 bits
          %o2 (reg 10) = offset low 32 bits
          %o3 (reg 11) = result pointer (for 64-bit result)
          %o4 (reg 12) = whence
        Returns:
          %o0 = 0 on success, -errno on error
          Result written to *result pointer (64-bit)
        """
        fd = self.cpu_state.registers.read_register(8)
        offset_high = self.cpu_state.registers.read_register(9)
        offset_low = self.cpu_state.registers.read_register(10)
        result_ptr = self.cpu_state.registers.read_register(11)
        whence = self.cpu_state.registers.read_register(12)

        # Combine into 64-bit offset
        offset = (offset_high << 32) | offset_low
        # Handle signed offset
        if offset & 0x8000000000000000:
            offset = offset - 0x10000000000000000

        result = self.cpu_state.fd_table.lseek(fd, offset, whence)
        if result < 0:
            self._return_error(-result)
        else:
            # Write 64-bit result to memory
            self.cpu_state.memory.write(
                result_ptr, struct.pack(">Q", result & 0xFFFFFFFFFFFFFFFF)
            )
            self._return_success(0)

    def _syscall_getdents64(self):
        """
        getdents64 syscall implementation - read directory entries
        Arguments:
          %o0 (reg 8) = file descriptor (directory)
          %o1 (reg 9) = buffer pointer
          %o2 (reg 10) = buffer size
        Returns:
          %o0 = number of bytes read on success
          %o0 = 0 on end of directory
          %o0 = errno, carry set on error

        struct linux_dirent64 {
            ino64_t        d_ino;    /* 64-bit inode number */
            off64_t        d_off;    /* 64-bit offset to next structure */
            unsigned short d_reclen; /* Size of this dirent */
            unsigned char  d_type;   /* File type */
            char           d_name[]; /* Filename (null-terminated) */
        };
        """
        fd = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        buf_size = self.cpu_state.registers.read_register(10)

        desc = self.cpu_state.fd_table.get(fd)
        if desc is None:
            self._return_error(EBADF)
            return

        if not desc.is_directory or desc.dir_fd is None:
            self._return_error(EBADF)
            return

        # Use scandir with the host path
        host_path = self.cpu_state.fd_table.translate_path(desc.path)

        try:
            # Get directory entries starting from the current position
            entries = list(os.scandir(host_path))
        except OSError as e:
            self._return_error(e.errno if e.errno else EBADF)
            return

        # Track position in directory (using desc.position as entry index)
        start_idx = desc.position

        if start_idx >= len(entries):
            # End of directory
            self._return_success(0)
            return

        # d_type constants
        DT_UNKNOWN = 0
        DT_FIFO = 1
        DT_CHR = 2
        DT_DIR = 4
        DT_BLK = 6
        DT_REG = 8
        DT_LNK = 10
        DT_SOCK = 12

        buf = bytearray()
        entries_read = 0

        for i in range(start_idx, len(entries)):
            entry = entries[i]

            # Get entry info
            try:
                st = entry.stat(follow_symlinks=False)
                d_ino = st.st_ino
                # Determine d_type from mode
                if stat.S_ISDIR(st.st_mode):
                    d_type = DT_DIR
                elif stat.S_ISREG(st.st_mode):
                    d_type = DT_REG
                elif stat.S_ISLNK(st.st_mode):
                    d_type = DT_LNK
                elif stat.S_ISCHR(st.st_mode):
                    d_type = DT_CHR
                elif stat.S_ISBLK(st.st_mode):
                    d_type = DT_BLK
                elif stat.S_ISFIFO(st.st_mode):
                    d_type = DT_FIFO
                elif stat.S_ISSOCK(st.st_mode):
                    d_type = DT_SOCK
                else:
                    d_type = DT_UNKNOWN
            except OSError:
                d_ino = 0
                d_type = DT_UNKNOWN

            name_bytes = entry.name.encode("utf-8") + b"\x00"

            # Calculate record length (8-byte aligned)
            # d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name
            base_len = 8 + 8 + 2 + 1 + len(name_bytes)
            d_reclen = (base_len + 7) & ~7  # 8-byte align

            # Check if this entry fits in the buffer
            if len(buf) + d_reclen > buf_size:
                if entries_read == 0:
                    # Buffer too small for even one entry
                    self._return_error(EINVAL)
                    return
                break

            # d_off is the offset to the next entry (1-indexed position)
            d_off = i + 1

            # Pack the dirent64 structure (big-endian for SPARC)
            entry_buf = bytearray(d_reclen)
            struct.pack_into(">Q", entry_buf, 0, d_ino)  # d_ino
            struct.pack_into(">Q", entry_buf, 8, d_off)  # d_off
            struct.pack_into(">H", entry_buf, 16, d_reclen)  # d_reclen
            entry_buf[18] = d_type  # d_type
            entry_buf[19 : 19 + len(name_bytes)] = name_bytes  # d_name

            buf.extend(entry_buf)
            entries_read += 1
            desc.position = i + 1

        if len(buf) > 0:
            self.cpu_state.memory.write(buf_ptr, bytes(buf))
            self._return_success(len(buf))
        else:
            self._return_success(0)

    def _syscall_poll(self):
        """
        poll syscall implementation
        Arguments:
          %o0 (reg 8) = fds pointer (array of pollfd structs)
          %o1 (reg 9) = nfds (number of file descriptors)
          %o2 (reg 10) = timeout in milliseconds (-1 = infinite, 0 = return immediately)
        Returns:
          %o0 = number of fds with events, carry clear on success
          %o0 = errno, carry set on error

        struct pollfd {
            int   fd;         /* file descriptor */
            short events;     /* requested events */
            short revents;    /* returned events */
        };  // 8 bytes total on 32-bit
        """
        fds_ptr = self.cpu_state.registers.read_register(8)
        nfds = self.cpu_state.registers.read_register(9)
        timeout = self.cpu_state.registers.read_register(10)
        # Handle signed timeout (-1 = infinite)
        if timeout & 0x80000000:
            timeout = timeout - 0x100000000

        if nfds == 0:
            self._return_success(0)
            return

        # Read pollfd structures (8 bytes each: int fd, short events, short revents)
        read_fds: list[int] = []
        write_fds: list[int] = []
        except_fds: list[int] = []
        fd_to_idx: dict[int, int] = {}  # Map host fd to pollfd index

        for i in range(nfds):
            pollfd_data = self.cpu_state.memory.read(fds_ptr + i * 8, 8)
            fd = struct.unpack(">i", pollfd_data[0:4])[0]
            events = struct.unpack(">h", pollfd_data[4:6])[0]

            if fd < 0:
                continue

            host_fd = self._get_host_fd(fd)
            if host_fd is None:
                continue

            fd_to_idx[host_fd] = i

            if events & (POLLIN | POLLPRI):
                read_fds.append(host_fd)
            if events & POLLOUT:
                write_fds.append(host_fd)
            except_fds.append(host_fd)

        # Convert timeout to seconds for select (None for infinite)
        if timeout < 0:
            timeout_sec = None
        else:
            timeout_sec = timeout / 1000.0

        try:
            readable, writable, exceptional = select.select(
                read_fds, write_fds, except_fds, timeout_sec
            )
        except (OSError, ValueError):
            self._return_error(EBADF)
            return

        # Write revents back to pollfd structures
        count = 0
        for i in range(nfds):
            pollfd_data = self.cpu_state.memory.read(fds_ptr + i * 8, 8)
            fd = struct.unpack(">i", pollfd_data[0:4])[0]

            if fd < 0:
                # Write back with revents = 0
                self.cpu_state.memory.write(fds_ptr + i * 8 + 6, struct.pack(">h", 0))
                continue

            # Find the host fd for this guest fd
            host_fd = self._get_host_fd(fd)
            if host_fd is None:
                # Invalid fd - set POLLNVAL
                self.cpu_state.memory.write(
                    fds_ptr + i * 8 + 6, struct.pack(">h", POLLNVAL)
                )
                count += 1
                continue

            revents = 0
            if host_fd in readable:
                revents |= POLLIN
            if host_fd in writable:
                revents |= POLLOUT
            if host_fd in exceptional:
                revents |= POLLERR

            if revents != 0:
                count += 1

            # Write revents back
            self.cpu_state.memory.write(fds_ptr + i * 8 + 6, struct.pack(">h", revents))

        self._return_success(count)

    def _write_stat64(self, addr: int, st: os.stat_result) -> None:
        """Write a stat64 structure to guest memory.

        SPARC Linux stat64 structure layout (104 bytes):
          0x00: st_dev (8 bytes)
          0x08: padding (4 bytes)
          0x0c: st_ino (8 bytes)
          0x14: st_mode (4 bytes)
          0x18: st_nlink (4 bytes)
          0x1c: st_uid (4 bytes)
          0x20: st_gid (4 bytes)
          0x24: st_rdev (8 bytes)
          0x2c: padding (4 bytes)
          0x30: st_size (8 bytes)
          0x38: st_blksize (4 bytes)
          0x3c: padding (4 bytes)
          0x40: st_blocks (8 bytes)
          0x48: st_atime (4 bytes)
          0x4c: st_atime_nsec (4 bytes)
          0x50: st_mtime (4 bytes)
          0x54: st_mtime_nsec (4 bytes)
          0x58: st_ctime (4 bytes)
          0x5c: st_ctime_nsec (4 bytes)
          0x60: unused (8 bytes)
        Total: 104 bytes (0x68)
        """
        buf = bytearray(104)
        # st_dev (8 bytes, big-endian)
        struct.pack_into(">Q", buf, 0x00, st.st_dev)
        # padding (4 bytes) at 0x08
        # st_ino (8 bytes)
        struct.pack_into(">Q", buf, 0x0C, st.st_ino)
        # st_mode (4 bytes)
        struct.pack_into(">I", buf, 0x14, st.st_mode)
        # st_nlink (4 bytes)
        struct.pack_into(">I", buf, 0x18, st.st_nlink)
        # st_uid (4 bytes)
        struct.pack_into(">I", buf, 0x1C, st.st_uid)
        # st_gid (4 bytes)
        struct.pack_into(">I", buf, 0x20, st.st_gid)
        # st_rdev (8 bytes)
        struct.pack_into(">Q", buf, 0x24, st.st_rdev)
        # padding (4 bytes) at 0x2C
        # st_size (8 bytes)
        struct.pack_into(">Q", buf, 0x30, st.st_size)
        # st_blksize (4 bytes)
        struct.pack_into(">I", buf, 0x38, st.st_blksize)
        # padding (4 bytes) at 0x3C
        # st_blocks (8 bytes)
        struct.pack_into(">Q", buf, 0x40, st.st_blocks)
        # st_atime (4 bytes) + nsec (4 bytes)
        struct.pack_into(">I", buf, 0x48, int(st.st_atime))
        struct.pack_into(">I", buf, 0x4C, int((st.st_atime % 1) * 1e9))
        # st_mtime (4 bytes) + nsec (4 bytes)
        struct.pack_into(">I", buf, 0x50, int(st.st_mtime))
        struct.pack_into(">I", buf, 0x54, int((st.st_mtime % 1) * 1e9))
        # st_ctime (4 bytes) + nsec (4 bytes)
        struct.pack_into(">I", buf, 0x58, int(st.st_ctime))
        struct.pack_into(">I", buf, 0x5C, int((st.st_ctime % 1) * 1e9))

        self.cpu_state.memory.write(addr, bytes(buf))

    def _syscall_fstat64(self):
        """
        fstat64 syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = stat buffer pointer
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        fd = self.cpu_state.registers.read_register(8)
        stat_buf = self.cpu_state.registers.read_register(9)

        desc = self.cpu_state.fd_table.get(fd)
        if desc is None:
            self._return_error(EBADF)
            return

        try:
            if desc.is_special:
                # For stdin/stdout/stderr, use os.fstat on actual fd
                st = os.fstat(fd)
            elif desc.is_directory and desc.dir_fd is not None:
                st = os.fstat(desc.dir_fd)
            elif desc.file is not None:
                st = os.fstat(desc.file.fileno())
            else:
                self._return_error(EBADF)
                return

            self._write_stat64(stat_buf, st)
            self._return_success(0)
        except OSError as e:
            self._return_error(e.errno if e.errno else EBADF)

    def _syscall_fstat(self):
        """
        fstat syscall implementation (old version, uses stat64 format)
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = stat buffer pointer
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        # Delegate to fstat64 implementation
        self._syscall_fstat64()

    def _syscall_stat(self):
        """
        stat syscall implementation (old 32-bit version)
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = stat buffer pointer
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        # Use stat64 implementation - the kernel typically handles both
        self._syscall_stat64()

    def _syscall_stat64(self):
        """
        stat64 syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = stat buffer pointer
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        stat_buf = self.cpu_state.registers.read_register(9)

        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            st = os.stat(host_path)
            self._write_stat64(stat_buf, st)
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_lstat(self):
        """
        lstat syscall implementation (doesn't follow symlinks)
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = stat buffer pointer
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        stat_buf = self.cpu_state.registers.read_register(9)

        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            st = os.lstat(host_path)
            self._write_stat64(stat_buf, st)
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_fchown(self):
        """
        fchown / fchown32 syscall implementation
        Arguments:
          %o0 (reg 8) = fd
          %o1 (reg 9) = owner
          %o2 (reg 10) = group
        Returns:
          %o0 = 0 on success, -errno on error
        """
        fd = self.cpu_state.registers.read_register(8)

        desc = self.cpu_state.fd_table.get(fd)
        if desc is None:
            self._return_error(EBADF)
            return

        # Stub: just return success - we don't actually change ownership
        self._return_success(0)

    def _syscall_chown(self):
        """
        chown / chown32 syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = owner
          %o2 (reg 10) = group
        Returns:
          %o0 = 0 on success, -errno on error
        """
        # Stub: just return success - we don't actually change ownership
        self._return_success(0)

    def _syscall_mkdir(self):
        """
        mkdir syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = mode
        Returns:
          %o0 = 0 on success, -errno on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        mode = self.cpu_state.registers.read_register(9)

        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            os.mkdir(host_path, mode)
            self._return_success(0)
        except FileExistsError:
            self._return_error(17)  # EEXIST
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_fchmod(self):
        """
        fchmod syscall implementation
        Arguments:
          %o0 (reg 8) = fd
          %o1 (reg 9) = mode
        Returns:
          %o0 = 0 on success, -errno on error
        """
        fd = self.cpu_state.registers.read_register(8)
        mode = self.cpu_state.registers.read_register(9)

        desc = self.cpu_state.fd_table.get(fd)
        if desc is None:
            self._return_error(EBADF)
            return

        # Actually change permissions on the underlying file
        try:
            if desc.file is not None:
                os.fchmod(desc.file.fileno(), mode)
            self._return_success(0)
        except OSError as e:
            self._return_error(e.errno if e.errno else EACCES)

    def _syscall_sendfile64(self):
        """
        sendfile64 syscall implementation - copy data between file descriptors
        Arguments:
          %o0 (reg 8) = out_fd
          %o1 (reg 9) = in_fd
          %o2 (reg 10) = offset pointer (or NULL)
          %o3 (reg 11) = count
        Returns:
          %o0 = number of bytes copied on success
          %o0 = errno, carry set on error
        """
        out_fd = self.cpu_state.registers.read_register(8)
        in_fd = self.cpu_state.registers.read_register(9)
        offset_ptr = self.cpu_state.registers.read_register(10)
        count = self.cpu_state.registers.read_register(11)

        in_desc = self.cpu_state.fd_table.get(in_fd)
        out_desc = self.cpu_state.fd_table.get(out_fd)

        if in_desc is None or out_desc is None:
            self._return_error(EBADF)
            return

        try:
            # Handle offset if provided
            if offset_ptr != 0:
                # Read 64-bit offset from memory
                offset_bytes = self.cpu_state.memory.read(offset_ptr, 8)
                offset = struct.unpack(">Q", offset_bytes)[0]
                if in_desc.file:
                    in_desc.file.seek(offset)

            # Read from input
            if in_desc.file:
                data = in_desc.file.read(count)
            else:
                self._return_error(EBADF)
                return

            # Write to output
            if out_desc.is_special:
                if out_fd == 1:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif out_fd == 2:
                    sys.stderr.buffer.write(data)
                    sys.stderr.buffer.flush()
                else:
                    self._return_error(EBADF)
                    return
            elif out_desc.file:
                out_desc.file.write(data)
            else:
                self._return_error(EBADF)
                return

            # Update offset if provided
            if offset_ptr != 0 and in_desc.file:
                new_offset = in_desc.file.tell()
                self.cpu_state.memory.write(
                    offset_ptr, struct.pack(">Q", new_offset)
                )

            self._return_success(len(data))
        except OSError as e:
            self._return_error(e.errno if e.errno else EBADF)

    def _syscall_unlink(self):
        """
        unlink syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
        Returns:
          %o0 = 0 on success, -errno on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            os.unlink(host_path)
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_chdir(self):
        """
        chdir syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
        Returns:
          %o0 = 0 on success, -errno on error

        NOTE: This changes the host process's working directory, which may
        have side effects if the emulator is used as a library or runs
        multiple guest processes.
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            os.chdir(host_path)
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except NotADirectoryError:
            self._return_error(ENOTDIR)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_readlink(self):
        """
        readlink syscall implementation
        Arguments:
          %o0 (reg 8) = pathname pointer
          %o1 (reg 9) = buffer pointer
          %o2 (reg 10) = buffer size
        Returns:
          %o0 = number of bytes placed in buffer, carry clear on success
          %o0 = errno, carry set on error
        """
        pathname_ptr = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        bufsiz = self.cpu_state.registers.read_register(10)

        pathname = self._read_string(pathname_ptr)
        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            target = os.readlink(host_path)
            target_bytes = target.encode("utf-8")
            # Truncate to bufsiz (readlink does not null-terminate)
            to_write = target_bytes[:bufsiz]
            self.cpu_state.memory.write(buf_ptr, to_write)
            self._return_success(len(to_write))
        except FileNotFoundError:
            self._return_error(ENOENT)
        except OSError as e:
            if e.errno == 22:  # EINVAL - not a symlink
                self._return_error(EINVAL)
            else:
                self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_mmap(self):
        """
        mmap syscall implementation (old style, offset in bytes)
        Arguments:
          %o0 (reg 8) = addr (hint or required if MAP_FIXED)
          %o1 (reg 9) = length
          %o2 (reg 10) = prot (PROT_READ | PROT_WRITE | PROT_EXEC)
          %o3 (reg 11) = flags (MAP_PRIVATE | MAP_ANONYMOUS | etc.)
          %o4 (reg 12) = fd (ignored if MAP_ANONYMOUS)
          %o5 (reg 13) = offset in bytes
        Returns:
          %o0 = mapped address, carry clear on success
          %o0 = errno, carry set on error
        """
        addr = self.cpu_state.registers.read_register(8)
        length = self.cpu_state.registers.read_register(9)
        prot = self.cpu_state.registers.read_register(10)
        flags = self.cpu_state.registers.read_register(11)
        fd = self.cpu_state.registers.read_register(12)
        if fd & 0x80000000:
            fd = fd - 0x100000000
        offset = self.cpu_state.registers.read_register(13)  # Already in bytes
        self._do_mmap(addr, length, prot, flags, fd, offset)

    def _syscall_mmap2(self):
        """
        mmap2 syscall implementation
        Arguments:
          %o0 (reg 8) = addr (hint or required if MAP_FIXED)
          %o1 (reg 9) = length
          %o2 (reg 10) = prot (PROT_READ | PROT_WRITE | PROT_EXEC)
          %o3 (reg 11) = flags (MAP_PRIVATE | MAP_ANONYMOUS | etc.)
          %o4 (reg 12) = fd (ignored if MAP_ANONYMOUS)
          %o5 (reg 13) = offset in pages (4KB units, not bytes!)
        Returns:
          %o0 = mapped address, carry clear on success
          %o0 = errno, carry set on error
        """
        addr = self.cpu_state.registers.read_register(8)
        length = self.cpu_state.registers.read_register(9)
        prot = self.cpu_state.registers.read_register(10)
        flags = self.cpu_state.registers.read_register(11)
        fd = self.cpu_state.registers.read_register(12)
        # Handle signed fd for MAP_ANONYMOUS (-1)
        if fd & 0x80000000:
            fd = fd - 0x100000000
        offset_pages = self.cpu_state.registers.read_register(13)
        offset = offset_pages * 4096  # Convert pages to bytes
        self._do_mmap(addr, length, prot, flags, fd, offset)

    def _do_mmap(
        self, addr: int, length: int, prot: int, flags: int, fd: int, offset: int
    ) -> None:
        """Common implementation for mmap and mmap2."""

        if length == 0:
            self._return_error(EINVAL)
            return

        is_fixed = bool(flags & MAP_FIXED)

        # Handle MAP_ANONYMOUS - no file backing
        if flags & MAP_ANONYMOUS:
            # Allocate anonymous memory
            segment = self.cpu_state.memory.allocate_at(
                addr if (addr or is_fixed) else 0, length, prot, fixed=is_fixed
            )

            if segment is None:
                self._return_error(EINVAL)  # Could be ENOMEM
                return

            # Anonymous mappings are zero-initialized (already done by allocate_at)
            self._return_success(segment.start)
            return

        # File-backed mapping
        desc = self.cpu_state.fd_table.get(fd)
        if desc is None or desc.file is None:
            self._return_error(EBADF)
            return

        # Allocate the memory region
        segment = self.cpu_state.memory.allocate_at(
            addr if (addr or is_fixed) else 0, length, prot, fixed=is_fixed
        )

        if segment is None:
            self._return_error(EINVAL)
            return

        # Read file contents into the mapped region
        try:
            original_pos = desc.file.tell()
            desc.file.seek(offset)
            data = desc.file.read(length)
            desc.file.seek(original_pos)

            if data:
                # Copy file data into segment buffer
                segment.buffer[: len(data)] = data
        except OSError as e:
            # Allocation succeeded but file read failed - unmap and return error
            self.cpu_state.memory.remove_segment_range(segment.start, length)
            self._return_error(e.errno if e.errno else EBADF)
            return

        self._return_success(segment.start)

    def _syscall_munmap(self):
        """
        munmap syscall implementation
        Arguments:
          %o0 (reg 8) = addr
          %o1 (reg 9) = length
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        addr = self.cpu_state.registers.read_register(8)
        length = self.cpu_state.registers.read_register(9)

        if length == 0:
            self._return_error(EINVAL)
            return

        # For simplicity, we just return success even if nothing was unmapped
        # A full implementation would track mappings more precisely
        self.cpu_state.memory.remove_segment_range(addr, length)
        self._return_success(0)

    def _syscall_mprotect(self):
        """
        mprotect syscall implementation
        Arguments:
          %o0 (reg 8) = addr
          %o1 (reg 9) = length
          %o2 (reg 10) = prot
        Returns:
          %o0 = 0, carry clear on success
          %o0 = errno, carry set on error
        """
        addr = self.cpu_state.registers.read_register(8)
        length = self.cpu_state.registers.read_register(9)
        prot = self.cpu_state.registers.read_register(10)

        if length == 0:
            self._return_error(EINVAL)
            return

        # For now, just return success - we don't enforce permissions
        # A full implementation would track and enforce memory protection
        self.cpu_state.memory.set_permissions(addr, length, prot)
        self._return_success(0)

    def _syscall_readlinkat(self):
        """
        readlinkat syscall implementation
        Arguments:
          %o0 (reg 8) = dirfd (AT_FDCWD for current directory)
          %o1 (reg 9) = pathname pointer
          %o2 (reg 10) = buffer pointer
          %o3 (reg 11) = buffer size
        Returns:
          %o0 = number of bytes placed in buffer, carry clear on success
          %o0 = errno, carry set on error
        """
        dirfd = self.cpu_state.registers.read_register(8)
        pathname_ptr = self.cpu_state.registers.read_register(9)
        buf_ptr = self.cpu_state.registers.read_register(10)
        bufsiz = self.cpu_state.registers.read_register(11)

        pathname = self._read_string(pathname_ptr)

        # Handle AT_FDCWD and absolute paths
        if dirfd != (AT_FDCWD & 0xFFFFFFFF) and not pathname.startswith("/"):
            self._return_error(EBADF)
            return

        # Emulate /proc/self/exe - return the path to the executable
        if pathname == "/proc/self/exe":
            target = self.cpu_state.exe_path
            if not target:
                self._return_error(ENOENT)
                return
            target_bytes = target.encode("utf-8")
            to_write = target_bytes[:bufsiz]
            self.cpu_state.memory.write(buf_ptr, to_write)
            self._return_success(len(to_write))
            return

        host_path = self.cpu_state.fd_table.translate_path(pathname)

        try:
            target = os.readlink(host_path)
            target_bytes = target.encode("utf-8")
            to_write = target_bytes[:bufsiz]
            self.cpu_state.memory.write(buf_ptr, to_write)
            self._return_success(len(to_write))
        except FileNotFoundError:
            self._return_error(ENOENT)
        except OSError as e:
            if e.errno == 22:  # EINVAL - not a symlink
                self._return_error(EINVAL)
            else:
                self._return_error(e.errno if e.errno else ENOENT)

    def _syscall_getuid(self):
        """
        getuid / getuid32 syscall implementation
        Returns:
          %o0 = user ID
        """
        # Return a fixed UID - matches our fake TID
        self._return_success(1000)

    def _syscall_getgid(self):
        """
        getgid / getgid32 syscall implementation
        Returns:
          %o0 = group ID
        """
        self._return_success(1000)

    def _syscall_geteuid(self):
        """
        geteuid syscall implementation
        Returns:
          %o0 = effective user ID
        """
        self._return_success(1000)

    def _syscall_getegid(self):
        """
        getegid syscall implementation
        Returns:
          %o0 = effective group ID
        """
        self._return_success(1000)

    def _syscall_setuid(self):
        """
        setuid / setuid32 syscall implementation
        Arguments:
          %o0 (reg 8) = uid
        Returns:
          %o0 = 0 on success
        """
        # Stub - just return success (we don't actually change privileges)
        self._return_success(0)

    def _syscall_setgid(self):
        """
        setgid / setgid32 syscall implementation
        Arguments:
          %o0 (reg 8) = gid
        Returns:
          %o0 = 0 on success
        """
        # Stub - just return success
        self._return_success(0)

    def _syscall_dup2(self):
        """
        dup2 syscall implementation
        Arguments:
          %o0 (reg 8) = oldfd
          %o1 (reg 9) = newfd
        Returns:
          %o0 = new fd on success
          %o0 = errno, carry set on error
        """
        oldfd = self.cpu_state.registers.read_register(8)
        newfd = self.cpu_state.registers.read_register(9)

        result = self.cpu_state.fd_table.dup2(oldfd, newfd)
        if result < 0:
            self._return_error(-result)
        else:
            self._return_success(result)

    def _syscall_set_tid_address(self):
        """
        set_tid_address syscall implementation
        Arguments:
          %o0 (reg 8) = tidptr - pointer where to store TID on exit
        Returns:
          %o0 = caller's thread ID (same as PID for single-threaded)
        """
        # Just store the pointer and return a fixed TID (same as our PID)
        # For single-threaded emulation, we don't actually need to use tidptr
        self._return_success(1000)  # Fixed TID matching our fake UID/GID

    def _syscall_set_robust_list(self):
        """
        set_robust_list syscall implementation
        Arguments:
          %o0 (reg 8) = head - pointer to robust list head
          %o1 (reg 9) = len - size of the structure
        Returns:
          %o0 = 0 on success
        """
        # Stub for single-threaded emulation - just return success
        self._return_success(0)

    def _syscall_rt_sigaction(self):
        """
        rt_sigaction syscall implementation
        Arguments:
          %o0 (reg 8) = signum - signal number
          %o1 (reg 9) = act - pointer to new action (or NULL)
          %o2 (reg 10) = oldact - pointer to store old action (or NULL)
          %o3 (reg 11) = sigsetsize - size of sigset_t
        Returns:
          %o0 = 0 on success, -errno on error
        """
        # Stub: Accept any signal setup but don't actually do anything
        # A real implementation would track signal handlers
        self._return_success(0)

    def _syscall_rt_sigprocmask(self):
        """
        rt_sigprocmask syscall implementation
        Arguments:
          %o0 (reg 8) = how - SIG_BLOCK, SIG_UNBLOCK, or SIG_SETMASK
          %o1 (reg 9) = set - pointer to new signal mask (or NULL)
          %o2 (reg 10) = oldset - pointer to store old mask (or NULL)
          %o3 (reg 11) = sigsetsize - size of sigset_t
        Returns:
          %o0 = 0 on success, -errno on error
        """
        # Stub: Accept any mask operation but don't actually do anything
        self._return_success(0)

    def _syscall_prlimit64(self):
        """
        prlimit64 syscall implementation
        Arguments:
          %o0 (reg 8) = pid - process ID (0 = current)
          %o1 (reg 9) = resource - resource type (RLIMIT_*)
          %o2 (reg 10) = new_limit - pointer to new limit (or NULL)
          %o3 (reg 11) = old_limit - pointer to store old limit (or NULL)
        Returns:
          %o0 = 0 on success, -errno on error

        RLIMIT_STACK = 3, RLIMIT_NOFILE = 6, etc.
        """
        old_limit_ptr = self.cpu_state.registers.read_register(11)

        if old_limit_ptr != 0:
            # Return some reasonable default limits
            # rlimit64 structure: 2 x 8-byte values (rlim_cur, rlim_max)
            # Using RLIM_INFINITY (0xffffffffffffffff) for most
            rlim_cur = 0xFFFFFFFFFFFFFFFF  # RLIM_INFINITY
            rlim_max = 0xFFFFFFFFFFFFFFFF  # RLIM_INFINITY
            self.cpu_state.memory.write(
                old_limit_ptr, struct.pack(">QQ", rlim_cur, rlim_max)
            )

        self._return_success(0)

    def _syscall_statx(self):
        """
        statx syscall implementation
        Arguments:
          %o0 (reg 8) = dirfd (AT_FDCWD for current directory, or fd)
          %o1 (reg 9) = pathname pointer
          %o2 (reg 10) = flags (AT_EMPTY_PATH = 0x1000)
          %o3 (reg 11) = mask (which fields to fill)
          %o4 (reg 12) = statxbuf pointer
        Returns:
          %o0 = 0 on success, -errno on error
        """
        AT_EMPTY_PATH = 0x1000

        dirfd = self.cpu_state.registers.read_register(8)
        pathname_ptr = self.cpu_state.registers.read_register(9)
        flags = self.cpu_state.registers.read_register(10)
        # mask = self.cpu_state.registers.read_register(11)
        statxbuf = self.cpu_state.registers.read_register(12)

        pathname = self._read_string(pathname_ptr)

        try:
            # Handle AT_EMPTY_PATH with fd - stat the fd directly
            if (flags & AT_EMPTY_PATH) and (pathname == "" or pathname_ptr == 0):
                # dirfd is an actual file descriptor
                desc = self.cpu_state.fd_table.get(dirfd)
                if desc is None:
                    self._return_error(EBADF)
                    return
                if desc.is_special:
                    st = os.fstat(dirfd)
                elif desc.is_directory and desc.dir_fd is not None:
                    st = os.fstat(desc.dir_fd)
                elif desc.file is not None:
                    st = os.fstat(desc.file.fileno())
                else:
                    self._return_error(EBADF)
                    return
            elif dirfd == (AT_FDCWD & 0xFFFFFFFF) or pathname.startswith("/"):
                # Normal path-based stat
                host_path = self.cpu_state.fd_table.translate_path(pathname)
                st = os.stat(host_path)
            else:
                # Relative path with dirfd - not fully supported yet
                # For now, just try the path directly
                host_path = self.cpu_state.fd_table.translate_path(pathname)
                st = os.stat(host_path)

            self._write_statx(statxbuf, st)
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)

    def _write_statx(self, addr: int, st: os.stat_result) -> None:
        """Write a statx structure to guest memory.

        struct statx layout (256 bytes):
          0x00: stx_mask (4 bytes)
          0x04: stx_blksize (4 bytes)
          0x08: stx_attributes (8 bytes)
          0x10: stx_nlink (4 bytes)
          0x14: stx_uid (4 bytes)
          0x18: stx_gid (4 bytes)
          0x1c: stx_mode (2 bytes)
          0x1e: padding (2 bytes)
          0x20: stx_ino (8 bytes)
          0x28: stx_size (8 bytes)
          0x30: stx_blocks (8 bytes)
          0x38: stx_attributes_mask (8 bytes)
          0x40: stx_atime (16 bytes: tv_sec, tv_nsec, padding)
          0x50: stx_btime (16 bytes)
          0x60: stx_ctime (16 bytes)
          0x70: stx_mtime (16 bytes)
          ... more fields up to 256 bytes
        """
        buf = bytearray(256)

        # stx_mask - indicate which fields are valid
        STATX_BASIC_STATS = 0x7ff
        struct.pack_into(">I", buf, 0x00, STATX_BASIC_STATS)
        # stx_blksize
        struct.pack_into(">I", buf, 0x04, st.st_blksize)
        # stx_attributes (8 bytes)
        struct.pack_into(">Q", buf, 0x08, 0)
        # stx_nlink
        struct.pack_into(">I", buf, 0x10, st.st_nlink)
        # stx_uid
        struct.pack_into(">I", buf, 0x14, st.st_uid)
        # stx_gid
        struct.pack_into(">I", buf, 0x18, st.st_gid)
        # stx_mode (2 bytes)
        struct.pack_into(">H", buf, 0x1c, st.st_mode)
        # stx_ino (8 bytes)
        struct.pack_into(">Q", buf, 0x20, st.st_ino)
        # stx_size (8 bytes)
        struct.pack_into(">Q", buf, 0x28, st.st_size)
        # stx_blocks (8 bytes)
        struct.pack_into(">Q", buf, 0x30, st.st_blocks)
        # stx_attributes_mask (8 bytes)
        struct.pack_into(">Q", buf, 0x38, 0)
        # stx_atime (tv_sec 8 bytes, tv_nsec 4 bytes, padding 4 bytes)
        struct.pack_into(">Q", buf, 0x40, int(st.st_atime))
        struct.pack_into(">I", buf, 0x48, int((st.st_atime % 1) * 1e9))
        # stx_btime (birth time - use mtime as fallback)
        struct.pack_into(">Q", buf, 0x50, int(st.st_mtime))
        struct.pack_into(">I", buf, 0x58, int((st.st_mtime % 1) * 1e9))
        # stx_ctime
        struct.pack_into(">Q", buf, 0x60, int(st.st_ctime))
        struct.pack_into(">I", buf, 0x68, int((st.st_ctime % 1) * 1e9))
        # stx_mtime
        struct.pack_into(">Q", buf, 0x70, int(st.st_mtime))
        struct.pack_into(">I", buf, 0x78, int((st.st_mtime % 1) * 1e9))
        # stx_rdev_major, stx_rdev_minor
        struct.pack_into(">I", buf, 0x80, os.major(st.st_rdev))
        struct.pack_into(">I", buf, 0x84, os.minor(st.st_rdev))
        # stx_dev_major, stx_dev_minor
        struct.pack_into(">I", buf, 0x88, os.major(st.st_dev))
        struct.pack_into(">I", buf, 0x8c, os.minor(st.st_dev))

        self.cpu_state.memory.write(addr, bytes(buf))

    def _syscall_utimensat(self):
        """
        utimensat / utimensat_time64 syscall implementation
        Arguments:
          %o0 (reg 8) = dirfd
          %o1 (reg 9) = pathname pointer
          %o2 (reg 10) = times array pointer (or NULL for now)
          %o3 (reg 11) = flags
        Returns:
          %o0 = 0 on success, -errno on error
        """
        dirfd = self.cpu_state.registers.read_register(8)
        pathname_ptr = self.cpu_state.registers.read_register(9)
        # times_ptr = self.cpu_state.registers.read_register(10)
        # flags = self.cpu_state.registers.read_register(11)

        # If pathname is NULL/empty, operate on dirfd
        if pathname_ptr == 0:
            # Operating on the fd directly - just return success
            # A full implementation would set the timestamps
            self._return_success(0)
            return

        pathname = self._read_string(pathname_ptr)

        # Handle AT_FDCWD
        if dirfd == (AT_FDCWD & 0xFFFFFFFF) or pathname.startswith("/"):
            host_path = self.cpu_state.fd_table.translate_path(pathname)
        else:
            host_path = pathname

        # For now, just touch the file to update timestamps
        # A full implementation would parse the times array
        try:
            os.utime(host_path, None)  # Set to current time
            self._return_success(0)
        except FileNotFoundError:
            self._return_error(ENOENT)
        except PermissionError:
            self._return_error(EACCES)
        except OSError as e:
            self._return_error(e.errno if e.errno else ENOENT)
