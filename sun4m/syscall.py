from __future__ import annotations

import os
import stat
import struct
import sys
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
            case 17:
                self._syscall_brk()
            case 19:
                self._syscall_lseek()
            case 28:
                self._syscall_fstat64()
            case 32:
                self._syscall_fchown()
            case 38:
                self._syscall_stat()
            case 54:
                self._syscall_ioctl()
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
            case 85:
                self._syscall_readlink()
            case 102:
                self._syscall_rt_sigaction()
            case 103:
                self._syscall_rt_sigprocmask()
            case 124:
                self._syscall_fchmod()
            case 188:
                self._syscall_exit()  # exit_group - same as exit for single-threaded
            case 215:
                self._syscall_stat64()
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
        sys.exit(exit_code)

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

        LIMITATION: The heap is fixed at 1MB (0x100000 bytes) starting at
        address 0x100000. Allocations beyond this limit will succeed from
        brk's perspective but will cause MemoryError when the program
        attempts to access memory beyond the allocated segment. Programs
        requiring more heap space will need this limit increased.
        """
        new_brk = self.cpu_state.registers.read_register(8)

        # Initialize brk to a reasonable heap start if not set
        if self.cpu_state.brk == 0:
            # Set initial break to 0x100000 (1MB) - above typical code/data
            self.cpu_state.brk = 0x100000
            # Create initial heap segment (1MB fixed size - see docstring)
            self.cpu_state.memory.add_segment(self.cpu_state.brk, 0x100000)

        if new_brk == 0:
            # Query current break
            self._return_success(self.cpu_state.brk)
        elif new_brk > self.cpu_state.brk:
            # Extend the heap - we only update the break pointer.
            # Note: accesses beyond the initial 1MB segment will fail.
            self.cpu_state.brk = new_brk
            self._return_success(self.cpu_state.brk)
        else:
            # Shrink or same - just update and return
            self.cpu_state.brk = new_brk
            self._return_success(self.cpu_state.brk)

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

        # Check if fd maps to a real host terminal
        if fd in (0, 1, 2) and os.isatty(fd):
            # For terminal ioctls, return 0 (success) to indicate it's a tty
            # This makes programs like gzip behave correctly when run interactively
            self._return_success(0)
        else:
            self._return_error(ENOTTY)

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
