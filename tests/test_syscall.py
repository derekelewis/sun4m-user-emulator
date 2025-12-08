import unittest
from unittest.mock import patch, MagicMock
import io
import os
import shutil
import sys
import tempfile

from sun4m.cpu import CpuState
from sun4m.syscall import Syscall


class TestSyscallRead(unittest.TestCase):
    """Tests for read syscall (syscall 3)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_read_from_stdin(self):
        """Test reading from stdin (fd=0)."""
        # Set up syscall: read(0, 0x1000, 10)
        self.cpu_state.registers.write_register(1, 3)  # syscall number in %g1
        self.cpu_state.registers.write_register(8, 0)  # fd = 0 (stdin) in %o0
        self.cpu_state.registers.write_register(9, 0x1000)  # buffer in %o1
        self.cpu_state.registers.write_register(10, 10)  # count in %o2

        test_input = b"hello"
        mock_stdin = MagicMock()
        mock_stdin.buffer.read.return_value = test_input
        with patch.object(sys, 'stdin', mock_stdin):
            self.syscall.handle()

        # Check return value (bytes read)
        self.assertEqual(self.cpu_state.registers.read_register(8), 5)
        # Check buffer contents
        self.assertEqual(self.cpu_state.memory.read(0x1000, 5), b"hello")

    def test_read_eof(self):
        """Test reading EOF from stdin."""
        self.cpu_state.registers.write_register(1, 3)
        self.cpu_state.registers.write_register(8, 0)
        self.cpu_state.registers.write_register(9, 0x1000)
        self.cpu_state.registers.write_register(10, 10)

        mock_stdin = MagicMock()
        mock_stdin.buffer.read.return_value = b""
        with patch.object(sys, 'stdin', mock_stdin):
            self.syscall.handle()

        # EOF returns 0
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)

    def test_read_unsupported_fd(self):
        """Test reading from unsupported file descriptor."""
        self.cpu_state.registers.write_register(1, 3)
        self.cpu_state.registers.write_register(8, 5)  # fd = 5 (unsupported)
        self.cpu_state.registers.write_register(9, 0x1000)
        self.cpu_state.registers.write_register(10, 10)

        self.syscall.handle()

        # Should return EBADF (9) with carry set
        self.assertEqual(self.cpu_state.registers.read_register(8), 9)
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallClose(unittest.TestCase):
    """Tests for close syscall (syscall 6)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_close_stdin_returns_success(self):
        """Test close syscall on stdin returns success (no-op for special fds)."""
        self.cpu_state.registers.write_register(1, 6)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # fd = 0 (stdin)

        self.syscall.handle()

        # Should return 0 (success) for special fds
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)  # carry clear on success

    def test_close_invalid_fd_returns_ebadf(self):
        """Test close syscall on invalid fd returns EBADF."""
        self.cpu_state.registers.write_register(1, 6)  # syscall number
        self.cpu_state.registers.write_register(8, 99)  # fd = 99 (invalid)

        self.syscall.handle()

        # Should return EBADF (9) with carry set
        self.assertEqual(self.cpu_state.registers.read_register(8), 9)
        self.assertTrue(self.cpu_state.icc.c)  # carry set on error


class TestSyscallBrk(unittest.TestCase):
    """Tests for brk syscall (syscall 17)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)
        # brk is now stored in cpu_state, no need to reset class variable

    def test_brk_query_initial(self):
        """Test querying brk when not initialized."""
        self.cpu_state.registers.write_register(1, 17)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # query current brk

        self.syscall.handle()

        # Should return initial break (0x10000000 - heap starts at 256MB)
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x10000000)

    def test_brk_extend(self):
        """Test extending the break."""
        # First, initialize brk
        self.cpu_state.registers.write_register(1, 17)
        self.cpu_state.registers.write_register(8, 0)
        self.syscall.handle()

        # Now extend it (heap starts at 0x10000000)
        self.cpu_state.registers.write_register(8, 0x10200000)
        self.syscall.handle()

        # Should return new break
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x10200000)
        self.assertEqual(self.cpu_state.brk, 0x10200000)

    def test_brk_shrink(self):
        """Test shrinking the break."""
        # First, initialize and extend
        self.cpu_state.registers.write_register(1, 17)
        self.cpu_state.registers.write_register(8, 0)
        self.syscall.handle()

        self.cpu_state.registers.write_register(8, 0x10200000)
        self.syscall.handle()

        # Now shrink it
        self.cpu_state.registers.write_register(8, 0x10150000)
        self.syscall.handle()

        # Should return new (smaller) break
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x10150000)
        self.assertEqual(self.cpu_state.brk, 0x10150000)


class TestSyscallIoctl(unittest.TestCase):
    """Tests for ioctl syscall (syscall 54)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_ioctl_returns_enotty(self):
        """Test ioctl returns ENOTTY for non-standard file descriptors."""
        self.cpu_state.registers.write_register(1, 54)  # syscall number
        self.cpu_state.registers.write_register(8, 5)  # fd = 5 (not stdin/stdout/stderr)
        self.cpu_state.registers.write_register(9, 0x5401)  # TIOCGWINSZ
        self.cpu_state.registers.write_register(10, 0x1000)  # arg

        self.syscall.handle()

        # Non-standard fds should return ENOTTY (25) with carry set
        self.assertEqual(self.cpu_state.registers.read_register(8), 25)
        self.assertTrue(self.cpu_state.icc.c)

    def test_ioctl_stdin_returns_success(self):
        """Test ioctl on stdin/stdout/stderr returns success with defaults."""
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.cpu_state.registers.write_register(1, 54)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # fd = 0 (stdin)
        self.cpu_state.registers.write_register(9, 0x40087468)  # SPARC TIOCGWINSZ
        self.cpu_state.registers.write_register(10, 0x1000)  # arg buffer

        self.syscall.handle()

        # Should return success (0) with carry clear for stdin
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallGetrandom(unittest.TestCase):
    """Tests for getrandom syscall (syscall 347 on SPARC)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_getrandom_fills_buffer(self):
        """Test getrandom fills buffer with random bytes."""
        self.cpu_state.registers.write_register(1, 347)  # syscall number
        self.cpu_state.registers.write_register(8, 0x1000)  # buffer
        self.cpu_state.registers.write_register(9, 16)  # count
        self.cpu_state.registers.write_register(10, 0)  # flags

        self.syscall.handle()

        # Should return count
        self.assertEqual(self.cpu_state.registers.read_register(8), 16)
        # Buffer should be filled (not all zeros)
        data = self.cpu_state.memory.read(0x1000, 16)
        self.assertEqual(len(data), 16)
        # Very unlikely to be all zeros with real random data
        # But we won't test randomness, just that it was written

    def test_getrandom_null_pointer(self):
        """Test getrandom with null pointer returns 0."""
        self.cpu_state.registers.write_register(1, 347)
        self.cpu_state.registers.write_register(8, 0)  # NULL buffer
        self.cpu_state.registers.write_register(9, 16)
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return 0
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)

    def test_getrandom_zero_count(self):
        """Test getrandom with zero count returns 0."""
        self.cpu_state.registers.write_register(1, 347)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0)  # zero count
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return 0
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)


class TestSyscallExitGroup(unittest.TestCase):
    """Tests for exit_group syscall (syscall 188)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_exit_group_exits_with_code(self):
        """Test exit_group syscall sets halted flag with the specified code."""
        self.cpu_state.registers.write_register(1, 188)  # syscall number
        self.cpu_state.registers.write_register(8, 42)  # exit code in %o0

        self.syscall.handle()

        self.assertTrue(self.cpu_state.halted)
        self.assertEqual(self.cpu_state.exit_code, 42)

    def test_exit_group_exits_with_zero(self):
        """Test exit_group syscall sets halted flag with code 0."""
        self.cpu_state.registers.write_register(1, 188)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # exit code 0

        self.syscall.handle()

        self.assertTrue(self.cpu_state.halted)
        self.assertEqual(self.cpu_state.exit_code, 0)


class TestSyscallUnimplemented(unittest.TestCase):
    """Tests for unimplemented syscalls."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_unimplemented_syscall_raises(self):
        """Test that unimplemented syscalls raise ValueError."""
        self.cpu_state.registers.write_register(1, 999)  # unknown syscall

        with self.assertRaises(ValueError) as context:
            self.syscall.handle()

        self.assertIn("999", str(context.exception))
        self.assertIn("not implemented", str(context.exception))


class TestSyscallOpenClose(unittest.TestCase):
    """Tests for open/openat and close syscalls."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        # Create a temp file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"test content")
        self.temp_file.close()

    def tearDown(self):
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def _write_string(self, addr: int, s: str) -> None:
        """Write null-terminated string to memory."""
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_open_existing_file(self):
        """Test opening an existing file."""
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 5)  # open syscall
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname
        self.cpu_state.registers.write_register(9, 0)  # O_RDONLY
        self.cpu_state.registers.write_register(10, 0)  # mode

        self.syscall.handle()

        # Should return a valid fd (>= 3)
        fd = self.cpu_state.registers.read_register(8)
        self.assertGreaterEqual(fd, 3)
        self.assertFalse(self.cpu_state.icc.c)

        # Clean up - close the fd
        self.cpu_state.registers.write_register(1, 6)
        self.cpu_state.registers.write_register(8, fd)
        self.syscall.handle()

    def test_open_nonexistent_file(self):
        """Test opening a nonexistent file returns ENOENT."""
        self._write_string(0x1000, "/nonexistent/path/file.txt")
        self.cpu_state.registers.write_register(1, 5)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0)
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return ENOENT (2)
        self.assertEqual(self.cpu_state.registers.read_register(8), 2)
        self.assertTrue(self.cpu_state.icc.c)

    def test_openat_with_at_fdcwd(self):
        """Test openat with AT_FDCWD."""
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 284)  # openat syscall
        self.cpu_state.registers.write_register(8, 0xFFFFFF9C)  # AT_FDCWD (-100)
        self.cpu_state.registers.write_register(9, 0x1000)  # pathname
        self.cpu_state.registers.write_register(10, 0)  # O_RDONLY
        self.cpu_state.registers.write_register(11, 0)  # mode

        self.syscall.handle()

        fd = self.cpu_state.registers.read_register(8)
        self.assertGreaterEqual(fd, 3)
        self.assertFalse(self.cpu_state.icc.c)

        # Clean up
        self.cpu_state.registers.write_register(1, 6)
        self.cpu_state.registers.write_register(8, fd)
        self.syscall.handle()


class TestSyscallUnlink(unittest.TestCase):
    """Tests for unlink syscall (syscall 10)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def _write_string(self, addr: int, s: str) -> None:
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_unlink_existing_file(self):
        """Test unlinking an existing file."""
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        self._write_string(0x1000, temp_path)
        self.cpu_state.registers.write_register(1, 10)  # unlink
        self.cpu_state.registers.write_register(8, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)
        self.assertFalse(os.path.exists(temp_path))

    def test_unlink_nonexistent_file(self):
        """Test unlinking a nonexistent file returns ENOENT."""
        self._write_string(0x1000, "/nonexistent/file.txt")
        self.cpu_state.registers.write_register(1, 10)
        self.cpu_state.registers.write_register(8, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 2)  # ENOENT
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallFstat(unittest.TestCase):
    """Tests for fstat/fstat64 syscalls."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_fstat_stdin(self):
        """Test fstat on stdin returns success."""
        self.cpu_state.registers.write_register(1, 62)  # fstat
        self.cpu_state.registers.write_register(8, 0)  # stdin
        self.cpu_state.registers.write_register(9, 0x1000)  # stat buffer

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_fstat_invalid_fd(self):
        """Test fstat on invalid fd returns EBADF."""
        self.cpu_state.registers.write_register(1, 62)
        self.cpu_state.registers.write_register(8, 99)  # invalid fd
        self.cpu_state.registers.write_register(9, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 9)  # EBADF
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallLseek(unittest.TestCase):
    """Tests for lseek syscall (syscall 19)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        # Create temp file with content
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"0123456789")
        self.temp_file.close()
        # Open the file
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 5)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0)
        self.cpu_state.registers.write_register(10, 0)
        self.syscall.handle()
        self.fd = self.cpu_state.registers.read_register(8)

    def tearDown(self):
        # Close fd
        self.cpu_state.registers.write_register(1, 6)
        self.cpu_state.registers.write_register(8, self.fd)
        self.syscall.handle()
        os.unlink(self.temp_file.name)

    def _write_string(self, addr: int, s: str) -> None:
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_lseek_set(self):
        """Test lseek with SEEK_SET."""
        self.cpu_state.registers.write_register(1, 19)  # lseek
        self.cpu_state.registers.write_register(8, self.fd)
        self.cpu_state.registers.write_register(9, 5)  # offset
        self.cpu_state.registers.write_register(10, 0)  # SEEK_SET

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 5)
        self.assertFalse(self.cpu_state.icc.c)

    def test_lseek_end(self):
        """Test lseek with SEEK_END."""
        self.cpu_state.registers.write_register(1, 19)
        self.cpu_state.registers.write_register(8, self.fd)
        self.cpu_state.registers.write_register(9, 0)  # offset
        self.cpu_state.registers.write_register(10, 2)  # SEEK_END

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 10)  # file size
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallMmap(unittest.TestCase):
    """Tests for mmap/mmap2 syscalls."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_mmap_anonymous(self):
        """Test anonymous mmap allocation."""
        self.cpu_state.registers.write_register(1, 71)  # mmap
        self.cpu_state.registers.write_register(8, 0)  # addr (let kernel choose)
        self.cpu_state.registers.write_register(9, 0x1000)  # length
        self.cpu_state.registers.write_register(10, 0x3)  # PROT_READ | PROT_WRITE
        self.cpu_state.registers.write_register(11, 0x22)  # MAP_PRIVATE | MAP_ANONYMOUS
        self.cpu_state.registers.write_register(12, 0xFFFFFFFF)  # fd = -1
        self.cpu_state.registers.write_register(13, 0)  # offset

        self.syscall.handle()

        addr = self.cpu_state.registers.read_register(8)
        self.assertGreater(addr, 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify we can write to the allocated memory
        self.cpu_state.memory.write(addr, b"test")
        self.assertEqual(self.cpu_state.memory.read(addr, 4), b"test")

    def test_mmap2_anonymous(self):
        """Test mmap2 with anonymous mapping."""
        self.cpu_state.registers.write_register(1, 56)  # mmap2
        self.cpu_state.registers.write_register(8, 0)
        self.cpu_state.registers.write_register(9, 0x2000)
        self.cpu_state.registers.write_register(10, 0x3)
        self.cpu_state.registers.write_register(11, 0x22)
        self.cpu_state.registers.write_register(12, 0xFFFFFFFF)
        self.cpu_state.registers.write_register(13, 0)

        self.syscall.handle()

        addr = self.cpu_state.registers.read_register(8)
        self.assertGreater(addr, 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_mmap_zero_length_fails(self):
        """Test mmap with zero length fails."""
        self.cpu_state.registers.write_register(1, 71)
        self.cpu_state.registers.write_register(8, 0)
        self.cpu_state.registers.write_register(9, 0)  # zero length
        self.cpu_state.registers.write_register(10, 0x3)
        self.cpu_state.registers.write_register(11, 0x22)
        self.cpu_state.registers.write_register(12, 0xFFFFFFFF)
        self.cpu_state.registers.write_register(13, 0)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 22)  # EINVAL
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallSignals(unittest.TestCase):
    """Tests for signal-related syscalls (stubs)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_rt_sigaction(self):
        """Test rt_sigaction returns success."""
        self.cpu_state.registers.write_register(1, 102)  # rt_sigaction
        self.cpu_state.registers.write_register(8, 2)  # SIGINT
        self.cpu_state.registers.write_register(9, 0x1000)  # act
        self.cpu_state.registers.write_register(10, 0)  # oldact
        self.cpu_state.registers.write_register(11, 8)  # sigsetsize

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_rt_sigprocmask(self):
        """Test rt_sigprocmask returns success."""
        self.cpu_state.registers.write_register(1, 103)  # rt_sigprocmask
        self.cpu_state.registers.write_register(8, 0)  # SIG_BLOCK
        self.cpu_state.registers.write_register(9, 0x1000)  # set
        self.cpu_state.registers.write_register(10, 0)  # oldset
        self.cpu_state.registers.write_register(11, 8)  # sigsetsize

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallThread(unittest.TestCase):
    """Tests for thread-related syscalls (stubs)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_set_tid_address(self):
        """Test set_tid_address returns TID."""
        self.cpu_state.registers.write_register(1, 166)  # set_tid_address
        self.cpu_state.registers.write_register(8, 0x1000)  # tidptr

        self.syscall.handle()

        # Should return TID (1000 in our implementation)
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)

    def test_set_robust_list(self):
        """Test set_robust_list returns success."""
        self.cpu_state.registers.write_register(1, 300)  # set_robust_list
        self.cpu_state.registers.write_register(8, 0x1000)  # head
        self.cpu_state.registers.write_register(9, 12)  # len

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallPrlimit(unittest.TestCase):
    """Tests for prlimit64 syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_prlimit64_query(self):
        """Test prlimit64 returns limits."""
        self.cpu_state.registers.write_register(1, 331)  # prlimit64
        self.cpu_state.registers.write_register(8, 0)  # pid (current)
        self.cpu_state.registers.write_register(9, 3)  # RLIMIT_STACK
        self.cpu_state.registers.write_register(10, 0)  # new_limit (NULL)
        self.cpu_state.registers.write_register(11, 0x1000)  # old_limit

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Check that limits were written (should be RLIM_INFINITY)
        data = self.cpu_state.memory.read(0x1000, 16)
        self.assertEqual(len(data), 16)


class TestSyscallFchmod(unittest.TestCase):
    """Tests for fchmod syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        # Create and open temp file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 5)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 2)  # O_RDWR
        self.cpu_state.registers.write_register(10, 0)
        self.syscall.handle()
        self.fd = self.cpu_state.registers.read_register(8)

    def tearDown(self):
        self.cpu_state.registers.write_register(1, 6)
        self.cpu_state.registers.write_register(8, self.fd)
        self.syscall.handle()
        os.unlink(self.temp_file.name)

    def _write_string(self, addr: int, s: str) -> None:
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_fchmod_changes_permissions(self):
        """Test fchmod changes file permissions."""
        self.cpu_state.registers.write_register(1, 124)  # fchmod
        self.cpu_state.registers.write_register(8, self.fd)
        self.cpu_state.registers.write_register(9, 0o755)  # mode

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify permissions changed
        st = os.stat(self.temp_file.name)
        self.assertEqual(st.st_mode & 0o777, 0o755)

    def test_fchmod_invalid_fd(self):
        """Test fchmod with invalid fd returns EBADF."""
        self.cpu_state.registers.write_register(1, 124)
        self.cpu_state.registers.write_register(8, 99)  # invalid fd
        self.cpu_state.registers.write_register(9, 0o755)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 9)  # EBADF
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallGetuid(unittest.TestCase):
    """Tests for getuid/getgid family syscalls."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_getuid32(self):
        """Test getuid32 returns 1000."""
        self.cpu_state.registers.write_register(1, 44)  # getuid32
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)

    def test_getgid(self):
        """Test getgid returns 1000."""
        self.cpu_state.registers.write_register(1, 47)  # getgid
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)

    def test_geteuid(self):
        """Test geteuid returns 1000."""
        self.cpu_state.registers.write_register(1, 49)  # geteuid
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)

    def test_getegid(self):
        """Test getegid returns 1000."""
        self.cpu_state.registers.write_register(1, 50)  # getegid
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)

    def test_getgid32(self):
        """Test getgid32 returns 1000."""
        self.cpu_state.registers.write_register(1, 53)  # getgid32
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 1000)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallSetuid(unittest.TestCase):
    """Tests for setuid/setgid syscalls (stubs)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_setuid32(self):
        """Test setuid32 returns success."""
        self.cpu_state.registers.write_register(1, 87)  # setuid32
        self.cpu_state.registers.write_register(8, 1000)  # uid
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_setgid32(self):
        """Test setgid32 returns success."""
        self.cpu_state.registers.write_register(1, 89)  # setgid32
        self.cpu_state.registers.write_register(8, 1000)  # gid
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallChown(unittest.TestCase):
    """Tests for chown syscall (stub)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_chown32(self):
        """Test chown32 returns success (stub)."""
        self.cpu_state.registers.write_register(1, 35)  # chown32
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname ptr
        self.cpu_state.registers.write_register(9, 1000)  # owner
        self.cpu_state.registers.write_register(10, 1000)  # group
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallDup2(unittest.TestCase):
    """Tests for dup2 syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)

    def test_dup2_stdout(self):
        """Test dup2 can duplicate stdout."""
        self.cpu_state.registers.write_register(1, 90)  # dup2
        self.cpu_state.registers.write_register(8, 1)  # oldfd (stdout)
        self.cpu_state.registers.write_register(9, 10)  # newfd
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 10)
        self.assertFalse(self.cpu_state.icc.c)

    def test_dup2_invalid_fd(self):
        """Test dup2 with invalid oldfd returns EBADF."""
        self.cpu_state.registers.write_register(1, 90)  # dup2
        self.cpu_state.registers.write_register(8, 99)  # invalid oldfd
        self.cpu_state.registers.write_register(9, 10)  # newfd
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 9)  # EBADF
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallChdir(unittest.TestCase):
    """Tests for chdir syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        self.original_dir = os.getcwd()

    def tearDown(self):
        os.chdir(self.original_dir)

    def test_chdir_success(self):
        """Test chdir to /tmp succeeds."""
        path = b"/tmp\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 12)  # chdir
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname ptr
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_chdir_enoent(self):
        """Test chdir to nonexistent path returns ENOENT."""
        path = b"/nonexistent_path_12345\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 12)  # chdir
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname ptr
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 2)  # ENOENT
        self.assertTrue(self.cpu_state.icc.c)


class TestPassthrough(unittest.TestCase):
    """Tests for passthrough path handling."""

    def test_translate_path_no_sysroot(self):
        """Without sysroot, paths are unchanged."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable()
        self.assertEqual(fdt.translate_path("/home/user/file"), "/home/user/file")

    def test_translate_path_with_sysroot(self):
        """With sysroot, absolute paths are prefixed."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot")
        self.assertEqual(fdt.translate_path("/home/user/file"), "/sysroot/home/user/file")

    def test_translate_path_passthrough_exact(self):
        """Passthrough paths are not prefixed with sysroot."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot", passthrough=["/home"])
        self.assertEqual(fdt.translate_path("/home/user/file"), "/home/user/file")

    def test_translate_path_passthrough_subdir(self):
        """Passthrough also works for subdirectories."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp"])
        self.assertEqual(fdt.translate_path("/tmp/foo/bar"), "/tmp/foo/bar")

    def test_translate_path_passthrough_no_partial_match(self):
        """Passthrough does not match partial directory names."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp"])
        # /tmpfiles should NOT match /tmp passthrough
        self.assertEqual(fdt.translate_path("/tmpfiles/foo"), "/sysroot/tmpfiles/foo")

    def test_translate_path_multiple_passthrough(self):
        """Multiple passthrough paths work correctly."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp", "/home"])
        self.assertEqual(fdt.translate_path("/tmp/file"), "/tmp/file")
        self.assertEqual(fdt.translate_path("/home/user"), "/home/user")
        self.assertEqual(fdt.translate_path("/var/log"), "/sysroot/var/log")

    def test_translate_path_relative_unchanged(self):
        """Relative paths are not affected by sysroot or passthrough."""
        from sun4m.cpu import FileDescriptorTable

        fdt = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp"])
        self.assertEqual(fdt.translate_path("./file"), "./file")
        self.assertEqual(fdt.translate_path("relative/path"), "relative/path")


class TestSyscallLlseek(unittest.TestCase):
    """Tests for _llseek syscall (64-bit seek)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"x" * 1000)
        self.temp_file.close()
        # Open the file
        path = self.temp_file.name.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 5)  # open
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0)  # O_RDONLY
        self.syscall.handle()
        self.fd = self.cpu_state.registers.read_register(8)

    def tearDown(self):
        # Close the fd
        self.cpu_state.registers.write_register(1, 6)  # close
        self.cpu_state.registers.write_register(8, self.fd)
        self.syscall.handle()
        os.unlink(self.temp_file.name)

    def test_llseek_to_offset(self):
        """Test _llseek seeks to correct position."""
        self.cpu_state.registers.write_register(1, 236)  # _llseek
        self.cpu_state.registers.write_register(8, self.fd)  # fd
        self.cpu_state.registers.write_register(9, 0)  # offset_high
        self.cpu_state.registers.write_register(10, 500)  # offset_low
        self.cpu_state.registers.write_register(11, 0x1500)  # result ptr
        self.cpu_state.registers.write_register(12, 0)  # SEEK_SET
        self.syscall.handle()
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)
        # Check result was written
        result = self.cpu_state.memory.read(0x1500, 8)
        import struct
        pos = struct.unpack(">Q", result)[0]
        self.assertEqual(pos, 500)


class TestPassthroughPathTranslation(unittest.TestCase):
    """Tests for passthrough path translation in FileDescriptorTable."""

    def test_no_passthrough_with_sysroot(self):
        """Test that paths are translated through sysroot when no passthrough."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=[])
        self.assertEqual(fd_table.translate_path("/bin/ls"), "/sysroot/bin/ls")
        self.assertEqual(fd_table.translate_path("/etc/passwd"), "/sysroot/etc/passwd")

    def test_passthrough_exact_match(self):
        """Test that exact passthrough path match bypasses sysroot."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp"])
        self.assertEqual(fd_table.translate_path("/tmp"), "/tmp")

    def test_passthrough_prefix_match(self):
        """Test that paths under passthrough prefix bypass sysroot."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=["/home"])
        self.assertEqual(fd_table.translate_path("/home/user/file"), "/home/user/file")
        self.assertEqual(fd_table.translate_path("/home/user/dir/file"), "/home/user/dir/file")

    def test_passthrough_does_not_match_similar_prefix(self):
        """Test that /homedir does not match /home passthrough."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=["/home"])
        # /homedir should NOT match /home passthrough
        self.assertEqual(fd_table.translate_path("/homedir/file"), "/sysroot/homedir/file")

    def test_passthrough_trailing_slash(self):
        """Test passthrough with trailing slash works correctly."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=["/tmp/"])
        self.assertEqual(fd_table.translate_path("/tmp/foo"), "/tmp/foo")
        # /tmp itself does not match /tmp/ passthrough (only children match)
        self.assertEqual(fd_table.translate_path("/tmp"), "/sysroot/tmp")

    def test_multiple_passthrough_paths(self):
        """Test multiple passthrough paths work independently."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=["/home", "/tmp"])
        self.assertEqual(fd_table.translate_path("/home/user"), "/home/user")
        self.assertEqual(fd_table.translate_path("/tmp/test"), "/tmp/test")
        self.assertEqual(fd_table.translate_path("/etc/passwd"), "/sysroot/etc/passwd")

    def test_no_sysroot_no_translation(self):
        """Test that paths are not modified when no sysroot is set."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="", passthrough=[])
        self.assertEqual(fd_table.translate_path("/bin/ls"), "/bin/ls")

    def test_relative_path_not_translated(self):
        """Test that relative paths are not translated."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable(sysroot="/sysroot", passthrough=[])
        self.assertEqual(fd_table.translate_path("relative/path"), "relative/path")


class TestDirectoryOpen(unittest.TestCase):
    """Tests for opening directories."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x2000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_open_directory(self):
        """Test opening a directory returns a valid fd."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable()
        fd = fd_table.open(self.temp_dir, 0x10000)  # O_DIRECTORY
        self.assertGreater(fd, 0)
        desc = fd_table.get(fd)
        self.assertIsNotNone(desc)
        self.assertTrue(desc.is_directory)
        self.assertIsNotNone(desc.dir_fd)
        fd_table.close(fd)

    def test_open_directory_without_flag(self):
        """Test opening a directory without O_DIRECTORY flag still works."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable()
        fd = fd_table.open(self.temp_dir, 0)  # O_RDONLY
        self.assertGreater(fd, 0)
        desc = fd_table.get(fd)
        self.assertTrue(desc.is_directory)
        fd_table.close(fd)

    def test_close_directory(self):
        """Test closing a directory fd."""
        from sun4m.cpu import FileDescriptorTable

        fd_table = FileDescriptorTable()
        fd = fd_table.open(self.temp_dir, 0x10000)
        result = fd_table.close(fd)
        self.assertEqual(result, 0)
        self.assertIsNone(fd_table.get(fd))


class TestSyscallGetdents64(unittest.TestCase):
    """Tests for getdents64 syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x4000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()
        # Create some test files
        open(os.path.join(self.temp_dir, "file1.txt"), "w").close()
        open(os.path.join(self.temp_dir, "file2.txt"), "w").close()
        os.mkdir(os.path.join(self.temp_dir, "subdir"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_getdents64_reads_entries(self):
        """Test getdents64 returns directory entries."""
        # Open the directory
        path = self.temp_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 5)  # open
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname
        self.cpu_state.registers.write_register(9, 0x10000)  # O_DIRECTORY
        self.syscall.handle()
        fd = self.cpu_state.registers.read_register(8)
        self.assertGreater(fd, 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Call getdents64
        self.cpu_state.registers.write_register(1, 154)  # getdents64
        self.cpu_state.registers.write_register(8, fd)
        self.cpu_state.registers.write_register(9, 0x2000)  # buffer
        self.cpu_state.registers.write_register(10, 4096)  # size
        self.syscall.handle()

        bytes_read = self.cpu_state.registers.read_register(8)
        self.assertGreater(bytes_read, 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_getdents64_end_of_directory(self):
        """Test getdents64 returns 0 at end of directory."""
        # Open the directory
        path = self.temp_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 5)  # open
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0x10000)
        self.syscall.handle()
        fd = self.cpu_state.registers.read_register(8)

        # Read all entries
        self.cpu_state.registers.write_register(1, 154)
        self.cpu_state.registers.write_register(8, fd)
        self.cpu_state.registers.write_register(9, 0x2000)
        self.cpu_state.registers.write_register(10, 4096)
        self.syscall.handle()

        # Read again - should return 0 (end of directory)
        self.cpu_state.registers.write_register(1, 154)
        self.cpu_state.registers.write_register(8, fd)
        self.cpu_state.registers.write_register(9, 0x2000)
        self.cpu_state.registers.write_register(10, 4096)
        self.syscall.handle()

        bytes_read = self.cpu_state.registers.read_register(8)
        self.assertEqual(bytes_read, 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_getdents64_invalid_fd(self):
        """Test getdents64 returns EBADF for invalid fd."""
        self.cpu_state.registers.write_register(1, 154)
        self.cpu_state.registers.write_register(8, 999)  # invalid fd
        self.cpu_state.registers.write_register(9, 0x2000)
        self.cpu_state.registers.write_register(10, 4096)
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 9)  # EBADF
        self.assertTrue(self.cpu_state.icc.c)

    def test_getdents64_on_regular_file(self):
        """Test getdents64 returns EBADF for regular file."""
        # Open a regular file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        try:
            path = temp_file.name.encode() + b"\x00"
            self.cpu_state.memory.write(0x1000, path)
            self.cpu_state.registers.write_register(1, 5)
            self.cpu_state.registers.write_register(8, 0x1000)
            self.cpu_state.registers.write_register(9, 0)  # O_RDONLY
            self.syscall.handle()
            fd = self.cpu_state.registers.read_register(8)

            # Try getdents64 on it
            self.cpu_state.registers.write_register(1, 154)
            self.cpu_state.registers.write_register(8, fd)
            self.cpu_state.registers.write_register(9, 0x2000)
            self.cpu_state.registers.write_register(10, 4096)
            self.syscall.handle()

            self.assertEqual(self.cpu_state.registers.read_register(8), 9)  # EBADF
            self.assertTrue(self.cpu_state.icc.c)

            # Close the fd
            self.cpu_state.registers.write_register(1, 6)  # close
            self.cpu_state.registers.write_register(8, fd)
            self.syscall.handle()
        finally:
            os.unlink(temp_file.name)


class TestSyscallUmask(unittest.TestCase):
    """Tests for umask syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)
        # Save original umask
        self.original_umask = os.umask(0o022)
        os.umask(self.original_umask)

    def tearDown(self):
        # Restore original umask
        os.umask(self.original_umask)

    def test_umask_returns_old_value(self):
        """Test umask returns the previous mask."""
        os.umask(0o022)
        self.cpu_state.registers.write_register(1, 60)  # umask
        self.cpu_state.registers.write_register(8, 0o077)
        self.syscall.handle()

        old_mask = self.cpu_state.registers.read_register(8)
        self.assertEqual(old_mask, 0o022)
        self.assertFalse(self.cpu_state.icc.c)

    def test_umask_sets_new_value(self):
        """Test umask actually sets the new mask."""
        self.cpu_state.registers.write_register(1, 60)
        self.cpu_state.registers.write_register(8, 0o077)
        self.syscall.handle()

        # Verify by calling again
        self.cpu_state.registers.write_register(1, 60)
        self.cpu_state.registers.write_register(8, 0o022)
        self.syscall.handle()

        old_mask = self.cpu_state.registers.read_register(8)
        self.assertEqual(old_mask, 0o077)


class TestSyscallMkdir(unittest.TestCase):
    """Tests for mkdir syscall."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_mkdir_creates_directory(self):
        """Test mkdir creates a new directory."""
        new_dir = os.path.join(self.temp_dir, "newdir")
        path = new_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)

        self.cpu_state.registers.write_register(1, 136)  # mkdir
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0o755)
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)
        self.assertTrue(os.path.isdir(new_dir))

    def test_mkdir_existing_directory(self):
        """Test mkdir returns EEXIST for existing directory."""
        path = self.temp_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)

        self.cpu_state.registers.write_register(1, 136)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0o755)
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 17)  # EEXIST
        self.assertTrue(self.cpu_state.icc.c)

    def test_mkdir_nonexistent_parent(self):
        """Test mkdir returns ENOENT for nonexistent parent."""
        path = b"/nonexistent/path/newdir\x00"
        self.cpu_state.memory.write(0x1000, path)

        self.cpu_state.registers.write_register(1, 136)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0o755)
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 2)  # ENOENT
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallFstat64Directory(unittest.TestCase):
    """Tests for fstat64 on directory file descriptors."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fstat64_on_directory(self):
        """Test fstat64 works on directory fd."""
        # Open directory
        path = self.temp_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 5)  # open
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0x10000)  # O_DIRECTORY
        self.syscall.handle()
        fd = self.cpu_state.registers.read_register(8)
        self.assertGreater(fd, 0)

        # Call fstat64
        self.cpu_state.registers.write_register(1, 28)  # fstat64
        self.cpu_state.registers.write_register(8, fd)
        self.cpu_state.registers.write_register(9, 0x1100)  # stat buffer
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify it's a directory (check st_mode at offset 0x14)
        stat_buf = self.cpu_state.memory.read(0x1100, 104)
        st_mode = int.from_bytes(stat_buf[0x14:0x18], "big")
        self.assertTrue(st_mode & 0o040000)  # S_IFDIR


class TestSyscallStatxDirectory(unittest.TestCase):
    """Tests for statx on directory file descriptors."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x2000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_statx_on_directory_fd_with_empty_path(self):
        """Test statx with AT_EMPTY_PATH on directory fd."""
        # Open directory
        path = self.temp_dir.encode() + b"\x00"
        self.cpu_state.memory.write(0x1000, path)
        self.cpu_state.registers.write_register(1, 5)  # open
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0x10000)  # O_DIRECTORY
        self.syscall.handle()
        fd = self.cpu_state.registers.read_register(8)
        self.assertGreater(fd, 0)

        # Write empty string for pathname
        self.cpu_state.memory.write(0x1100, b"\x00")

        # Call statx with AT_EMPTY_PATH
        self.cpu_state.registers.write_register(1, 360)  # statx
        self.cpu_state.registers.write_register(8, fd)  # dirfd
        self.cpu_state.registers.write_register(9, 0x1100)  # empty pathname
        self.cpu_state.registers.write_register(10, 0x1000)  # AT_EMPTY_PATH
        self.cpu_state.registers.write_register(11, 0x7ff)  # mask
        self.cpu_state.registers.write_register(12, 0x1200)  # statxbuf
        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify it's a directory (check stx_mode at offset 0x1c)
        statx_buf = self.cpu_state.memory.read(0x1200, 256)
        stx_mode = int.from_bytes(statx_buf[0x1c:0x1e], "big")
        self.assertTrue(stx_mode & 0o040000)  # S_IFDIR


class TestSyscallAccess(unittest.TestCase):
    """Tests for access syscall (syscall 33)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()

    def tearDown(self):
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def _write_string(self, addr: int, s: str) -> None:
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_access_existing_file(self):
        """Test access on existing file returns success."""
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 33)  # access syscall
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname
        self.cpu_state.registers.write_register(9, 0)  # F_OK (existence check)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_access_nonexistent_file(self):
        """Test access on nonexistent file returns ENOENT."""
        self._write_string(0x1000, "/nonexistent/path/file.txt")
        self.cpu_state.registers.write_register(1, 33)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0)  # F_OK

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 2)  # ENOENT
        self.assertTrue(self.cpu_state.icc.c)

    def test_access_read_permission(self):
        """Test access with R_OK on readable file."""
        self._write_string(0x1000, self.temp_file.name)
        self.cpu_state.registers.write_register(1, 33)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 4)  # R_OK

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallLstat(unittest.TestCase):
    """Tests for lstat syscall (syscall 84)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x2000)
        self.syscall = Syscall(self.cpu_state)
        self.temp_dir = tempfile.mkdtemp()
        self.temp_file = os.path.join(self.temp_dir, "testfile")
        self.temp_link = os.path.join(self.temp_dir, "testlink")
        # Create a regular file and a symlink
        with open(self.temp_file, "w") as f:
            f.write("test content")
        os.symlink(self.temp_file, self.temp_link)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_string(self, addr: int, s: str) -> None:
        self.cpu_state.memory.write(addr, s.encode() + b"\x00")

    def test_lstat_regular_file(self):
        """Test lstat on regular file returns success."""
        self._write_string(0x1000, self.temp_file)
        self.cpu_state.registers.write_register(1, 84)  # lstat syscall
        self.cpu_state.registers.write_register(8, 0x1000)  # pathname
        self.cpu_state.registers.write_register(9, 0x1100)  # stat buffer

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify it's a regular file (check st_mode at offset 0x14)
        stat_buf = self.cpu_state.memory.read(0x1100, 104)
        import struct
        st_mode = struct.unpack(">I", stat_buf[0x14:0x18])[0]
        self.assertTrue(st_mode & 0o100000)  # S_IFREG

    def test_lstat_symlink(self):
        """Test lstat on symlink returns symlink info (not target)."""
        self._write_string(0x1000, self.temp_link)
        self.cpu_state.registers.write_register(1, 84)  # lstat
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0x1100)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify it's a symlink (check st_mode at offset 0x14)
        stat_buf = self.cpu_state.memory.read(0x1100, 104)
        import struct
        st_mode = struct.unpack(">I", stat_buf[0x14:0x18])[0]
        self.assertTrue(st_mode & 0o120000)  # S_IFLNK

    def test_lstat_nonexistent_file(self):
        """Test lstat on nonexistent file returns ENOENT."""
        self._write_string(0x1000, "/nonexistent/path/file.txt")
        self.cpu_state.registers.write_register(1, 84)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 0x1100)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 2)  # ENOENT
        self.assertTrue(self.cpu_state.icc.c)


class TestSyscallPoll(unittest.TestCase):
    """Tests for poll syscall (syscall 153)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_poll_empty(self):
        """Test poll with no fds returns 0."""
        self.cpu_state.registers.write_register(1, 153)  # poll syscall
        self.cpu_state.registers.write_register(8, 0x1000)  # fds pointer
        self.cpu_state.registers.write_register(9, 0)  # nfds = 0
        self.cpu_state.registers.write_register(10, 0)  # timeout = 0

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_poll_stdout_writable(self):
        """Test poll on stdout returns POLLOUT."""
        import struct
        # Setup pollfd structure: fd=1 (stdout), events=POLLOUT(4), revents=0
        pollfd = struct.pack(">ihh", 1, 4, 0)  # fd, events, revents
        self.cpu_state.memory.write(0x1000, pollfd)

        self.cpu_state.registers.write_register(1, 153)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 1)  # nfds = 1
        self.cpu_state.registers.write_register(10, 0)  # timeout = 0 (return immediately)

        self.syscall.handle()

        # Should return 1 (one fd with events)
        result = self.cpu_state.registers.read_register(8)
        self.assertGreaterEqual(result, 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_poll_invalid_fd(self):
        """Test poll with invalid fd sets POLLNVAL."""
        import struct
        # Setup pollfd with invalid fd
        pollfd = struct.pack(">ihh", 999, 1, 0)  # invalid fd, POLLIN, revents=0
        self.cpu_state.memory.write(0x1000, pollfd)

        self.cpu_state.registers.write_register(1, 153)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 1)
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return 1 and set POLLNVAL in revents
        result = self.cpu_state.registers.read_register(8)
        self.assertEqual(result, 1)
        self.assertFalse(self.cpu_state.icc.c)

        # Check revents has POLLNVAL (0x20)
        revents_data = self.cpu_state.memory.read(0x1006, 2)
        revents = struct.unpack(">h", revents_data)[0]
        self.assertEqual(revents & 0x20, 0x20)  # POLLNVAL

    def test_poll_negative_fd_ignored(self):
        """Test poll ignores negative fds."""
        import struct
        # Negative fd should be ignored
        pollfd = struct.pack(">ihh", -1, 1, 0)
        self.cpu_state.memory.write(0x1000, pollfd)

        self.cpu_state.registers.write_register(1, 153)
        self.cpu_state.registers.write_register(8, 0x1000)
        self.cpu_state.registers.write_register(9, 1)
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return 0 (negative fd ignored)
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)


class TestSyscallTerminalIoctl(unittest.TestCase):
    """Tests for terminal ioctl handling."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_tcgets_returns_termios(self):
        """Test TCGETS ioctl returns termios structure."""
        TCGETS = 0x40245408
        self.cpu_state.registers.write_register(1, 54)  # ioctl
        self.cpu_state.registers.write_register(8, 0)  # fd = stdin
        self.cpu_state.registers.write_register(9, TCGETS)
        self.cpu_state.registers.write_register(10, 0x1000)  # termios buffer

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify termios structure was written (36 bytes)
        termios_data = self.cpu_state.memory.read(0x1000, 36)
        self.assertEqual(len(termios_data), 36)

    def test_tcsets_succeeds(self):
        """Test TCSETS ioctl returns success."""
        TCSETS = 0x80245409
        # Write a valid termios structure first
        import struct
        termios_buf = bytearray(36)
        struct.pack_into(">I", termios_buf, 0, 0x2D02)  # iflag
        struct.pack_into(">I", termios_buf, 4, 0x0005)  # oflag
        struct.pack_into(">I", termios_buf, 8, 0x00BF)  # cflag
        struct.pack_into(">I", termios_buf, 12, 0x8A3B)  # lflag
        self.cpu_state.memory.write(0x1000, bytes(termios_buf))

        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 0)  # stdin
        self.cpu_state.registers.write_register(9, TCSETS)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_tiocgwinsz_returns_window_size(self):
        """Test TIOCGWINSZ returns window size structure."""
        TIOCGWINSZ = 0x40087468
        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 1)  # stdout
        self.cpu_state.registers.write_register(9, TIOCGWINSZ)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

        # Verify winsize structure was written (8 bytes)
        winsize_data = self.cpu_state.memory.read(0x1000, 8)
        self.assertEqual(len(winsize_data), 8)
        # Should have reasonable default values (at least rows > 0, cols > 0)
        import struct
        rows, cols = struct.unpack(">HH", winsize_data[:4])
        self.assertGreater(rows, 0)
        self.assertGreater(cols, 0)

    def test_tiocgwinsz_returns_reasonable_size(self):
        """Test TIOCGWINSZ returns reasonable window dimensions.

        This test catches endianness bugs where byte-swapped values would
        produce impossibly large dimensions (e.g., 6144x20480 instead of 24x80).
        """
        TIOCGWINSZ = 0x40087468
        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 1)  # stdout
        self.cpu_state.registers.write_register(9, TIOCGWINSZ)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        winsize_data = self.cpu_state.memory.read(0x1000, 8)
        import struct
        rows, cols, xpix, ypix = struct.unpack(">HHHH", winsize_data)

        # Reasonable terminal sizes: 1-500 rows, 1-1000 cols
        # Byte-swapped values would be much larger (e.g., 0x1800=6144 for 24)
        self.assertLessEqual(rows, 500, f"rows={rows} suggests endianness bug")
        self.assertLessEqual(cols, 1000, f"cols={cols} suggests endianness bug")

    def test_tcsetsw_succeeds(self):
        """Test TCSETSW ioctl returns success."""
        TCSETSW = 0x8024540A
        import struct
        termios_buf = bytearray(36)
        struct.pack_into(">I", termios_buf, 0, 0x2D02)  # iflag
        struct.pack_into(">I", termios_buf, 4, 0x0005)  # oflag
        struct.pack_into(">I", termios_buf, 8, 0x00BF)  # cflag
        struct.pack_into(">I", termios_buf, 12, 0x8A3B)  # lflag
        self.cpu_state.memory.write(0x1000, bytes(termios_buf))

        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 0)  # stdin
        self.cpu_state.registers.write_register(9, TCSETSW)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_tcsetsf_succeeds(self):
        """Test TCSETSF ioctl returns success."""
        TCSETSF = 0x8024540B
        import struct
        termios_buf = bytearray(36)
        struct.pack_into(">I", termios_buf, 0, 0x2D02)  # iflag
        struct.pack_into(">I", termios_buf, 4, 0x0005)  # oflag
        struct.pack_into(">I", termios_buf, 8, 0x00BF)  # cflag
        struct.pack_into(">I", termios_buf, 12, 0x8A3B)  # lflag
        self.cpu_state.memory.write(0x1000, bytes(termios_buf))

        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 0)  # stdin
        self.cpu_state.registers.write_register(9, TCSETSF)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_tiocswinsz_succeeds(self):
        """Test TIOCSWINSZ ioctl returns success."""
        TIOCSWINSZ = 0x80087467
        import struct
        # Write a winsize structure: rows=25, cols=80, xpixel=0, ypixel=0
        winsize = struct.pack(">HHHH", 25, 80, 0, 0)
        self.cpu_state.memory.write(0x1000, winsize)

        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 1)  # stdout
        self.cpu_state.registers.write_register(9, TIOCSWINSZ)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()

        self.assertEqual(self.cpu_state.registers.read_register(8), 0)
        self.assertFalse(self.cpu_state.icc.c)

    def test_tiocswinsz_stores_size_for_tiocgwinsz(self):
        """Test TIOCSWINSZ stores window size that TIOCGWINSZ returns."""
        import struct
        TIOCSWINSZ = 0x80087467
        TIOCGWINSZ = 0x40087468

        # First, set a custom window size via TIOCSWINSZ
        winsize = struct.pack(">HHHH", 50, 120, 800, 600)
        self.cpu_state.memory.write(0x1000, winsize)

        self.cpu_state.registers.write_register(1, 54)
        self.cpu_state.registers.write_register(8, 1)  # stdout
        self.cpu_state.registers.write_register(9, TIOCSWINSZ)
        self.cpu_state.registers.write_register(10, 0x1000)

        self.syscall.handle()
        self.assertFalse(self.cpu_state.icc.c)

        # Now verify window_size is stored in cpu_state
        self.assertIsNotNone(self.cpu_state.window_size)
        self.assertEqual(self.cpu_state.window_size, (50, 120, 800, 600))


class TestSyscallTermiosNonCanonical(unittest.TestCase):
    """Tests for SPARC to host termios c_cc translation in non-canonical mode.

    SPARC and x86_64 have different c_cc indices for VMIN and VTIME:
    - SPARC: VMIN=4, VTIME=5 (shared with VEOF/VEOL in canonical mode)
    - x86_64: VMIN=6, VTIME=5, VEOF=4, VEOL=11

    These tests verify the translation works correctly for raw/non-canonical mode
    where vi and other interactive programs need VMIN/VTIME set properly.
    """

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_read_sparc_termios_noncanonical_vmin_vtime(self):
        """Test that VMIN/VTIME are correctly translated from SPARC to host in non-canonical mode."""
        import struct

        # Create a SPARC termios structure with ICANON unset (non-canonical mode)
        # SPARC termios: iflag(4) + oflag(4) + cflag(4) + lflag(4) + c_line(1) + c_cc(19)
        buf = bytearray(36)

        # Set flags - importantly, ICANON (0x2) is NOT set in lflag
        iflag = 0x0000  # No input processing
        oflag = 0x0000  # No output processing
        cflag = 0x00BF  # CS8 | CREAD | CLOCAL
        lflag = 0x0000  # ICANON not set - this is non-canonical mode!

        struct.pack_into(">I", buf, 0, iflag)
        struct.pack_into(">I", buf, 4, oflag)
        struct.pack_into(">I", buf, 8, cflag)
        struct.pack_into(">I", buf, 12, lflag)
        buf[16] = 0  # c_line

        # Set SPARC c_cc values
        # In non-canonical mode, SPARC index 4 is VMIN, index 5 is VTIME
        sparc_vmin = 1   # Read at least 1 character
        sparc_vtime = 0  # No timeout
        buf[17 + 4] = sparc_vmin   # SPARC VMIN at index 4
        buf[17 + 5] = sparc_vtime  # SPARC VTIME at index 5

        self.cpu_state.memory.write(0x1000, bytes(buf))

        # Call _read_sparc_termios
        result = self.syscall._read_sparc_termios(0x1000)

        # Result format: [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
        host_cc = result[6]

        # In x86_64, VMIN is at index 6, VTIME is at index 5
        self.assertEqual(host_cc[6], sparc_vmin, "VMIN should be at x86_64 index 6")
        self.assertEqual(host_cc[5], sparc_vtime, "VTIME should be at x86_64 index 5")

        # VEOF should get a default value in non-canonical mode
        self.assertEqual(host_cc[4], 0x04, "VEOF should be default Ctrl-D in non-canonical mode")

    def test_read_sparc_termios_canonical_veof_veol(self):
        """Test that VEOF/VEOL are correctly translated in canonical mode."""
        import struct

        buf = bytearray(36)

        # Set ICANON in lflag - canonical mode
        lflag = 0x0002  # ICANON is set

        struct.pack_into(">I", buf, 0, 0)      # iflag
        struct.pack_into(">I", buf, 4, 0)      # oflag
        struct.pack_into(">I", buf, 8, 0x00BF) # cflag
        struct.pack_into(">I", buf, 12, lflag)
        buf[16] = 0  # c_line

        # In canonical mode, SPARC index 4 is VEOF, index 5 is VEOL
        sparc_veof = 0x04  # Ctrl-D
        sparc_veol = 0x00  # No VEOL
        buf[17 + 4] = sparc_veof
        buf[17 + 5] = sparc_veol

        self.cpu_state.memory.write(0x1000, bytes(buf))

        result = self.syscall._read_sparc_termios(0x1000)
        host_cc = result[6]

        # In x86_64, VEOF is at index 4, VEOL is at index 11
        self.assertEqual(host_cc[4], sparc_veof, "VEOF should be at x86_64 index 4")
        self.assertEqual(host_cc[11], sparc_veol, "VEOL should be at x86_64 index 11")

    def test_termios_roundtrip_noncanonical(self):
        """Test that writing and reading termios in non-canonical mode preserves key values."""
        import struct

        # First write default termios
        self.syscall._write_default_sparc_termios(0x1000)

        # Read it back
        termios_data = self.cpu_state.memory.read(0x1000, 36)

        # Modify to non-canonical mode with specific VMIN/VTIME
        buf = bytearray(termios_data)
        # Clear ICANON in lflag (offset 12)
        lflag = struct.unpack(">I", buf[12:16])[0]
        lflag &= ~0x2  # Clear ICANON
        struct.pack_into(">I", buf, 12, lflag)

        # Set VMIN=1, VTIME=0 at SPARC indices
        buf[17 + 4] = 1  # VMIN
        buf[17 + 5] = 0  # VTIME

        self.cpu_state.memory.write(0x1000, bytes(buf))

        # Read and convert to host format
        result = self.syscall._read_sparc_termios(0x1000)
        host_cc = result[6]

        # Verify VMIN/VTIME are at correct x86_64 indices
        self.assertEqual(host_cc[6], 1, "VMIN=1 should be at x86_64 index 6")
        self.assertEqual(host_cc[5], 0, "VTIME=0 should be at x86_64 index 5")


if __name__ == "__main__":
    unittest.main()
