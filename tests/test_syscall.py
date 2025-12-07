import unittest
from unittest.mock import patch, MagicMock
import io
import os
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
        """Test ioctl returns ENOTTY for non-tty file descriptors."""
        self.cpu_state.registers.write_register(1, 54)  # syscall number
        self.cpu_state.registers.write_register(8, 1)  # fd = 1 (stdout)
        self.cpu_state.registers.write_register(9, 0x5401)  # TIOCGWINSZ
        self.cpu_state.registers.write_register(10, 0x1000)  # arg

        self.syscall.handle()

        # In test context, stdout is not a tty, so should return ENOTTY (25) with carry set
        self.assertEqual(self.cpu_state.registers.read_register(8), 25)
        self.assertTrue(self.cpu_state.icc.c)


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
        """Test exit_group syscall exits with the specified code."""
        self.cpu_state.registers.write_register(1, 188)  # syscall number
        self.cpu_state.registers.write_register(8, 42)  # exit code in %o0

        with self.assertRaises(SystemExit) as context:
            self.syscall.handle()

        self.assertEqual(context.exception.code, 42)

    def test_exit_group_exits_with_zero(self):
        """Test exit_group syscall exits with code 0."""
        self.cpu_state.registers.write_register(1, 188)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # exit code 0

        with self.assertRaises(SystemExit) as context:
            self.syscall.handle()

        self.assertEqual(context.exception.code, 0)


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


if __name__ == "__main__":
    unittest.main()
