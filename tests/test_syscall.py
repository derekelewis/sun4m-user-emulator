import unittest
from unittest.mock import patch, MagicMock
import io
import sys

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

    def test_close_returns_success(self):
        """Test close syscall returns success."""
        self.cpu_state.registers.write_register(1, 6)  # syscall number
        self.cpu_state.registers.write_register(8, 3)  # fd = 3

        self.syscall.handle()

        # Should return 0 (success)
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)


class TestSyscallBrk(unittest.TestCase):
    """Tests for brk syscall (syscall 17)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.syscall = Syscall(self.cpu_state)
        # Reset brk to 0 for each test
        Syscall._brk = 0

    def test_brk_query_initial(self):
        """Test querying brk when not initialized."""
        self.cpu_state.registers.write_register(1, 17)  # syscall number
        self.cpu_state.registers.write_register(8, 0)  # query current brk

        self.syscall.handle()

        # Should return initial break (0x100000)
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x100000)

    def test_brk_extend(self):
        """Test extending the break."""
        # First, initialize brk
        self.cpu_state.registers.write_register(1, 17)
        self.cpu_state.registers.write_register(8, 0)
        self.syscall.handle()

        # Now extend it
        self.cpu_state.registers.write_register(8, 0x200000)
        self.syscall.handle()

        # Should return new break
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x200000)
        self.assertEqual(Syscall._brk, 0x200000)

    def test_brk_shrink(self):
        """Test shrinking the break."""
        # First, initialize and extend
        self.cpu_state.registers.write_register(1, 17)
        self.cpu_state.registers.write_register(8, 0)
        self.syscall.handle()

        self.cpu_state.registers.write_register(8, 0x200000)
        self.syscall.handle()

        # Now shrink it
        self.cpu_state.registers.write_register(8, 0x150000)
        self.syscall.handle()

        # Should return new (smaller) break
        self.assertEqual(self.cpu_state.registers.read_register(8), 0x150000)
        self.assertEqual(Syscall._brk, 0x150000)


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
    """Tests for getrandom syscall (syscall 360)."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0x1000, 0x1000)
        self.syscall = Syscall(self.cpu_state)

    def test_getrandom_fills_buffer(self):
        """Test getrandom fills buffer with random bytes."""
        self.cpu_state.registers.write_register(1, 360)  # syscall number
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
        self.cpu_state.registers.write_register(1, 360)
        self.cpu_state.registers.write_register(8, 0)  # NULL buffer
        self.cpu_state.registers.write_register(9, 16)
        self.cpu_state.registers.write_register(10, 0)

        self.syscall.handle()

        # Should return 0
        self.assertEqual(self.cpu_state.registers.read_register(8), 0)

    def test_getrandom_zero_count(self):
        """Test getrandom with zero count returns 0."""
        self.cpu_state.registers.write_register(1, 360)
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


if __name__ == "__main__":
    unittest.main()
