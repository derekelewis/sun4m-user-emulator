from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sun4m.cpu import CpuState

# SPARC/Linux errno values
EBADF = 9  # Bad file descriptor
ENOTTY = 25  # Not a typewriter (inappropriate ioctl for device)
ENOSYS = 38  # Function not implemented

# Page size for memory alignment
PAGE_SIZE = 4096


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
            case 6:
                self._syscall_close()
            case 17:
                self._syscall_brk()
            case 54:
                self._syscall_ioctl()
            case 188:
                self._syscall_exit()  # exit_group - same as exit for single-threaded
            case 360:
                self._syscall_getrandom()
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

        if fd == 0:  # STDIN
            data = sys.stdin.buffer.read(count)
            if data:
                self.cpu_state.memory.write(buf_ptr, data)
            self._return_success(len(data))
        else:
            self._return_error(EBADF)

    def _syscall_close(self):
        """
        Close syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
        Returns:
          %o0 = 0, carry clear on success
        """
        # Just return success for now
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

        if fd == 1:  # STDOUT
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            self._return_success(length)
        elif fd == 2:  # STDERR
            sys.stderr.buffer.write(data)
            sys.stderr.buffer.flush()
            self._return_success(length)
        else:
            self._return_error(EBADF)

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
