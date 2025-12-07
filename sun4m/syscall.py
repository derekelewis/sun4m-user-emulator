from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sun4m.cpu import CpuState


class Syscall:
    # Track program break for brk syscall (class variable shared across instances)
    _brk: int = 0

    def __init__(self, cpu_state: CpuState):
        self.cpu_state = cpu_state

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
          %o0 = number of bytes read (or -1 on error)
        """
        fd = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        count = self.cpu_state.registers.read_register(10)

        if fd == 0:  # STDIN
            data = sys.stdin.buffer.read(count)
            if data:
                self.cpu_state.memory.write(buf_ptr, data)
                self.cpu_state.registers.write_register(8, len(data))
            else:
                self.cpu_state.registers.write_register(8, 0)  # EOF
        else:
            # Unsupported fd
            self.cpu_state.registers.write_register(8, 0xFFFFFFFF)  # -1

    def _syscall_close(self):
        """
        Close syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
        Returns:
          %o0 = 0 on success, -1 on error
        """
        # Just return success for now
        self.cpu_state.registers.write_register(8, 0)

    def _syscall_write(self):
        """
        Write syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = buffer pointer
          %o2 (reg 10) = length
        Returns:
          %o0 = number of bytes written (or -1 on error)
        """

        fd = self.cpu_state.registers.read_register(8)
        buf_ptr = self.cpu_state.registers.read_register(9)
        length = self.cpu_state.registers.read_register(10)

        data = self.cpu_state.memory.read(buf_ptr, length)

        if fd == 1:  # STDOUT
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            self.cpu_state.registers.write_register(8, length)
        elif fd == 2:  # STDERR
            sys.stderr.buffer.write(data)
            sys.stderr.buffer.flush()
            self.cpu_state.registers.write_register(8, length)
        else:
            # Unsupported fd
            self.cpu_state.registers.write_register(8, 0xFFFFFFFF)  # write -1 (error)

    def _syscall_brk(self):
        """
        brk syscall implementation
        Arguments:
          %o0 (reg 8) = new break address (0 = query current)
        Returns:
          %o0 = current break address on success, -1 on error
        """
        new_brk = self.cpu_state.registers.read_register(8)

        # Initialize brk to a reasonable heap start if not set
        if Syscall._brk == 0:
            # Set initial break to 0x100000 (1MB) - above typical code/data
            Syscall._brk = 0x100000
            # Create initial heap segment
            self.cpu_state.memory.add_segment(Syscall._brk, 0x100000)

        if new_brk == 0:
            # Query current break
            self.cpu_state.registers.write_register(8, Syscall._brk)
        elif new_brk > Syscall._brk:
            # Extend the heap - for simplicity, we just update the break
            # In a real implementation, we'd need to extend the memory segment
            old_brk = Syscall._brk
            Syscall._brk = new_brk
            self.cpu_state.registers.write_register(8, Syscall._brk)
        else:
            # Shrink or same - just update and return
            Syscall._brk = new_brk
            self.cpu_state.registers.write_register(8, Syscall._brk)

    def _syscall_ioctl(self):
        """
        ioctl syscall implementation
        Arguments:
          %o0 (reg 8) = file descriptor
          %o1 (reg 9) = request code
          %o2 (reg 10) = argument
        Returns:
          %o0 = 0 on success, -errno on error
        """
        fd = self.cpu_state.registers.read_register(8)
        request = self.cpu_state.registers.read_register(9)
        # For TIOCGWINSZ (get window size) and similar, return -ENOTTY
        # This tells the program it's not a tty
        # ENOTTY = 25 on SPARC
        self.cpu_state.registers.write_register(8, (-25) & 0xFFFFFFFF)

    def _syscall_getrandom(self):
        """
        getrandom syscall implementation
        Arguments:
          %o0 (reg 8) = buffer pointer
          %o1 (reg 9) = count
          %o2 (reg 10) = flags
        Returns:
          %o0 = number of bytes written, or -errno on error
        """
        buf_ptr = self.cpu_state.registers.read_register(8)
        count = self.cpu_state.registers.read_register(9)
        if buf_ptr == 0 or count == 0:
            # NULL pointer or zero count - return 0
            self.cpu_state.registers.write_register(8, 0)
            return
        # Generate random bytes
        random_bytes = os.urandom(count)
        self.cpu_state.memory.write(buf_ptr, random_bytes)
        self.cpu_state.registers.write_register(8, count)
