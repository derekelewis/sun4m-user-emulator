from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sun4m.cpu import CpuState


class Syscall:

    def __init__(self, cpu_state: CpuState):
        self.cpu_state = cpu_state

    def handle(self):
        # Get syscall number from %g1
        syscall_number: int = self.cpu_state.registers.read_register(1)

        match syscall_number:
            case 1:
                self._syscall_exit()
            case 4:
                self._syscall_write()
            case _:
                raise ValueError("syscall not implemented")

    def _syscall_exit(self):
        """
        Exit syscall implementation
        Arguments:
          %o0 (reg 8) = exit code
        """
        exit_code = self.cpu_state.registers.read_register(8)
        sys.exit(exit_code)

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
