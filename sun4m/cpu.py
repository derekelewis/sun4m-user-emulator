from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import IO

from sun4m.register import RegisterFile
from sun4m.memory import SystemMemory
from sun4m.decoder import decode


@dataclass
class FileDescriptor:
    """Represents an open file descriptor in the emulated process."""

    fd: int
    path: str
    file: IO[bytes] | None  # None for stdin/stdout/stderr (use sys.std*)
    position: int = 0
    flags: int = 0
    is_special: bool = False  # True for stdin/stdout/stderr


@dataclass
class FileDescriptorTable:
    """Manages file descriptors for the emulated process."""

    _table: dict[int, FileDescriptor] = field(default_factory=dict)
    _next_fd: int = 3  # Start after stdin/stdout/stderr
    sysroot: str = ""  # Path prefix for guest filesystem access

    def __post_init__(self) -> None:
        # Pre-populate stdin, stdout, stderr
        self._table[0] = FileDescriptor(fd=0, path="/dev/stdin", file=None, is_special=True)
        self._table[1] = FileDescriptor(fd=1, path="/dev/stdout", file=None, is_special=True)
        self._table[2] = FileDescriptor(fd=2, path="/dev/stderr", file=None, is_special=True)

    def translate_path(self, guest_path: str) -> str:
        """Translate a guest path to a host path using the sysroot."""
        if self.sysroot and guest_path.startswith("/"):
            return self.sysroot + guest_path
        return guest_path

    def open(self, path: str, flags: int, mode: int = 0o644) -> int:
        """Open a file and return its file descriptor, or negative errno on error."""
        import os

        host_path = self.translate_path(path)

        # Convert Linux O_* flags to Python mode string
        # Linux flags: O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, O_APPEND=0x400
        access_mode = flags & 3
        if access_mode == 0:
            py_mode = "rb"
        elif access_mode == 1:
            py_mode = "wb" if (flags & 0x200) else "r+b"  # O_TRUNC
            if flags & 0x400:  # O_APPEND
                py_mode = "ab"
        else:  # O_RDWR
            py_mode = "r+b"
            if flags & 0x40:  # O_CREAT
                py_mode = "w+b" if (flags & 0x200) else "r+b"

        try:
            # For O_CREAT, create parent dirs if needed and handle file creation
            if flags & 0x40:  # O_CREAT
                f = open(host_path, py_mode)
            else:
                f = open(host_path, py_mode)
        except FileNotFoundError:
            return -2  # ENOENT
        except PermissionError:
            return -13  # EACCES
        except IsADirectoryError:
            return -21  # EISDIR
        except OSError as e:
            return -e.errno if e.errno else -5  # EIO

        fd = self._next_fd
        self._next_fd += 1
        self._table[fd] = FileDescriptor(fd=fd, path=path, file=f, flags=flags)
        return fd

    def close(self, fd: int) -> int:
        """Close a file descriptor. Returns 0 on success, negative errno on error."""
        if fd not in self._table:
            return -9  # EBADF
        desc = self._table[fd]
        if desc.is_special:
            # Don't actually close stdin/stdout/stderr
            return 0
        if desc.file:
            desc.file.close()
        del self._table[fd]
        return 0

    def get(self, fd: int) -> FileDescriptor | None:
        """Get a file descriptor entry."""
        return self._table.get(fd)

    def read(self, fd: int, count: int) -> bytes | int:
        """Read from a file descriptor. Returns bytes or negative errno."""
        desc = self.get(fd)
        if desc is None:
            return -9  # EBADF
        if desc.is_special:
            if fd == 0:
                data = sys.stdin.buffer.read(count)
                return data if data else b""
            return -9  # Can't read from stdout/stderr
        if desc.file is None:
            return -9  # EBADF
        try:
            data = desc.file.read(count)
            desc.position += len(data)
            return data
        except OSError as e:
            return -e.errno if e.errno else -5

    def write(self, fd: int, data: bytes) -> int:
        """Write to a file descriptor. Returns bytes written or negative errno."""
        desc = self.get(fd)
        if desc is None:
            return -9  # EBADF
        if desc.is_special:
            if fd == 1:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                return len(data)
            elif fd == 2:
                sys.stderr.buffer.write(data)
                sys.stderr.buffer.flush()
                return len(data)
            return -9  # Can't write to stdin
        if desc.file is None:
            return -9  # EBADF
        try:
            written = desc.file.write(data)
            desc.position += written
            return written
        except OSError as e:
            return -e.errno if e.errno else -5

    def lseek(self, fd: int, offset: int, whence: int) -> int:
        """Seek in a file. Returns new position or negative errno."""
        desc = self.get(fd)
        if desc is None:
            return -9  # EBADF
        if desc.is_special:
            return -29  # ESPIPE - can't seek on pipe/socket
        if desc.file is None:
            return -9  # EBADF
        try:
            new_pos = desc.file.seek(offset, whence)
            desc.position = new_pos
            return new_pos
        except OSError as e:
            return -e.errno if e.errno else -5


class ICC:
    """Integer Condition Codes (N, Z, V, C)."""

    def __init__(self):
        self.n: bool = False  # Negative
        self.z: bool = False  # Zero
        self.v: bool = False  # Overflow
        self.c: bool = False  # Carry

    def update(self, result: int, op1: int, op2: int, is_sub: bool = False) -> None:
        """Update ICC based on an ALU operation result.

        Args:
            result: The 32-bit result of the operation (already masked).
            op1: First operand (32-bit).
            op2: Second operand (32-bit).
            is_sub: True for subtraction, False for addition.
        """
        # N: set if result is negative (bit 31 set)
        self.n = bool(result & 0x80000000)

        # Z: set if result is zero
        self.z = result == 0

        if is_sub:
            # For subtraction A - B:
            # C: set if there WAS a borrow (i.e., A < B as unsigned)
            self.c = (op1 & 0xFFFFFFFF) < (op2 & 0xFFFFFFFF)
            # V: overflow if signs of operands differ and sign of result
            # differs from sign of first operand
            op1_sign = bool(op1 & 0x80000000)
            op2_sign = bool(op2 & 0x80000000)
            result_sign = bool(result & 0x80000000)
            self.v = (op1_sign != op2_sign) and (result_sign != op1_sign)
        else:
            # For addition A + B:
            # C: set if carry out of bit 31
            full_result = (op1 & 0xFFFFFFFF) + (op2 & 0xFFFFFFFF)
            self.c = full_result > 0xFFFFFFFF
            # V: overflow if both operands have same sign but result differs
            op1_sign = bool(op1 & 0x80000000)
            op2_sign = bool(op2 & 0x80000000)
            result_sign = bool(result & 0x80000000)
            self.v = (op1_sign == op2_sign) and (result_sign != op1_sign)


class CpuState:
    """Represents the architectural state of the emulated CPU."""

    def __init__(
        self,
        memory: SystemMemory | None = None,
        trace: bool = False,
        sysroot: str = "",
    ):
        self.trace: bool = trace
        self.pc: int = 0
        self.npc: int | None = None
        self.psr: int = 0
        self.y: int = 0  # Y register for multiply/divide
        self.icc: ICC = ICC()  # Integer Condition Codes
        self.registers: RegisterFile = RegisterFile()
        # Memory is shared with Machine; fall back to a private instance for
        # standalone CpuState usage in tests.
        self.memory: SystemMemory = memory if memory else SystemMemory()
        # Flag set by branch instructions to annul the delay slot
        self.annul_next: bool = False
        # Program break address for brk syscall (heap management)
        self.brk: int = 0
        # File descriptor table for file I/O syscalls
        self.fd_table: FileDescriptorTable = FileDescriptorTable(sysroot=sysroot)
        # Path to the executable (for /proc/self/exe emulation)
        self.exe_path: str = ""

    def step(self):
        """
        Execute a single instruction and advance the PC/nPC pipeline.

        Semantics mirror SPARC's PC/nPC pair: PC points at the executing
        instruction; nPC points at the instruction after that (or a branch
        target). After execution we shift PC ← old nPC and set nPC to the
        next sequential address unless the instruction overrode it.
        """

        # Treat an unset nPC as sequential execution from the current PC.
        current_npc = self.npc if self.npc is not None else (self.pc + 4) & 0xFFFFFFFF

        # Default fallthrough for the instruction after *current_npc*.
        default_next_npc = (current_npc + 4) & 0xFFFFFFFF
        self.npc = default_next_npc

        inst_bytes = self.memory.read(self.pc, 4)
        inst_word = int.from_bytes(inst_bytes, "big")
        if self.trace:
            print(f"PC={self.pc:#010x} inst: {hex(inst_word)}", file=sys.stderr)

        instruction = decode(inst_word)
        instruction.execute(self)

        # Advance pipeline: execute delay-slot semantics.
        # If annul_next is set, skip the delay slot entirely.
        if self.annul_next:
            self.annul_next = False
            self.pc = self.npc & 0xFFFFFFFF
            self.npc = (self.npc + 4) & 0xFFFFFFFF
        else:
            self.pc = current_npc & 0xFFFFFFFF
            self.npc = self.npc & 0xFFFFFFFF
        return instruction

    def run(self, max_steps: int | None = None) -> None:
        """Run until ``max_steps`` is reached or a syscall terminates."""

        steps = 0
        while True:
            if max_steps is not None and steps >= max_steps:
                return
            self.step()
            steps += 1
