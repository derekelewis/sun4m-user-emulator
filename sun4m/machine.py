from __future__ import annotations

import os
import struct

from .memory import SystemMemory, MMAP_BASE
from .elf import load_elf, load_elf_info, ElfInfo
from .cpu import CpuState


# Auxiliary vector types (from elf.h)
AT_NULL = 0  # End of vector
AT_IGNORE = 1  # Entry should be ignored
AT_EXECFD = 2  # File descriptor of program
AT_PHDR = 3  # Program headers for program
AT_PHENT = 4  # Size of program header entry
AT_PHNUM = 5  # Number of program headers
AT_PAGESZ = 6  # System page size
AT_BASE = 7  # Base address of interpreter
AT_FLAGS = 8  # Flags
AT_ENTRY = 9  # Entry point of program
AT_NOTELF = 10  # Program is not ELF
AT_UID = 11  # Real uid
AT_EUID = 12  # Effective uid
AT_GID = 13  # Real gid
AT_EGID = 14  # Effective gid
AT_PLATFORM = 15  # String identifying platform
AT_HWCAP = 16  # Machine-dependent hints about processor capabilities
AT_CLKTCK = 17  # Frequency of times()
AT_RANDOM = 25  # Address of 16 random bytes
AT_HWCAP2 = 26  # Extension of AT_HWCAP
AT_EXECFN = 31  # Filename of executable

# Interpreter base address (where we load ld-uClibc.so.0)
INTERP_BASE = MMAP_BASE  # 0x40000000


class Machine:

    def __init__(self, trace: bool = False, sysroot: str = ""):
        self.memory: SystemMemory = SystemMemory()
        # CpuState shares the same memory object to keep a single address space.
        self.cpu: CpuState = CpuState(memory=self.memory, trace=trace, sysroot=sysroot)
        self.entrypoint: int | None = None
        self.trace: bool = trace
        self.sysroot: str = sysroot

    def load_file(self, file: str, argv: list[str] | None = None) -> int:
        """Load an ELF file and set up execution environment.

        For dynamically linked executables, this also loads the interpreter
        and sets up the auxiliary vector for the dynamic linker.
        """
        with open(file, "rb") as f:
            elf_bytes = f.read()

        # Load the main executable
        main_info = load_elf_info(self.memory, elf_bytes, base_addr=0)
        self.entrypoint = main_info.entry_point

        # Load interpreter if present (dynamic linking)
        interp_info: ElfInfo | None = None
        if main_info.interpreter_path:
            interp_path = self._resolve_path(main_info.interpreter_path)
            if os.path.exists(interp_path):
                with open(interp_path, "rb") as f:
                    interp_bytes = f.read()
                interp_info = load_elf_info(
                    self.memory, interp_bytes, base_addr=INTERP_BASE
                )
                # For dynamic executables, start at interpreter entry point
                self.entrypoint = interp_info.entry_point

        # Initialise the CPU to start at the (possibly interpreter) entrypoint
        self.cpu.pc = self.entrypoint
        self.cpu.npc = (self.entrypoint + 4) & 0xFFFFFFFF

        # Initialize memory segments (after ELF is loaded to avoid conflicts)
        # Use a large stack for dynamic linking (16MB total)
        # Leave space above the "logical" stack top for SPARC ABI callers
        stack_size = 0x1000000  # 16MB
        stack_base = 0xD0000000
        self.cpu.memory.add_segment(stack_base, stack_size)
        # Set the logical stack top lower to leave headroom above SP
        stack_top = stack_base + stack_size - 0x100000  # Leave 1MB above

        # Add a segment at the top of address space for TLS/libc init
        self.cpu.memory.add_segment(0xFFFF0000, 0x10000)

        # Set up the stack with argc, argv, envp, auxv
        if argv is None:
            argv = [file]

        sp = self._setup_stack(
            stack_top, argv, main_info, interp_info
        )

        # Initialize %sp
        self.cpu.registers.write_register(14, sp)
        return self.entrypoint

    def _resolve_path(self, guest_path: str) -> str:
        """Resolve a guest path to host path using sysroot."""
        if self.sysroot and guest_path.startswith("/"):
            return self.sysroot + guest_path
        return guest_path

    def _setup_stack(
        self,
        stack_top: int,
        argv: list[str],
        main_info: ElfInfo,
        interp_info: ElfInfo | None,
    ) -> int:
        """Set up the stack with argc, argv, envp, auxv per SPARC ABI.

        Stack layout (growing down):
            [strings area - argv strings, env strings, platform string]
            [16 random bytes for AT_RANDOM]
            [padding for alignment]
            [auxv entries]
            [NULL - envp terminator]
            [envp pointers...]
            [NULL - argv terminator]
            [argv pointers...]
            [argc]
            [16-word register save area]  <- %sp points here

        Returns:
            The stack pointer value to use.
        """
        # Environment variables (for now, just empty or minimal)
        envp: list[str] = []

        # Reserve space at top of stack for various data
        # Start 256 bytes below stack_top for safety margin
        data_ptr = stack_top - 256

        # Write 16 random bytes for AT_RANDOM
        random_bytes = os.urandom(16)
        data_ptr -= 16
        data_ptr &= ~7  # Align to 8 bytes
        at_random_addr = data_ptr
        self.cpu.memory.write(at_random_addr, random_bytes)

        # Write platform string "sparc" for AT_PLATFORM
        platform = b"sparc\x00"
        data_ptr -= len(platform)
        platform_addr = data_ptr
        self.cpu.memory.write(platform_addr, platform)

        # Write executable filename for AT_EXECFN
        execfn = argv[0].encode("utf-8") + b"\x00"
        data_ptr -= len(execfn)
        execfn_addr = data_ptr
        self.cpu.memory.write(execfn_addr, execfn)

        # Write argv strings
        argv_string_addrs: list[int] = []
        for arg in argv:
            arg_bytes = arg.encode("utf-8") + b"\x00"
            data_ptr -= len(arg_bytes)
            self.cpu.memory.write(data_ptr, arg_bytes)
            argv_string_addrs.append(data_ptr)

        # Write envp strings
        envp_string_addrs: list[int] = []
        for env in envp:
            env_bytes = env.encode("utf-8") + b"\x00"
            data_ptr -= len(env_bytes)
            self.cpu.memory.write(data_ptr, env_bytes)
            envp_string_addrs.append(data_ptr)

        # Copy program headers to stack for AT_PHDR
        # The dynamic linker needs access to the main program's phdrs
        phdr_data = main_info.program_headers
        data_ptr -= len(phdr_data)
        data_ptr &= ~7  # Align
        phdr_stack_addr = data_ptr
        self.cpu.memory.write(phdr_stack_addr, phdr_data)

        # Align data_ptr for the arrays below
        data_ptr &= ~7

        # Build auxv entries
        auxv: list[tuple[int, int]] = []

        # AT_PHDR - address of program headers (on stack)
        auxv.append((AT_PHDR, phdr_stack_addr))
        # AT_PHENT - size of program header entry
        auxv.append((AT_PHENT, main_info.phdr_size))
        # AT_PHNUM - number of program headers
        auxv.append((AT_PHNUM, main_info.phdr_count))
        # AT_PAGESZ - page size
        auxv.append((AT_PAGESZ, 4096))
        # AT_BASE - interpreter base address (0 if no interpreter)
        auxv.append((AT_BASE, interp_info.base_address if interp_info else 0))
        # AT_FLAGS
        auxv.append((AT_FLAGS, 0))
        # AT_ENTRY - program entry point
        auxv.append((AT_ENTRY, main_info.entry_point))
        # AT_UID, AT_EUID, AT_GID, AT_EGID
        auxv.append((AT_UID, 1000))
        auxv.append((AT_EUID, 1000))
        auxv.append((AT_GID, 1000))
        auxv.append((AT_EGID, 1000))
        # AT_PLATFORM - platform string
        auxv.append((AT_PLATFORM, platform_addr))
        # AT_HWCAP - hardware capabilities (0 for basic SPARC)
        auxv.append((AT_HWCAP, 0))
        # AT_CLKTCK - clock ticks per second
        auxv.append((AT_CLKTCK, 100))
        # AT_RANDOM - 16 random bytes
        auxv.append((AT_RANDOM, at_random_addr))
        # AT_EXECFN - executable filename
        auxv.append((AT_EXECFN, execfn_addr))
        # AT_NULL - terminator
        auxv.append((AT_NULL, 0))

        # Calculate total size needed for pointers/values
        argc = len(argv)
        envc = len(envp)
        # Layout: 16 save words + argc + argv ptrs + NULL + envp ptrs + NULL + auxv
        # Each auxv entry is 2 words (type, value)
        pointer_area_size = (
            64  # 16-word register save area
            + 4  # argc
            + 4 * argc  # argv pointers
            + 4  # NULL
            + 4 * envc  # envp pointers
            + 4  # NULL
            + 8 * len(auxv)  # auxv entries (type + value each)
        )
        # Align to 8 bytes
        pointer_area_size = (pointer_area_size + 7) & ~7

        sp = data_ptr - pointer_area_size
        sp &= ~7  # Ensure 8-byte alignment

        # Write argc at sp + 64
        offset = 64
        self.cpu.memory.write(sp + offset, argc.to_bytes(4, "big"))
        offset += 4

        # Write argv pointers
        for addr in argv_string_addrs:
            self.cpu.memory.write(sp + offset, addr.to_bytes(4, "big"))
            offset += 4
        # NULL terminator for argv
        self.cpu.memory.write(sp + offset, (0).to_bytes(4, "big"))
        offset += 4

        # Write envp pointers
        for addr in envp_string_addrs:
            self.cpu.memory.write(sp + offset, addr.to_bytes(4, "big"))
            offset += 4
        # NULL terminator for envp
        self.cpu.memory.write(sp + offset, (0).to_bytes(4, "big"))
        offset += 4

        # Write auxv entries (pairs of 32-bit values)
        for atype, aval in auxv:
            self.cpu.memory.write(sp + offset, atype.to_bytes(4, "big"))
            offset += 4
            self.cpu.memory.write(sp + offset, (aval & 0xFFFFFFFF).to_bytes(4, "big"))
            offset += 4

        return sp
