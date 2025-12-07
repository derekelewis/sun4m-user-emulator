from .memory import SystemMemory
from .elf import load_elf
from .cpu import CpuState


class Machine:

    def __init__(self, trace: bool = False):
        self.memory: SystemMemory = SystemMemory()
        # CpuState shares the same memory object to keep a single address space.
        self.cpu: CpuState = CpuState(memory=self.memory, trace=trace)
        self.entrypoint: int | None = None
        self.trace: bool = trace

    def load_file(self, file: str, argv: list[str] | None = None) -> int:
        with open(file, "rb") as f:
            elf_bytes = f.read()
            self.entrypoint = load_elf(self.memory, elf_bytes)
            # Initialise the CPU to start at the binary entrypoint.
            self.cpu.pc = self.entrypoint
            self.cpu.npc = (self.entrypoint + 4) & 0xFFFFFFFF
            # Initialize 256KB memory segment for stack
            # Place it with room above for register save areas and argc/argv
            stack_size = 0x40000  # 256KB
            stack_base = 0xDFFC0000
            self.cpu.memory.add_segment(stack_base, stack_size)
            stack_top = stack_base + stack_size  # 0xE0000000
            # Add a segment at the top of address space for TLS/libc init
            # (addresses like 0xFFFFFFF8 are used for thread-local storage)
            self.cpu.memory.add_segment(0xFFFF0000, 0x10000)
            # Add low memory segment for libc initialization
            self.cpu.memory.add_segment(0x0, 0x10000)
            # Set up argc/argv on the stack per SPARC ABI.
            # Layout at %sp: 16-word register save area, then argc at %sp+64,
            # argv pointers starting at %sp+68, NULL terminator, then strings.
            if argv is None:
                argv = [file]
            argc = len(argv)
            # Build strings first to know their addresses. Place strings near
            # top of stack (but within segment bounds) and work downward.
            # Leave 256 bytes at top for safety margin.
            string_area = stack_top - 256
            string_addrs: list[int] = []
            for arg in argv:
                arg_bytes = arg.encode("utf-8") + b"\x00"
                string_area -= len(arg_bytes)
                self.cpu.memory.write(string_area, arg_bytes)
                string_addrs.append(string_area)
            # Align string_area down to 8 bytes
            string_area &= ~7
            # envp is empty (just a NULL pointer)
            # argv layout: argv[0..n-1], NULL, envp[0] (NULL)
            # We need space for: 16 save words + argc + argv ptrs + NULL + NULL
            # = 64 + 4 + 4*argc + 4 + 4 = 72 + 4*argc bytes
            frame_size = 64 + 4 + 4 * argc + 4 + 4
            # Align to 8 bytes
            frame_size = (frame_size + 7) & ~7
            sp = string_area - frame_size
            # Ensure sp is 8-byte aligned
            sp &= ~7
            # Write argc at sp + 64
            self.cpu.memory.write(sp + 64, argc.to_bytes(4, "big"))
            # Write argv pointers at sp + 68
            argv_offset = 68
            for addr in string_addrs:
                self.cpu.memory.write(sp + argv_offset, addr.to_bytes(4, "big"))
                argv_offset += 4
            # NULL terminator for argv
            self.cpu.memory.write(sp + argv_offset, (0).to_bytes(4, "big"))
            argv_offset += 4
            # NULL terminator for envp
            self.cpu.memory.write(sp + argv_offset, (0).to_bytes(4, "big"))
            # Initialize %sp
            self.cpu.registers.write_register(14, sp)
            return self.entrypoint
