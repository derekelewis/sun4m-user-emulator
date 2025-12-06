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

    def load_file(self, file: str) -> int:
        with open(file, "rb") as f:
            elf_bytes = f.read()
            self.entrypoint = load_elf(self.memory, elf_bytes)
            # Initialise the CPU to start at the binary entrypoint.
            self.cpu.pc = self.entrypoint
            self.cpu.npc = (self.entrypoint + 4) & 0xFFFFFFFF
            # Initialize 64KB memory segment for stack
            self.cpu.memory.add_segment(0xFFFFFFF0 - 65536, 65536)
            # Initialize %sp to 0xFFFFFFF0
            self.cpu.registers.write_register(14, 0xFFFFFFF0)
            return self.entrypoint
