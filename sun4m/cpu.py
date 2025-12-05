from sun4m.register import RegisterFile
from sun4m.memory import SystemMemory


class CpuState:
    """Represents the architectural state of the emulated CPU."""

    def __init__(self, memory: SystemMemory | None = None, trace: bool = False):
        self.trace: bool = trace
        self.pc: int = 0
        self.npc: int | None = None
        self.psr: int = 0
        self.registers: RegisterFile = RegisterFile()
        # Memory is shared with Machine; fall back to a private instance for
        # standalone CpuState usage in tests.
        self.memory: SystemMemory = memory if memory else SystemMemory()

    def _fetch_word(self, addr: int) -> int:
        """Fetch a 32-bit instruction from ``addr`` (big-endian)."""

        inst_bytes = self.memory.read(addr, 4)
        inst = int.from_bytes(inst_bytes, "big")
        if self.trace:
            print(f"_fetch_word: inst: {hex(inst)}")
        return inst

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

        inst_word = self._fetch_word(self.pc)
        # Local import to avoid circular dependency during module import.
        from .decoder import decode

        instruction = decode(inst_word)
        instruction.execute(self)

        # Advance pipeline: execute delay-slot semantics.
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
