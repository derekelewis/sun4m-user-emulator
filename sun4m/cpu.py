from sun4m.register import RegisterFile
from sun4m.memory import SystemMemory
from sun4m.decoder import decode


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

    def __init__(self, memory: SystemMemory | None = None, trace: bool = False):
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
            print(f"PC={self.pc:#010x} inst: {hex(inst_word)}")

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
