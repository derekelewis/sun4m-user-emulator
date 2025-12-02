from .cpu import CpuState


class Instruction:

    def __init__(self, inst: int):
        self.inst = inst


class CallInstruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)
        self.disp30: int = self.inst & ((1 << 30) - 1)  # erase op bits
        if self.disp30 & (0b1 << 29):  # sign extend
            self.disp30 |= 0b11 << 30

    def execute(self, cpu_state: CpuState):
        # disp30 is word offset, so we need to multiple by 4 & wraparound on overflow
        cpu_state.npc = (cpu_state.pc + (self.disp30 << 2)) & 0xFFFFFFFF


class Format2Instruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)

    def execute(self): ...


class Format3Instruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)
        self.rd: int = self.inst >> 25 & 0b11111
        self.op3: int = self.inst >> 19 & 0b111111
        self.rs1: int = self.inst >> 14 & 0b11111
        self.i: int = self.inst >> 13 & 0b1
        if self.i:
            self.simm13: int = self.inst & 0b1111111111111
            if self.simm13 >> 12:  # negative signed
                self.simm13 -= 0x2000  # get the negative value
        else:
            self.rs2: int = self.inst & 0b11111

    def execute(self, cpu_state: CpuState):
        match self.op3:
            case 0b111100:  # SAVE instruction
                sp: int = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    sp = sp + self.simm13
                else:
                    sp = sp + cpu_state.registers.read_register(self.rs2)
                cpu_state.registers.cwp = (
                    cpu_state.registers.cwp - 1
                ) % cpu_state.registers.n_windows
                cpu_state.registers.write_register(self.rd, sp)
            case 0b111101:  # RESTORE instruction
                ...

    def __str__(self) -> str:
        inst_string: str = (
            f"rd: {self.rd}, op3: {self.op3}, rs1: {self.rs1}, i: {self.i}"
        )
        if self.i:
            inst_string += f", simm13: {self.simm13}"
        else:
            inst_string += f", rs2: {self.rs2}"
        return inst_string
