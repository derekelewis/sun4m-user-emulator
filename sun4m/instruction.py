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

    def execute(self): ...
