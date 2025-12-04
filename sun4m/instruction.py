from .cpu import CpuState


class Instruction:

    def __init__(self, inst: int):
        self.inst = inst

    def execute(self, cpu_state: CpuState):
        pass


class CallInstruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)
        self.disp30: int = self.inst & ((1 << 30) - 1)  # erase op bits
        if self.disp30 & (0b1 << 29):  # sign extend
            self.disp30 |= 0b11 << 30

    def execute(self, cpu_state: CpuState):
        # disp30 is word offset, so we need to multiply by 4 & wraparound on overflow
        cpu_state.npc = (cpu_state.pc + (self.disp30 << 2)) & 0xFFFFFFFF


class Format2Instruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)
        self.rd: int = self.inst >> 25 & 0b11111
        self.op2: int = self.inst >> 22 & 0b111
        if self.op2 == 0b100:
            self.imm22: int = self.inst & 0b11_1111_1111_1111_1111_1111

    def execute(self, cpu_state: CpuState):
        match self.op2:
            case 0b100:  # SETHI instruction
                value: int = self.imm22 << 10
                cpu_state.registers.write_register(self.rd, value)

    def __str__(self) -> str:
        inst_string: str = f"rd: {self.rd}, op2: {self.op2}"
        if self.op2 == 0b100:
            inst_string += f", imm22: {self.imm22}"
        return inst_string


class TrapInstruction(Instruction):

    def __init__(self, inst: int):
        super().__init__(inst)
        self.op3: int = self.inst >> 19 & 0b111111
        self.rs1: int = self.inst >> 14 & 0b11111
        self.i: int = self.inst >> 13 & 0b1
        self.cond: int = self.inst >> 25 & 0b1111
        if self.i:
            self.imm7: int = self.inst & 0b1111111  # not signed
        else:
            self.rs2: int = self.inst & 0b11111

    def execute(self, cpu_state: CpuState): ...

    # TODO: finish implementing TrapInstruction.execute()

    def __str__(self) -> str:
        inst_string: str = (
            f"op3: {self.op3}, rs1: {self.rs1}, i: {self.i}, cond: {self.cond}"
        )
        if self.i:
            inst_string += f", simm13: {self.imm7}"
        else:
            inst_string += f", rs2: {self.rs2}"
        return inst_string


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
            case 0b000000:  # LD instruction
                if self.i:
                    memory_address: int = (
                        cpu_state.registers.read_register(self.rs1) + self.simm13
                    ) & 0xFFFFFFFF
                    # TODO: raise exception on unaligned memory access
                    load_word = cpu_state.memory.read(memory_address, 4)
                    cpu_state.registers.write_register(
                        self.rd, int.from_bytes(load_word, "big")
                    )
                else:
                    # supervisor only
                    raise ValueError("not implemented")
            case 0b000100:  # ST instruction
                if self.i:
                    memory_address: int = (
                        cpu_state.registers.read_register(self.rs1) + self.simm13
                    ) & 0xFFFFFFFF
                    store_word: int = cpu_state.registers.read_register(self.rd)
                    # TODO: raise exception on unaligned memory access
                    cpu_state.memory.write(
                        memory_address, store_word.to_bytes(4, byteorder="big")
                    )
                else:
                    # supervisor only
                    raise ValueError("not implemented")
            case 0b000010:  # OR instruction
                if self.i:
                    cpu_state.registers.write_register(
                        self.rd,
                        cpu_state.registers.read_register(self.rs1) | self.simm13,
                    )
                else:
                    cpu_state.registers.write_register(
                        self.rd,
                        cpu_state.registers.read_register(self.rs1)
                        | cpu_state.registers.read_register(self.rs2),
                    )
            case 0b111000:  # JMPL instruction
                # TODO: check for alignment
                cpu_state.registers.write_register(self.rd, cpu_state.pc)
                if self.i:
                    cpu_state.npc = (
                        cpu_state.registers.read_register(self.rs1) + self.simm13
                    ) & 0xFFFFFFFF
                else:
                    cpu_state.npc = (
                        cpu_state.registers.read_register(self.rs1)
                        + cpu_state.registers.read_register(self.rs2)
                    ) & 0xFFFFFFFF
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
                sp: int = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    sp = sp + self.simm13
                else:
                    sp = sp + cpu_state.registers.read_register(self.rs2)
                cpu_state.registers.cwp = (
                    cpu_state.registers.cwp + 1
                ) % cpu_state.registers.n_windows
                cpu_state.registers.write_register(self.rd, sp)
            case _:
                raise ValueError("unimplemented opcode")

    def __str__(self) -> str:
        inst_string: str = (
            f"rd: {self.rd}, op3: {self.op3}, rs1: {self.rs1}, i: {self.i}"
        )
        if self.i:
            inst_string += f", simm13: {self.simm13}"
        else:
            inst_string += f", rs2: {self.rs2}"
        return inst_string
