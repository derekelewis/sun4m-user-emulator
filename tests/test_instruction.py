import unittest

from sun4m.cpu import CpuState
from sun4m.instruction import CallInstruction, Format3Instruction, Format2Instruction


class TestInstruction(unittest.TestCase):

    def test_call_instruction_decode(self):
        inst: int = 0x7FFFFFFF
        call_instruction: CallInstruction = CallInstruction(inst)
        self.assertEqual(call_instruction.disp30, 0xFFFFFFFF)

    def test_call_instruction_execute(self):
        inst: int = 0x40000020  # jump 32 words
        call_instruction: CallInstruction = CallInstruction(inst)
        self.assertEqual(call_instruction.disp30, 0x20)
        cpu_state: CpuState = CpuState()
        call_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.pc, 0)
        # multiply word offset by 4 for word alignment
        self.assertEqual(cpu_state.npc, 0x20 * 4)

    def test_save_instruction_simm13_execute(self):
        inst: int = 0x9DE3BFA0  # SAVE %sp, -96, %sp
        save_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(save_instruction.rd, 14)  # %o6/%sp
        self.assertEqual(save_instruction.op3, 0b111100)  # op3 for SAVE
        self.assertEqual(save_instruction.rs1, 14)  # %o6/%sp
        self.assertEqual(save_instruction.i, 1)
        self.assertEqual(save_instruction.simm13, -96)
        cpu_state: CpuState = CpuState()
        save_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.cwp, 7)
        self.assertEqual(cpu_state.registers.read_register(14), -96)

    # TODO: need test_save_instruction_rs2_execute
    def test_save_instruction_rs2_execute(self): ...

    # TODO: need test_restore_instruction_simm13_execute
    def test_restore_instruction_simm13_execute(self): ...

    # TODO: need more than just RESTORE %g0, %g0, %g0
    def test_restore_instruction_rs2_execute(self):
        inst: int = 0x81E80000  # RESTORE %g0, %g0, %g0 / RESTORE
        save_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(save_instruction.rd, 0)  # %g0
        self.assertEqual(save_instruction.op3, 0b111101)  # op3 for SAVE
        self.assertEqual(save_instruction.rs1, 0)  # %g0
        self.assertEqual(save_instruction.i, 0)  # not using immediate
        self.assertEqual(save_instruction.rs2, 0)
        cpu_state: CpuState = CpuState()
        save_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.cwp, 1)
        self.assertEqual(cpu_state.registers.read_register(0), 0)

    def test_sethi_instruction_execute(self):
        inst: int = 0x03000040  # SETHI %hi(0x10000), %g1
        sethi_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(sethi_instruction.rd, 1)  # %g1
        self.assertEqual(sethi_instruction.imm22, 0b1000000)
        cpu_state: CpuState = CpuState()
        sethi_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(1), 0x10000)

    def test_or_instruction_simm13_execute(self):
        inst: int = 0x901060F0  # OR %g1, 0xf0, %o0
        or_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(or_instruction.rd, 8)  # %o0
        self.assertEqual(or_instruction.op3, 0b000010)  # op3 for OR
        self.assertEqual(or_instruction.rs1, 1)  # %g1
        self.assertEqual(or_instruction.i, 1)
        self.assertEqual(or_instruction.simm13, 0xF0)
        cpu_state: CpuState = CpuState()
        or_instruction.execute(cpu_state)
        self.assertEqual(
            cpu_state.registers.read_register(8),
            cpu_state.registers.read_register(1) | 0xF0,
        )

    # TODO: need test_or_instruction_rs2_execute
    def test_or_instruction_rs2_execute(self): ...

    def test_ld_instruction_simm13_execute(self):
        inst: int = 0xC407A044  # ld [ %fp + 0x44 ], %g2
        ld_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ld_instruction.rd, 2)  # %g2
        self.assertEqual(ld_instruction.op3, 0)  # op3 for LD
        self.assertEqual(ld_instruction.rs1, 30)  # %i6/%fp
        self.assertEqual(ld_instruction.i, 1)
        self.assertEqual(ld_instruction.simm13, 0x44)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        test_bytes: bytes = "hello, world".encode()
        cpu_state.memory.write(0x44, test_bytes)
        ld_instruction.execute(cpu_state)
        self.assertEqual(
            int.from_bytes(test_bytes[:4], "big"), cpu_state.registers.read_register(2)
        )

    def test_st_instruction_simm13_execute(self):
        inst: int = 0xF027A044  # ST %i0, [ %fp + 0x44 ]
        st_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(st_instruction.rd, 24)  # %i0
        self.assertEqual(st_instruction.op3, 4)  # op3 for ST
        self.assertEqual(st_instruction.rs1, 30)  # %i6/%fp
        self.assertEqual(st_instruction.i, 1)
        self.assertEqual(st_instruction.simm13, 0x44)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        test_bytes: bytes = "hello, world".encode()
        cpu_state.registers.write_register(
            st_instruction.rd, int.from_bytes(test_bytes[:4], "big")
        )
        st_instruction.execute(cpu_state)
        self.assertEqual(test_bytes[:4], cpu_state.memory.read(0x44, 4))

    def test_jmpl_instruction_simm13_execute(self):
        inst: int = 0x81C3E008  # JMPL [%o7 + 8], %g0
        jmpl_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(jmpl_instruction.rd, 0)
        self.assertEqual(jmpl_instruction.op3, 0b111000)
        self.assertEqual(jmpl_instruction.rs1, 15)
        self.assertEqual(jmpl_instruction.i, 1)
        self.assertEqual(jmpl_instruction.simm13, 0x8)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x100
        cpu_state.npc = 0x104
        cpu_state.registers.write_register(15, 0x200)
        jmpl_instruction.execute(cpu_state)
        breakpoint()
