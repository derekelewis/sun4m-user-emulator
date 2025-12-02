import unittest
from sun4m.cpu import CpuState
from sun4m.instruction import CallInstruction, Format3Instruction


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
    def test_restore_instruction_simm13_execute(self):
        pass

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
