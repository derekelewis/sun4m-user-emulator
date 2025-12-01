import unittest
from sun4m.cpu import CpuState
from sun4m.instruction import CallInstruction


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
