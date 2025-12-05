import unittest

from sun4m.cpu import CpuState
from sun4m.machine import Machine


class TestCpuStepping(unittest.TestCase):

    def test_machine_and_cpu_share_memory(self):
        machine = Machine()
        machine.memory.add_segment(0x0, 0x20)

        machine.memory.write(0x0, b"\xAA\xBB\xCC\xDD")
        self.assertEqual(machine.cpu.memory.read(0x0, 4), b"\xAA\xBB\xCC\xDD")

        machine.cpu.memory.write(0x4, b"\x11\x22\x33\x44")
        self.assertEqual(machine.memory.read(0x4, 4), b"\x11\x22\x33\x44")

    def test_step_advances_pc_when_npc_unset(self):
        cpu = CpuState()
        cpu.memory.add_segment(0x100, 0x20)
        nop = 0x01000000  # SETHI 0, %g0 (architectural NOP)
        cpu.memory.write(0x100, nop.to_bytes(4, "big"))

        cpu.pc = 0x100
        cpu.npc = None # exercise default nPC handling

        cpu.step()

        self.assertEqual(cpu.pc, 0x104)
        self.assertEqual(cpu.npc, 0x108)

    def test_call_updates_npc_and_pipeline(self):
        cpu = CpuState()
        cpu.memory.add_segment(0x200, 0x40)

        # CALL to 0x300 from 0x200: disp30 = (0x300 - 0x200) >> 2 = 0x40
        call_inst = (1 << 30) | 0x40
        cpu.memory.write(0x200, call_inst.to_bytes(4, "big"))

        cpu.pc = 0x200
        cpu.npc = 0x204

        cpu.step()

        self.assertEqual(cpu.pc, 0x204)  # advance into delay slot
        self.assertEqual(cpu.npc, 0x300)  # branch target for next cycle

