import unittest

from sun4m.cpu import CpuState
from sun4m.instruction import (
    CallInstruction,
    Format3Instruction,
    Format2Instruction,
    TrapInstruction,
)


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
        cpu_state.pc = 0x1000
        call_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.pc, 0x1000)
        # multiply word offset by 4 for word alignment
        self.assertEqual(cpu_state.npc, 0x1000 + (0x20 * 4))
        self.assertEqual(cpu_state.registers.read_register(15), cpu_state.pc)

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
        # CWP wraps from 0 to n_windows-1
        self.assertEqual(cpu_state.registers.cwp, cpu_state.registers.n_windows - 1)
        self.assertEqual(cpu_state.registers.read_register(14), (-96) & 0xFFFFFFFF)

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

    # TODO: need test_jmpl_instruction_rs2_execute:
    def test_jump_instruction_rs2_execute(self):
        pass

    def test_ta_instruction_imm7_execute(self):
        inst: int = 0x91D02010  # TA 0x10
        ta_instruction: TrapInstruction = TrapInstruction(inst)
        self.assertEqual(ta_instruction.op3, 0b111010)
        self.assertEqual(ta_instruction.rs1, 0)
        self.assertEqual(ta_instruction.i, 1)
        self.assertEqual(ta_instruction.cond, 0b1000)
        self.assertEqual(ta_instruction.imm7, 0b10000)
        cpu_state: CpuState = CpuState()
        with self.assertRaises(ValueError) as e:
            ta_instruction.execute(cpu_state)
        self.assertEqual(str(e.exception), "syscall 0 not implemented")

    # TODO: need test_ta_instruction_rs2_execute
    def test_ta_instruction_rs2_execute(self): ...

    # --- ADD instruction tests ---

    def test_add_instruction_simm13_execute(self):
        # ADD %g1, 10, %g2 -> op=2, rd=2, op3=0, rs1=1, i=1, simm13=10
        # Encoding: 10 00010 000000 00001 1 0000000001010
        inst: int = 0x8400600A  # ADD %g1, 10, %g2
        add_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(add_instruction.op, 2)
        self.assertEqual(add_instruction.rd, 2)
        self.assertEqual(add_instruction.op3, 0b000000)
        self.assertEqual(add_instruction.rs1, 1)
        self.assertEqual(add_instruction.i, 1)
        self.assertEqual(add_instruction.simm13, 10)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        add_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 110)

    def test_add_instruction_rs2_execute(self):
        # ADD %g1, %g3, %g2 -> op=2, rd=2, op3=0, rs1=1, i=0, rs2=3
        inst: int = 0x84004003  # ADD %g1, %g3, %g2
        add_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(add_instruction.op, 2)
        self.assertEqual(add_instruction.i, 0)
        self.assertEqual(add_instruction.rs2, 3)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(3, 50)
        add_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 150)

    def test_add_instruction_overflow(self):
        # Test wrap-around at 32-bit boundary
        inst: int = 0x8400600A  # ADD %g1, 10, %g2
        add_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFFFFFFF8)  # -8 as unsigned
        add_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 2)  # wraparound

    # --- SUB instruction tests ---

    def test_sub_instruction_simm13_execute(self):
        # SUB %g1, 10, %g2 -> op=2, rd=2, op3=4, rs1=1, i=1, simm13=10
        inst: int = 0x8420600A  # SUB %g1, 10, %g2
        sub_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(sub_instruction.op3, 0b000100)
        self.assertEqual(sub_instruction.simm13, 10)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        sub_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 90)

    def test_sub_instruction_rs2_execute(self):
        # SUB %g1, %g3, %g2 -> op=2, rd=2, op3=4, rs1=1, i=0, rs2=3
        inst: int = 0x84204003  # SUB %g1, %g3, %g2
        sub_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(3, 30)
        sub_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 70)

    # --- SUBCC instruction tests ---

    def test_subcc_instruction_sets_zero_flag(self):
        # SUBCC %g1, %g1, %g0 (effectively cmp %g1, %g1)
        inst: int = 0x80A04001  # SUBCC %g1, %g1, %g0
        subcc_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(subcc_instruction.op3, 0b010100)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 42)
        subcc_instruction.execute(cpu_state)
        self.assertTrue(cpu_state.icc.z)
        self.assertFalse(cpu_state.icc.n)
        self.assertFalse(cpu_state.icc.v)

    def test_subcc_instruction_sets_negative_flag(self):
        # SUBCC %g1, 100, %g2 where g1 < 100
        inst: int = 0x84A06064  # SUBCC %g1, 100, %g2
        subcc_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 50)
        subcc_instruction.execute(cpu_state)
        self.assertTrue(cpu_state.icc.n)  # result is negative
        self.assertFalse(cpu_state.icc.z)

    def test_subcc_cmp_equal(self):
        # CMP %g1, %g2 is SUBCC %g1, %g2, %g0
        inst: int = 0x80A04002  # SUBCC %g1, %g2, %g0
        subcc_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 100)
        subcc_instruction.execute(cpu_state)
        self.assertTrue(cpu_state.icc.z)

    # --- SRA instruction tests ---

    def test_sra_instruction_positive(self):
        # SRA %g1, 4, %g2 - shift right arithmetic by 4
        # op=2, rd=2, op3=0b100111, rs1=1, i=1, simm13=4
        inst: int = 0x85386004  # SRA %g1, 4, %g2
        sra_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(sra_instruction.op3, 0b100111)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x100)  # 256
        sra_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x10)  # 16

    def test_sra_instruction_negative(self):
        # SRA with negative value preserves sign
        # op=2, rd=2, op3=0b100111, rs1=1, i=1, simm13=4
        inst: int = 0x85386004  # SRA %g1, 4, %g2
        sra_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x80000000)  # -2147483648
        sra_instruction.execute(cpu_state)
        # After shift right by 4, should still have sign bits
        self.assertEqual(cpu_state.registers.read_register(2), 0xF8000000)

    # --- SMUL instruction tests ---

    def test_smul_instruction_positive(self):
        # SMUL %g1, %g2, %g3 - signed multiply
        # op=2, rd=3, op3=0b001011, rs1=1, i=0, rs2=2
        inst: int = 0x86584002  # SMUL %g1, %g2, %g3
        smul_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(smul_instruction.op3, 0b001011)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 200)
        smul_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 20000)
        self.assertEqual(cpu_state.y, 0)

    def test_smul_instruction_large_result(self):
        # SMUL with large result that overflows into Y
        # op=2, rd=3, op3=0b001011, rs1=1, i=0, rs2=2
        inst: int = 0x86584002  # SMUL %g1, %g2, %g3
        smul_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x10000)  # 65536
        cpu_state.registers.write_register(2, 0x10000)  # 65536
        smul_instruction.execute(cpu_state)
        # 65536 * 65536 = 4294967296 = 0x100000000
        self.assertEqual(cpu_state.registers.read_register(3), 0)
        self.assertEqual(cpu_state.y, 1)

    def test_smul_instruction_negative(self):
        # SMUL with negative operand
        # op=2, rd=3, op3=0b001011, rs1=1, i=0, rs2=2
        inst: int = 0x86584002  # SMUL %g1, %g2, %g3
        smul_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFFFFFFFF)  # -1
        cpu_state.registers.write_register(2, 10)
        smul_instruction.execute(cpu_state)
        # -1 * 10 = -10 = 0xFFFFFFF6 as 32-bit
        self.assertEqual(cpu_state.registers.read_register(3), 0xFFFFFFF6)
        self.assertEqual(cpu_state.y, 0xFFFFFFFF)  # sign extended

    # --- SDIV instruction tests ---

    def test_sdiv_instruction_positive(self):
        # SDIV %g1, %g2, %g3 - signed divide (dividend is Y:rs1)
        # op=2, rd=3, op3=0b001111, rs1=1, i=0, rs2=2
        inst: int = 0x86784002  # SDIV %g1, %g2, %g3
        sdiv_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(sdiv_instruction.op3, 0b001111)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 0
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 10)
        sdiv_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 10)

    def test_sdiv_instruction_with_y(self):
        # SDIV where Y register contributes to dividend
        # op=2, rd=3, op3=0b001111, rs1=1, i=0, rs2=2
        inst: int = 0x86784002  # SDIV %g1, %g2, %g3
        sdiv_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 1  # Y:rs1 = 0x100000000
        cpu_state.registers.write_register(1, 0)
        cpu_state.registers.write_register(2, 2)
        sdiv_instruction.execute(cpu_state)
        # 0x100000000 / 2 = 0x80000000 but gets clamped to 0x7FFFFFFF (max signed 32-bit)
        self.assertEqual(cpu_state.registers.read_register(3), 0x7FFFFFFF)

    def test_sdiv_division_by_zero(self):
        # op=2, rd=3, op3=0b001111, rs1=1, i=0, rs2=2
        inst: int = 0x86784002  # SDIV %g1, %g2, %g3
        sdiv_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 0
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 0)
        with self.assertRaises(ValueError) as e:
            sdiv_instruction.execute(cpu_state)
        self.assertEqual(str(e.exception), "division by zero")

    # --- WRY instruction tests ---

    def test_wry_instruction_simm13(self):
        # WRY %g1, 0, %y -> writes g1 ^ 0 to Y
        inst: int = 0x81800000  # WRY %g0, %g0
        wry_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(wry_instruction.op3, 0b110000)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x12345678)
        # WRY %g1, 0, %y
        inst = 0x81806000  # WRY %g1, 0
        wry_instruction = Format3Instruction(inst)
        wry_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.y, 0x12345678)

    def test_wry_instruction_xor(self):
        # WRY does XOR: Y = rs1 ^ operand2
        inst: int = 0x818060FF  # WRY %g1, 0xFF
        wry_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFF)
        wry_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.y, 0)  # 0xFF ^ 0xFF = 0

    # --- Bicc (branch) instruction tests ---

    def test_ba_instruction(self):
        # BA (branch always) with disp22 = 4 (16 bytes forward)
        # Format: 00 1 1000 010 disp22
        inst: int = 0x10800004  # BA +16
        ba_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(ba_instruction.op2, 0b010)
        self.assertEqual(ba_instruction.cond, 0b1000)
        self.assertEqual(ba_instruction.disp22, 4)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        ba_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)  # 0x1000 + (4 * 4)

    def test_bne_instruction_taken(self):
        # BNE when Z=0 (not equal)
        inst: int = 0x12800004  # BNE +16
        bne_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(bne_instruction.cond, 0b1001)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.icc.z = False
        bne_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)

    def test_bne_instruction_not_taken(self):
        # BNE when Z=1 (equal)
        inst: int = 0x12800004  # BNE +16
        bne_instruction: Format2Instruction = Format2Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.npc = 0x1004
        cpu_state.icc.z = True
        bne_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1004)  # unchanged

    def test_be_instruction_taken(self):
        # BE when Z=1 (equal)
        inst: int = 0x02800004  # BE +16
        be_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(be_instruction.cond, 0b0001)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.icc.z = True
        be_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)

    def test_bl_instruction_taken(self):
        # BL (less than) when N xor V = 1
        inst: int = 0x06800004  # BL +16
        bl_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(bl_instruction.cond, 0b0011)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.icc.n = True
        cpu_state.icc.v = False
        bl_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)

    def test_ble_instruction_taken(self):
        # BLE (less or equal) when Z=1 or (N xor V)=1
        inst: int = 0x04800004  # BLE +16
        ble_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(ble_instruction.cond, 0b0010)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.icc.z = True
        ble_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)

    def test_branch_backward(self):
        # BA with negative displacement (backward branch)
        inst: int = 0x10BFFFFC  # BA -16 (disp22 = -4)
        ba_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(ba_instruction.disp22, -4)
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        ba_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0xFF0)  # 0x1000 + (-4 * 4)

    # --- Branch annul bit tests ---

    def test_ba_annul_skips_delay_slot(self):
        # BA,A (branch always with annul) should skip delay slot
        # Format: 00 1 1000 010 disp22 with annul bit (bit 29) set
        inst: int = 0x30800004  # BA,A +16
        ba_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(ba_instruction.cond, 0b1000)  # BA
        self.assertEqual(ba_instruction.a, 1)  # annul bit set
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.annul_next = False
        ba_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)  # branch taken
        self.assertTrue(cpu_state.annul_next)  # delay slot should be annulled

    def test_ba_no_annul_executes_delay_slot(self):
        # BA without annul should NOT skip delay slot
        inst: int = 0x10800004  # BA +16 (no annul)
        ba_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(ba_instruction.a, 0)  # annul bit not set
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.annul_next = False
        ba_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)  # branch taken
        self.assertFalse(cpu_state.annul_next)  # delay slot should execute

    def test_bn_annul_skips_delay_slot(self):
        # BN,A (branch never with annul) should skip delay slot
        # BN never branches, but with annul it should still skip delay slot
        inst: int = 0x20800004  # BN,A +16
        bn_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(bn_instruction.cond, 0b0000)  # BN
        self.assertEqual(bn_instruction.a, 1)  # annul bit set
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.npc = 0x1004
        cpu_state.annul_next = False
        bn_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1004)  # branch not taken
        self.assertTrue(cpu_state.annul_next)  # delay slot should be annulled

    def test_bne_annul_taken_executes_delay_slot(self):
        # BNE,A when taken should NOT skip delay slot (conditional branch)
        inst: int = 0x32800004  # BNE,A +16
        bne_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(bne_instruction.cond, 0b1001)  # BNE
        self.assertEqual(bne_instruction.a, 1)  # annul bit set
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.icc.z = False  # not equal, so branch taken
        cpu_state.annul_next = False
        bne_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1010)  # branch taken
        self.assertFalse(cpu_state.annul_next)  # delay slot should execute

    def test_bne_annul_not_taken_skips_delay_slot(self):
        # BNE,A when not taken should skip delay slot
        inst: int = 0x32800004  # BNE,A +16
        bne_instruction: Format2Instruction = Format2Instruction(inst)
        self.assertEqual(bne_instruction.cond, 0b1001)  # BNE
        self.assertEqual(bne_instruction.a, 1)  # annul bit set
        cpu_state: CpuState = CpuState()
        cpu_state.pc = 0x1000
        cpu_state.npc = 0x1004
        cpu_state.icc.z = True  # equal, so branch not taken
        cpu_state.annul_next = False
        bne_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.npc, 0x1004)  # branch not taken
        self.assertTrue(cpu_state.annul_next)  # delay slot should be annulled

    # --- ICC update tests ---

    def test_icc_update_zero(self):
        from sun4m.cpu import ICC
        icc = ICC()
        icc.update(0, 5, 5, is_sub=True)
        self.assertTrue(icc.z)
        self.assertFalse(icc.n)

    def test_icc_update_negative(self):
        from sun4m.cpu import ICC
        icc = ICC()
        icc.update(0x80000000, 0, 0x80000000, is_sub=True)
        self.assertTrue(icc.n)
        self.assertFalse(icc.z)

    def test_icc_carry_subtraction(self):
        from sun4m.cpu import ICC
        icc = ICC()
        # 10 - 5 = 5, no borrow so C=0 (in SPARC, C=1 means borrow)
        icc.update(5, 10, 5, is_sub=True)
        self.assertFalse(icc.c)
        # 5 - 10 = -5 (unsigned wraparound), borrow so C=1
        icc.update(0xFFFFFFFB, 5, 10, is_sub=True)
        self.assertTrue(icc.c)

    # --- LDUB instruction tests ---

    def test_ldub_instruction_simm13_execute(self):
        # LDUB [%g1 + 4], %g2
        # op=3, rd=2, op3=0b000001, rs1=1, i=1, simm13=4
        inst: int = 0xC4086004
        ldub_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldub_instruction.op, 3)
        self.assertEqual(ldub_instruction.rd, 2)
        self.assertEqual(ldub_instruction.op3, 0b000001)
        self.assertEqual(ldub_instruction.rs1, 1)
        self.assertEqual(ldub_instruction.i, 1)
        self.assertEqual(ldub_instruction.simm13, 4)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(4, bytes([0xAB]))
        cpu_state.registers.write_register(1, 0)
        ldub_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xAB)

    def test_ldub_instruction_rs2_execute(self):
        # LDUB [%g1 + %g3], %g2
        # op=3, rd=2, op3=0b000001, rs1=1, i=0, rs2=3
        inst: int = 0xC4084003
        ldub_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldub_instruction.i, 0)
        self.assertEqual(ldub_instruction.rs2, 3)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0x14, bytes([0xCD]))
        cpu_state.registers.write_register(1, 0x10)
        cpu_state.registers.write_register(3, 0x4)
        ldub_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xCD)

    # --- LDSB instruction tests ---

    def test_ldsb_instruction_positive(self):
        # LDSB [%g1 + 0], %g2 - load positive byte
        # op=3, rd=2, op3=0b001001, rs1=1, i=1, simm13=0
        inst: int = 0xC4486000
        ldsb_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldsb_instruction.op3, 0b001001)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x7F]))  # +127
        ldsb_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x7F)

    def test_ldsb_instruction_negative(self):
        # LDSB with negative byte should sign-extend
        inst: int = 0xC4486000
        ldsb_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x80]))  # -128
        ldsb_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xFFFFFF80)

    # --- LDUH instruction tests ---

    def test_lduh_instruction_execute(self):
        # LDUH [%g1 + 0], %g2
        # op=3, rd=2, op3=0b000010, rs1=1, i=1, simm13=0
        inst: int = 0xC4106000
        lduh_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(lduh_instruction.op3, 0b000010)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0xAB, 0xCD]))
        lduh_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xABCD)

    # --- LDSH instruction tests ---

    def test_ldsh_instruction_positive(self):
        # LDSH [%g1 + 0], %g2
        # op=3, rd=2, op3=0b001010, rs1=1, i=1, simm13=0
        inst: int = 0xC4506000
        ldsh_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldsh_instruction.op3, 0b001010)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x7F, 0xFF]))  # +32767
        ldsh_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x7FFF)

    def test_ldsh_instruction_negative(self):
        # LDSH with negative halfword should sign-extend
        inst: int = 0xC4506000
        ldsh_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x80, 0x00]))  # -32768
        ldsh_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xFFFF8000)

    # --- LDD instruction tests ---

    def test_ldd_instruction_execute(self):
        # LDD [%g1 + 0], %g2 - loads into %g2 and %g3
        # op=3, rd=2, op3=0b000011, rs1=1, i=1, simm13=0
        inst: int = 0xC4186000
        ldd_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldd_instruction.op3, 0b000011)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]))
        ldd_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x12345678)
        self.assertEqual(cpu_state.registers.read_register(3), 0x9ABCDEF0)

    # --- STB instruction tests ---

    def test_stb_instruction_execute(self):
        # STB %g2, [%g1 + 4]
        # op=3, rd=2, op3=0b000101, rs1=1, i=1, simm13=4
        inst: int = 0xC4286004
        stb_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(stb_instruction.op3, 0b000101)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.registers.write_register(2, 0xABCDEF12)
        cpu_state.registers.write_register(1, 0)
        stb_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.memory.read(4, 1), bytes([0x12]))

    # --- STH instruction tests ---

    def test_sth_instruction_execute(self):
        # STH %g2, [%g1 + 0]
        # op=3, rd=2, op3=0b000110, rs1=1, i=1, simm13=0
        inst: int = 0xC4306000
        sth_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(sth_instruction.op3, 0b000110)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.registers.write_register(2, 0xABCD1234)
        sth_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.memory.read(0, 2), bytes([0x12, 0x34]))

    # --- STD instruction tests ---

    def test_std_instruction_execute(self):
        # STD %g2, [%g1 + 0] - stores %g2 and %g3
        # op=3, rd=2, op3=0b000111, rs1=1, i=1, simm13=0
        inst: int = 0xC4386000
        std_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(std_instruction.op3, 0b000111)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.registers.write_register(2, 0x12345678)
        cpu_state.registers.write_register(3, 0x9ABCDEF0)
        std_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.memory.read(0, 8), bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]))

    # --- SWAP instruction tests ---

    def test_swap_instruction_execute(self):
        # SWAP [%g1 + 0], %g2
        # op=3, rd=2, op3=0b111111, rs1=1, i=1, simm13=0
        inst: int = 0xC5F86000
        swap_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(swap_instruction.op3, 0b111111)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x11, 0x22, 0x33, 0x44]))
        cpu_state.registers.write_register(2, 0xAABBCCDD)
        swap_instruction.execute(cpu_state)
        # Memory should have register value
        self.assertEqual(cpu_state.memory.read(0, 4), bytes([0xAA, 0xBB, 0xCC, 0xDD]))
        # Register should have old memory value
        self.assertEqual(cpu_state.registers.read_register(2), 0x11223344)

    def test_ldstub_instruction_execute(self):
        # LDSTUB [%g1 + 0], %g2 - atomically load byte and store 0xFF
        # op=3, rd=2, op3=0b001101, rs1=1, i=1, simm13=0
        inst: int = 0xC4686000
        ldstub_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ldstub_instruction.op3, 0b001101)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0x42]))  # initial byte value
        cpu_state.registers.write_register(1, 0)  # address in %g1
        ldstub_instruction.execute(cpu_state)
        # Register should have old byte value (zero-extended)
        self.assertEqual(cpu_state.registers.read_register(2), 0x42)
        # Memory should now have 0xFF
        self.assertEqual(cpu_state.memory.read(0, 1), bytes([0xFF]))

    def test_ldstub_instruction_already_locked(self):
        # LDSTUB on a byte that's already 0xFF (spinlock held)
        inst: int = 0xC4686000  # LDSTUB [%g1 + 0], %g2
        ldstub_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0, bytes([0xFF]))  # already locked
        cpu_state.registers.write_register(1, 0)
        ldstub_instruction.execute(cpu_state)
        # Register should have 0xFF (indicating lock was held)
        self.assertEqual(cpu_state.registers.read_register(2), 0xFF)
        # Memory should still have 0xFF
        self.assertEqual(cpu_state.memory.read(0, 1), bytes([0xFF]))

    # --- Register-indexed load/store tests ---

    def test_ld_instruction_rs2_execute(self):
        # LD [%g1 + %g3], %g2 (register-indexed)
        # op=3, rd=2, op3=0b000000, rs1=1, i=0, rs2=3
        inst: int = 0xC4004003
        ld_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(ld_instruction.i, 0)
        self.assertEqual(ld_instruction.rs2, 3)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.memory.write(0x20, bytes([0xDE, 0xAD, 0xBE, 0xEF]))
        cpu_state.registers.write_register(1, 0x10)
        cpu_state.registers.write_register(3, 0x10)
        ld_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xDEADBEEF)

    def test_st_instruction_rs2_execute(self):
        # ST %g2, [%g1 + %g3] (register-indexed)
        # op=3, rd=2, op3=0b000100, rs1=1, i=0, rs2=3
        inst: int = 0xC4204003
        st_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(st_instruction.i, 0)
        cpu_state: CpuState = CpuState()
        cpu_state.memory.add_segment(0, 0x100)
        cpu_state.registers.write_register(1, 0x10)
        cpu_state.registers.write_register(3, 0x10)
        cpu_state.registers.write_register(2, 0xCAFEBABE)
        st_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.memory.read(0x20, 4), bytes([0xCA, 0xFE, 0xBA, 0xBE]))

    # --- ANDN instruction tests ---

    def test_andn_instruction_execute(self):
        # ANDN %g1, %g2, %g3 (result = g1 AND NOT g2)
        # op=2, rd=3, op3=0b000101, rs1=1, i=0, rs2=2
        inst: int = 0x86284002
        andn_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(andn_instruction.op3, 0b000101)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFF00FF00)
        cpu_state.registers.write_register(2, 0x0F0F0F0F)
        andn_instruction.execute(cpu_state)
        # 0xFF00FF00 AND NOT(0x0F0F0F0F) = 0xFF00FF00 AND 0xF0F0F0F0 = 0xF000F000
        self.assertEqual(cpu_state.registers.read_register(3), 0xF000F000)

    def test_andn_instruction_simm13(self):
        # ANDN %g1, 0xFF, %g2
        # op=2, rd=2, op3=0b000101, rs1=1, i=1, simm13=0xFF
        inst: int = 0x842860FF
        andn_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFFFFFFFF)
        andn_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0xFFFFFF00)

    # --- XNOR instruction tests ---

    def test_xnor_instruction_execute(self):
        # XNOR %g1, %g2, %g3 (result = NOT(g1 XOR g2))
        # op=2, rd=3, op3=0b000111, rs1=1, i=0, rs2=2
        inst: int = 0x86384002
        xnor_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(xnor_instruction.op3, 0b000111)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xAAAAAAAA)
        cpu_state.registers.write_register(2, 0xAAAAAAAA)
        xnor_instruction.execute(cpu_state)
        # XNOR of same values = all 1s
        self.assertEqual(cpu_state.registers.read_register(3), 0xFFFFFFFF)

    def test_xnor_instruction_different(self):
        # XNOR with different values
        inst: int = 0x86384002
        xnor_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFFFFFFFF)
        cpu_state.registers.write_register(2, 0x00000000)
        xnor_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0x00000000)

    # --- SLL instruction tests ---

    def test_sll_instruction_simm13(self):
        # SLL %g1, 4, %g2
        # op=2, rd=2, op3=0b100101, rs1=1, i=1, simm13=4
        inst: int = 0x85286004
        sll_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(sll_instruction.op3, 0b100101)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x12345678)
        sll_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x23456780)

    def test_sll_instruction_rs2(self):
        # SLL %g1, %g3, %g2
        # op=2, rd=2, op3=0b100101, rs1=1, i=0, rs2=3
        inst: int = 0x85284003
        sll_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x00000001)
        cpu_state.registers.write_register(3, 16)
        sll_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x00010000)

    # --- SRL instruction tests ---

    def test_srl_instruction_execute(self):
        # SRL %g1, 4, %g2
        # op=2, rd=2, op3=0b100110, rs1=1, i=1, simm13=4
        inst: int = 0x85306004
        srl_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(srl_instruction.op3, 0b100110)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x12345678)
        srl_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x01234567)

    def test_srl_instruction_no_sign_extend(self):
        # SRL should NOT sign-extend (unlike SRA)
        inst: int = 0x85306004
        srl_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x80000000)
        srl_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(2), 0x08000000)

    # --- UMUL instruction tests ---

    def test_umul_instruction_execute(self):
        # UMUL %g1, %g2, %g3
        # op=2, rd=3, op3=0b001010, rs1=1, i=0, rs2=2
        inst: int = 0x86504002
        umul_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(umul_instruction.op3, 0b001010)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 200)
        umul_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 20000)
        self.assertEqual(cpu_state.y, 0)

    def test_umul_instruction_large_result(self):
        # UMUL with result > 32 bits
        inst: int = 0x86504002
        umul_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x10000)
        cpu_state.registers.write_register(2, 0x10000)
        umul_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0)
        self.assertEqual(cpu_state.y, 1)

    # --- UDIV instruction tests ---

    def test_udiv_instruction_execute(self):
        # UDIV %g1, %g2, %g3 (dividend is Y:rs1)
        # op=2, rd=3, op3=0b001110, rs1=1, i=0, rs2=2
        inst: int = 0x86704002
        udiv_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(udiv_instruction.op3, 0b001110)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 0
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 10)
        udiv_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 10)

    def test_udiv_instruction_with_y(self):
        # UDIV with Y contributing to dividend
        inst: int = 0x86704002
        udiv_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 1
        cpu_state.registers.write_register(1, 0)
        cpu_state.registers.write_register(2, 2)
        udiv_instruction.execute(cpu_state)
        # 0x100000000 / 2 = 0x80000000
        self.assertEqual(cpu_state.registers.read_register(3), 0x80000000)

    def test_udiv_instruction_division_by_zero(self):
        inst: int = 0x86704002
        udiv_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.y = 0
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 0)
        with self.assertRaises(ValueError) as e:
            udiv_instruction.execute(cpu_state)
        self.assertEqual(str(e.exception), "division by zero")

    # --- ADDX instruction tests ---

    def test_addx_instruction_no_carry(self):
        # ADDX %g1, %g2, %g3 with C=0
        # op=2, rd=3, op3=0b001000, rs1=1, i=0, rs2=2
        inst: int = 0x86404002
        addx_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(addx_instruction.op3, 0b001000)
        cpu_state: CpuState = CpuState()
        cpu_state.icc.c = False
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 50)
        addx_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 150)

    def test_addx_instruction_with_carry(self):
        # ADDX with C=1
        inst: int = 0x86404002
        addx_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.icc.c = True
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 50)
        addx_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 151)

    # --- SUBX instruction tests ---

    def test_subx_instruction_no_borrow(self):
        # SUBX %g1, %g2, %g3 with C=0 (no borrow)
        # op=2, rd=3, op3=0b001100, rs1=1, i=0, rs2=2
        inst: int = 0x86604002
        subx_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(subx_instruction.op3, 0b001100)
        cpu_state: CpuState = CpuState()
        cpu_state.icc.c = False
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 30)
        subx_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 70)

    def test_subx_instruction_with_borrow(self):
        # SUBX with C=1 (borrow from previous)
        inst: int = 0x86604002
        subx_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.icc.c = True
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 30)
        subx_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 69)

    # --- TSUBcc instruction tests ---

    def test_tsubcc_instruction_execute(self):
        # TSUBcc %g1, %g2, %g3
        # op=2, rd=3, op3=0b100001, rs1=1, i=0, rs2=2
        inst: int = 0x87084002
        tsubcc_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(tsubcc_instruction.op3, 0b100001)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 100)
        cpu_state.registers.write_register(2, 40)
        tsubcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 60)
        self.assertFalse(cpu_state.icc.z)
        self.assertFalse(cpu_state.icc.n)

    def test_tsubcc_instruction_sets_zero(self):
        inst: int = 0x87084002
        tsubcc_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 50)
        cpu_state.registers.write_register(2, 50)
        tsubcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0)
        self.assertTrue(cpu_state.icc.z)

    # --- ANDCC instruction tests ---

    def test_andcc_instruction_execute(self):
        # ANDCC %g1, %g2, %g3
        # op=2, rd=3, op3=0b010001, rs1=1, i=0, rs2=2
        inst: int = 0x86884002
        andcc_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(andcc_instruction.op3, 0b010001)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFF00FF00)
        cpu_state.registers.write_register(2, 0x00FF00FF)
        andcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0)
        self.assertTrue(cpu_state.icc.z)

    def test_andcc_instruction_nonzero(self):
        inst: int = 0x86884002
        andcc_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0xFF00FF00)
        cpu_state.registers.write_register(2, 0xFF000000)
        andcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0xFF000000)
        self.assertFalse(cpu_state.icc.z)
        self.assertTrue(cpu_state.icc.n)

    # --- ORCC instruction tests ---

    def test_orcc_instruction_execute(self):
        # ORCC %g1, %g2, %g3
        # op=2, rd=3, op3=0b010010, rs1=1, i=0, rs2=2
        inst: int = 0x86904002
        orcc_instruction: Format3Instruction = Format3Instruction(inst)
        self.assertEqual(orcc_instruction.op3, 0b010010)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0)
        cpu_state.registers.write_register(2, 0)
        orcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0)
        self.assertTrue(cpu_state.icc.z)

    def test_orcc_instruction_nonzero(self):
        inst: int = 0x86904002
        orcc_instruction: Format3Instruction = Format3Instruction(inst)
        cpu_state: CpuState = CpuState()
        cpu_state.registers.write_register(1, 0x0000FFFF)
        cpu_state.registers.write_register(2, 0xFFFF0000)
        orcc_instruction.execute(cpu_state)
        self.assertEqual(cpu_state.registers.read_register(3), 0xFFFFFFFF)
        self.assertFalse(cpu_state.icc.z)
        self.assertTrue(cpu_state.icc.n)

    # --- Flush Windows trap tests ---

    def test_flush_windows_trap(self):
        # TA 0x03 (Flush Windows)
        # Format: op=2, cond=1000, op2=111010, rs1=0, i=1, imm7=3
        inst: int = 0x91D02003  # TA 0x03
        ta_instruction: TrapInstruction = TrapInstruction(inst)
        self.assertEqual(ta_instruction.imm7, 0x03)
        cpu_state: CpuState = CpuState()
        # Should not raise - just a NOP in our implementation
        ta_instruction.execute(cpu_state)
