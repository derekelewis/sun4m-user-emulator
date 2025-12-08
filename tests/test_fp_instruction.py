import math
import struct
import unittest

from sun4m.cpu import CpuState, FPUState, FCC_E, FCC_L, FCC_G, FCC_U
from sun4m.decoder import decode
from sun4m.instruction import (
    FPLoadStoreInstruction,
    FPop1Instruction,
    FPop2Instruction,
    FBfccInstruction,
)


class TestFPUState(unittest.TestCase):
    """Test the FPUState class."""

    def test_read_write_single(self):
        fpu = FPUState()
        fpu.write_single(0, 3.14)
        self.assertAlmostEqual(fpu.read_single(0), 3.14, places=5)

    def test_read_write_double(self):
        fpu = FPUState()
        fpu.write_double(0, 3.141592653589793)
        self.assertAlmostEqual(fpu.read_double(0), 3.141592653589793, places=10)

    def test_double_requires_even_register(self):
        fpu = FPUState()
        with self.assertRaises(ValueError):
            fpu.read_double(1)
        with self.assertRaises(ValueError):
            fpu.write_double(1, 1.0)

    def test_read_write_raw(self):
        fpu = FPUState()
        fpu.write_raw(5, 0x12345678)
        self.assertEqual(fpu.read_raw(5), 0x12345678)

    def test_fcc_property(self):
        fpu = FPUState()
        fpu.fcc = FCC_L
        self.assertEqual(fpu.fcc, FCC_L)
        self.assertEqual((fpu.fsr >> 10) & 0x3, FCC_L)

    def test_compare_equal(self):
        fpu = FPUState()
        fpu.compare(1.5, 1.5)
        self.assertEqual(fpu.fcc, FCC_E)

    def test_compare_less(self):
        fpu = FPUState()
        fpu.compare(1.0, 2.0)
        self.assertEqual(fpu.fcc, FCC_L)

    def test_compare_greater(self):
        fpu = FPUState()
        fpu.compare(2.0, 1.0)
        self.assertEqual(fpu.fcc, FCC_G)

    def test_compare_unordered_nan(self):
        fpu = FPUState()
        fpu.compare(float("nan"), 1.0)
        self.assertEqual(fpu.fcc, FCC_U)
        fpu.compare(1.0, float("nan"))
        self.assertEqual(fpu.fcc, FCC_U)


class TestFPLoadStoreInstruction(unittest.TestCase):
    """Test FP load/store instructions."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.memory.add_segment(0, 0x1000)

    def test_ldf_instruction(self):
        # LDF [%g1 + 0], %f2
        # op=3, rd=2, op3=0b100000, rs1=1, i=1, simm13=0
        # 11 00010 100000 00001 1 0000000000000
        inst = 0xC5006000
        ldf = FPLoadStoreInstruction(inst)
        self.assertEqual(ldf.op3, 0b100000)
        self.assertEqual(ldf.rd, 2)

        # Store a float in memory
        val = struct.pack(">f", 2.5)
        self.cpu_state.memory.write(0x100, val)
        self.cpu_state.registers.write_register(1, 0x100)

        ldf.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 2.5, places=5)

    def test_stf_instruction(self):
        # STF %f2, [%g1 + 0]
        # op=3, rd=2, op3=0b100100, rs1=1, i=1, simm13=0
        inst = 0xC5206000
        stf = FPLoadStoreInstruction(inst)
        self.assertEqual(stf.op3, 0b100100)

        self.cpu_state.fpu.write_single(2, 4.5)
        self.cpu_state.registers.write_register(1, 0x100)

        stf.execute(self.cpu_state)

        data = self.cpu_state.memory.read(0x100, 4)
        result = struct.unpack(">f", data)[0]
        self.assertAlmostEqual(result, 4.5, places=5)

    def test_lddf_instruction(self):
        # LDDF [%g1 + 0], %f4
        # op=3, rd=4, op3=0b100011, rs1=1, i=1, simm13=0
        inst = 0xC9186000
        lddf = FPLoadStoreInstruction(inst)
        self.assertEqual(lddf.op3, 0b100011)
        self.assertEqual(lddf.rd, 4)

        # Store a double in memory
        val = struct.pack(">d", 3.141592653589793)
        self.cpu_state.memory.write(0x100, val)
        self.cpu_state.registers.write_register(1, 0x100)

        lddf.execute(self.cpu_state)
        self.assertAlmostEqual(
            self.cpu_state.fpu.read_double(4), 3.141592653589793, places=10
        )

    def test_stdf_instruction(self):
        # STDF %f4, [%g1 + 0]
        # op=3, rd=4, op3=0b100111, rs1=1, i=1, simm13=0
        inst = 0xC9386000
        stdf = FPLoadStoreInstruction(inst)
        self.assertEqual(stdf.op3, 0b100111)

        self.cpu_state.fpu.write_double(4, 2.718281828459045)
        self.cpu_state.registers.write_register(1, 0x100)

        stdf.execute(self.cpu_state)

        data = self.cpu_state.memory.read(0x100, 8)
        result = struct.unpack(">d", data)[0]
        self.assertAlmostEqual(result, 2.718281828459045, places=10)

    def test_ldfsr_instruction(self):
        # LDFSR [%g1 + 0]
        # op=3, rd=0, op3=0b100001, rs1=1, i=1, simm13=0
        inst = 0xC1086000
        ldfsr = FPLoadStoreInstruction(inst)
        self.assertEqual(ldfsr.op3, 0b100001)

        # Store FSR value (with FCC=2 in bits 11-10)
        fsr_val = 0x00000800  # FCC = 2 (greater)
        self.cpu_state.memory.write(0x100, fsr_val.to_bytes(4, "big"))
        self.cpu_state.registers.write_register(1, 0x100)

        ldfsr.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_G)

    def test_stfsr_instruction(self):
        # STFSR [%g1 + 0]
        # op=3, rd=0, op3=0b100101, rs1=1, i=1, simm13=0
        inst = 0xC1286000
        stfsr = FPLoadStoreInstruction(inst)
        self.assertEqual(stfsr.op3, 0b100101)

        self.cpu_state.fpu.fcc = FCC_L  # Set FCC to 1
        self.cpu_state.registers.write_register(1, 0x100)

        stfsr.execute(self.cpu_state)

        data = self.cpu_state.memory.read(0x100, 4)
        fsr = int.from_bytes(data, "big")
        self.assertEqual((fsr >> 10) & 0x3, FCC_L)


class TestFPop1Instruction(unittest.TestCase):
    """Test FPop1 arithmetic and utility instructions."""

    def setUp(self):
        self.cpu_state = CpuState()

    def test_fmovs(self):
        # FMOVs %f1, %f2 (opf=0x001)
        # op=2, rd=2, op3=0b110100, rs1=0, opf=0x001, rs2=1
        inst = 0x85A00021
        fmov = FPop1Instruction(inst)
        self.assertEqual(fmov.opf, 0x001)

        self.cpu_state.fpu.write_single(1, 5.5)
        fmov.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 5.5, places=5)

    def test_fnegs(self):
        # FNEGs %f1, %f2 (opf=0x005)
        inst = 0x85A000A1
        fneg = FPop1Instruction(inst)
        self.assertEqual(fneg.opf, 0x005)

        self.cpu_state.fpu.write_single(1, 3.0)
        fneg.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), -3.0, places=5)

    def test_fabss(self):
        # FABSs %f1, %f2 (opf=0x009)
        inst = 0x85A00121
        fabs = FPop1Instruction(inst)
        self.assertEqual(fabs.opf, 0x009)

        self.cpu_state.fpu.write_single(1, -7.5)
        fabs.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 7.5, places=5)

    def test_fsqrts(self):
        # FSQRTs %f2, %f4 (opf=0x029)
        inst = 0x89A00522
        fsqrt = FPop1Instruction(inst)
        self.assertEqual(fsqrt.opf, 0x029)

        self.cpu_state.fpu.write_single(2, 4.0)
        fsqrt.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(4), 2.0, places=5)

    def test_fsqrtd(self):
        # FSQRTd %f2, %f4 (opf=0x02A)
        inst = 0x89A00542
        fsqrt = FPop1Instruction(inst)
        self.assertEqual(fsqrt.opf, 0x02A)

        self.cpu_state.fpu.write_double(2, 2.0)
        fsqrt.execute(self.cpu_state)
        self.assertAlmostEqual(
            self.cpu_state.fpu.read_double(4), math.sqrt(2.0), places=10
        )

    def test_fadds(self):
        # FADDs %f0, %f1, %f2 (opf=0x041)
        inst = 0x85A00821
        fadd = FPop1Instruction(inst)
        self.assertEqual(fadd.opf, 0x041)

        self.cpu_state.fpu.write_single(0, 1.5)
        self.cpu_state.fpu.write_single(1, 2.5)
        fadd.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 4.0, places=5)

    def test_faddd(self):
        # FADDd %f0, %f2, %f4 (opf=0x042)
        inst = 0x89A00842
        fadd = FPop1Instruction(inst)
        self.assertEqual(fadd.opf, 0x042)

        self.cpu_state.fpu.write_double(0, 1.1)
        self.cpu_state.fpu.write_double(2, 2.2)
        fadd.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(4), 3.3, places=10)

    def test_fsubs(self):
        # FSUBs %f0, %f1, %f2 (opf=0x045)
        inst = 0x85A008A1
        fsub = FPop1Instruction(inst)
        self.assertEqual(fsub.opf, 0x045)

        self.cpu_state.fpu.write_single(0, 5.0)
        self.cpu_state.fpu.write_single(1, 2.0)
        fsub.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 3.0, places=5)

    def test_fsubd(self):
        # FSUBd %f0, %f2, %f4 (opf=0x046)
        inst = 0x89A008C2
        fsub = FPop1Instruction(inst)
        self.assertEqual(fsub.opf, 0x046)

        self.cpu_state.fpu.write_double(0, 10.5)
        self.cpu_state.fpu.write_double(2, 3.5)
        fsub.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(4), 7.0, places=10)

    def test_fmuls(self):
        # FMULs %f0, %f1, %f2 (opf=0x049)
        inst = 0x85A00921
        fmul = FPop1Instruction(inst)
        self.assertEqual(fmul.opf, 0x049)

        self.cpu_state.fpu.write_single(0, 3.0)
        self.cpu_state.fpu.write_single(1, 4.0)
        fmul.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 12.0, places=5)

    def test_fmuld(self):
        # FMULd %f0, %f2, %f4 (opf=0x04A)
        inst = 0x89A00942
        fmul = FPop1Instruction(inst)
        self.assertEqual(fmul.opf, 0x04A)

        self.cpu_state.fpu.write_double(0, 2.5)
        self.cpu_state.fpu.write_double(2, 4.0)
        fmul.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(4), 10.0, places=10)

    def test_fdivs(self):
        # FDIVs %f0, %f1, %f2 (opf=0x04D)
        inst = 0x85A009A1
        fdiv = FPop1Instruction(inst)
        self.assertEqual(fdiv.opf, 0x04D)

        self.cpu_state.fpu.write_single(0, 10.0)
        self.cpu_state.fpu.write_single(1, 4.0)
        fdiv.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 2.5, places=5)

    def test_fdivd(self):
        # FDIVd %f0, %f2, %f4 (opf=0x04E)
        inst = 0x89A009C2
        fdiv = FPop1Instruction(inst)
        self.assertEqual(fdiv.opf, 0x04E)

        self.cpu_state.fpu.write_double(0, 15.0)
        self.cpu_state.fpu.write_double(2, 3.0)
        fdiv.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(4), 5.0, places=10)

    def test_fitos(self):
        # FiTOs %f1, %f2 (opf=0x0C4)
        inst = 0x85A01881
        fito = FPop1Instruction(inst)
        self.assertEqual(fito.opf, 0x0C4)

        # Store integer 42 in FP register (raw)
        self.cpu_state.fpu.write_raw(1, 42)
        fito.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), 42.0, places=5)

    def test_fitos_negative(self):
        # Test conversion of negative integer
        inst = 0x85A01881  # FiTOs %f1, %f2
        fito = FPop1Instruction(inst)

        # Store -10 as 32-bit two's complement
        self.cpu_state.fpu.write_raw(1, 0xFFFFFFF6)
        fito.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(2), -10.0, places=5)

    def test_fitod(self):
        # FiTOd %f1, %f2 (opf=0x0C8)
        inst = 0x85A01901
        fito = FPop1Instruction(inst)
        self.assertEqual(fito.opf, 0x0C8)

        self.cpu_state.fpu.write_raw(1, 1000)
        fito.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(2), 1000.0, places=10)

    def test_fstoi(self):
        # FsTOi %f1, %f2 (opf=0x0D1)
        inst = 0x85A01A21
        fstoi = FPop1Instruction(inst)
        self.assertEqual(fstoi.opf, 0x0D1)

        self.cpu_state.fpu.write_single(1, 7.9)
        fstoi.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.read_raw(2), 7)  # truncate toward zero

    def test_fstoi_negative(self):
        inst = 0x85A01A21  # FsTOi %f1, %f2
        fstoi = FPop1Instruction(inst)

        self.cpu_state.fpu.write_single(1, -5.7)
        fstoi.execute(self.cpu_state)
        # -5 as unsigned 32-bit
        self.assertEqual(self.cpu_state.fpu.read_raw(2), 0xFFFFFFFB)

    def test_fdtoi(self):
        # FdTOi %f2, %f4 (opf=0x0D2)
        inst = 0x89A01A42
        fdtoi = FPop1Instruction(inst)
        self.assertEqual(fdtoi.opf, 0x0D2)

        self.cpu_state.fpu.write_double(2, 123.999)
        fdtoi.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.read_raw(4), 123)

    def test_fstod(self):
        # FsTOd %f1, %f2 (opf=0x0C9)
        inst = 0x85A01921
        fstod = FPop1Instruction(inst)
        self.assertEqual(fstod.opf, 0x0C9)

        self.cpu_state.fpu.write_single(1, 3.5)
        fstod.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_double(2), 3.5, places=10)

    def test_fdtos(self):
        # FdTOs %f2, %f4 (opf=0x0C6)
        inst = 0x89A018C2
        fdtos = FPop1Instruction(inst)
        self.assertEqual(fdtos.opf, 0x0C6)

        self.cpu_state.fpu.write_double(2, 2.5)
        fdtos.execute(self.cpu_state)
        self.assertAlmostEqual(self.cpu_state.fpu.read_single(4), 2.5, places=5)


class TestFPop2Instruction(unittest.TestCase):
    """Test FPop2 compare instructions."""

    def setUp(self):
        self.cpu_state = CpuState()

    def test_fcmps_equal(self):
        # FCMPs %f0, %f1 (opf=0x051)
        inst = 0x81A80A21
        fcmp = FPop2Instruction(inst)
        self.assertEqual(fcmp.opf, 0x051)

        self.cpu_state.fpu.write_single(0, 5.0)
        self.cpu_state.fpu.write_single(1, 5.0)
        fcmp.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_E)

    def test_fcmps_less(self):
        inst = 0x81A80A21  # FCMPs %f0, %f1
        fcmp = FPop2Instruction(inst)

        self.cpu_state.fpu.write_single(0, 2.0)
        self.cpu_state.fpu.write_single(1, 5.0)
        fcmp.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_L)

    def test_fcmps_greater(self):
        inst = 0x81A80A21  # FCMPs %f0, %f1
        fcmp = FPop2Instruction(inst)

        self.cpu_state.fpu.write_single(0, 8.0)
        self.cpu_state.fpu.write_single(1, 3.0)
        fcmp.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_G)

    def test_fcmpd_equal(self):
        # FCMPd %f0, %f2 (opf=0x052)
        inst = 0x81A80A42
        fcmp = FPop2Instruction(inst)
        self.assertEqual(fcmp.opf, 0x052)

        self.cpu_state.fpu.write_double(0, 1.5)
        self.cpu_state.fpu.write_double(2, 1.5)
        fcmp.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_E)

    def test_fcmpd_less(self):
        inst = 0x81A80A42  # FCMPd %f0, %f2
        fcmp = FPop2Instruction(inst)

        self.cpu_state.fpu.write_double(0, 1.0)
        self.cpu_state.fpu.write_double(2, 2.0)
        fcmp.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.fpu.fcc, FCC_L)


class TestFBfccInstruction(unittest.TestCase):
    """Test FBfcc branch instructions."""

    def setUp(self):
        self.cpu_state = CpuState()
        self.cpu_state.pc = 0x1000

    def test_fba_instruction(self):
        # FBA +16 (branch always, disp22=4)
        inst = 0x11800004
        fba = FBfccInstruction(inst)
        self.assertEqual(fba.cond, 0b1000)
        self.assertEqual(fba.disp22, 4)

        fba.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbn_instruction(self):
        # FBN +16 (branch never)
        inst = 0x01800004
        fbn = FBfccInstruction(inst)
        self.assertEqual(fbn.cond, 0b0000)

        self.cpu_state.npc = 0x1004
        fbn.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1004)  # unchanged

    def test_fbe_taken(self):
        # FBE +16 (branch if equal)
        inst = 0x13800004
        fbe = FBfccInstruction(inst)
        self.assertEqual(fbe.cond, 0b1001)

        self.cpu_state.fpu.fcc = FCC_E
        fbe.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbe_not_taken(self):
        inst = 0x13800004  # FBE +16
        fbe = FBfccInstruction(inst)

        self.cpu_state.fpu.fcc = FCC_L
        self.cpu_state.npc = 0x1004
        fbe.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1004)

    def test_fbne_taken(self):
        # FBNE +16 (branch if not equal)
        inst = 0x03800004
        fbne = FBfccInstruction(inst)
        self.assertEqual(fbne.cond, 0b0001)

        self.cpu_state.fpu.fcc = FCC_G
        fbne.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbl_taken(self):
        # FBL +16 (branch if less)
        inst = 0x09800004
        fbl = FBfccInstruction(inst)
        self.assertEqual(fbl.cond, 0b0100)

        self.cpu_state.fpu.fcc = FCC_L
        fbl.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbg_taken(self):
        # FBG +16 (branch if greater)
        inst = 0x0D800004
        fbg = FBfccInstruction(inst)
        self.assertEqual(fbg.cond, 0b0110)

        self.cpu_state.fpu.fcc = FCC_G
        fbg.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbu_taken(self):
        # FBU +16 (branch if unordered)
        inst = 0x0F800004
        fbu = FBfccInstruction(inst)
        self.assertEqual(fbu.cond, 0b0111)

        self.cpu_state.fpu.fcc = FCC_U
        fbu.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbo_taken(self):
        # FBO +16 (branch if ordered)
        inst = 0x1F800004
        fbo = FBfccInstruction(inst)
        self.assertEqual(fbo.cond, 0b1111)

        self.cpu_state.fpu.fcc = FCC_E  # ordered
        fbo.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fbo_not_taken(self):
        inst = 0x1F800004  # FBO +16
        fbo = FBfccInstruction(inst)

        self.cpu_state.fpu.fcc = FCC_U  # unordered
        self.cpu_state.npc = 0x1004
        fbo.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1004)

    def test_fbge_taken(self):
        # FBGE +16 (branch if greater or equal)
        inst = 0x17800004
        fbge = FBfccInstruction(inst)
        self.assertEqual(fbge.cond, 0b1011)

        self.cpu_state.fpu.fcc = FCC_G
        fbge.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

        self.cpu_state.fpu.fcc = FCC_E
        self.cpu_state.pc = 0x1000
        fbge.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fble_taken(self):
        # FBLE +16 (branch if less or equal)
        inst = 0x1B800004
        fble = FBfccInstruction(inst)
        self.assertEqual(fble.cond, 0b1101)

        self.cpu_state.fpu.fcc = FCC_L
        fble.execute(self.cpu_state)
        self.assertEqual(self.cpu_state.npc, 0x1010)

    def test_fba_annul(self):
        # FBA,A +16 (branch always with annul)
        inst = 0x31800004
        fba = FBfccInstruction(inst)
        self.assertEqual(fba.a, 1)

        fba.execute(self.cpu_state)
        self.assertTrue(self.cpu_state.annul_next)

    def test_fbne_annul_not_taken(self):
        # FBNE,A +16 when equal - should annul
        inst = 0x23800004
        fbne = FBfccInstruction(inst)
        self.assertEqual(fbne.a, 1)

        self.cpu_state.fpu.fcc = FCC_E
        self.cpu_state.npc = 0x1004
        fbne.execute(self.cpu_state)
        self.assertTrue(self.cpu_state.annul_next)
        self.assertEqual(self.cpu_state.npc, 0x1004)


class TestDecoder(unittest.TestCase):
    """Test that decoder routes FP instructions correctly."""

    def test_decode_ldf(self):
        # LDF [%g1], %f2
        inst = 0xC5006000
        decoded = decode(inst)
        self.assertIsInstance(decoded, FPLoadStoreInstruction)

    def test_decode_stf(self):
        # STF %f2, [%g1]
        inst = 0xC5206000
        decoded = decode(inst)
        self.assertIsInstance(decoded, FPLoadStoreInstruction)

    def test_decode_fpop1(self):
        # FADDs %f0, %f1, %f2
        inst = 0x85A00821
        decoded = decode(inst)
        self.assertIsInstance(decoded, FPop1Instruction)

    def test_decode_fpop2(self):
        # FCMPs %f0, %f1
        inst = 0x81A80A21
        decoded = decode(inst)
        self.assertIsInstance(decoded, FPop2Instruction)

    def test_decode_fbfcc(self):
        # FBA +16
        inst = 0x11800004
        decoded = decode(inst)
        self.assertIsInstance(decoded, FBfccInstruction)


if __name__ == "__main__":
    unittest.main()
