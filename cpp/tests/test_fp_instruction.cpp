#include <gtest/gtest.h>
#include "sun4m/instruction.hpp"
#include "sun4m/decoder.hpp"
#include "sun4m/cpu.hpp"
#include <cmath>

namespace sun4m {
namespace {

TEST(FPInstructionTest, FADDs) {
    CpuState cpu;
    cpu.fpu.write_single(0, 1.5f);
    cpu.fpu.write_single(1, 2.5f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x41 (FADDs), rs1=0, rs2=1, rd=2
    uint32_t inst = (2 << 30) | (2 << 25) | (0x34 << 19) | (0 << 14) | (0x41 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(2), 4.0f);
}

TEST(FPInstructionTest, FSUBs) {
    CpuState cpu;
    cpu.fpu.write_single(0, 5.0f);
    cpu.fpu.write_single(1, 2.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x45 (FSUBs), rs1=0, rs2=1, rd=2
    uint32_t inst = (2 << 30) | (2 << 25) | (0x34 << 19) | (0 << 14) | (0x45 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(2), 3.0f);
}

TEST(FPInstructionTest, FMULs) {
    CpuState cpu;
    cpu.fpu.write_single(0, 3.0f);
    cpu.fpu.write_single(1, 4.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x49 (FMULs), rs1=0, rs2=1, rd=2
    uint32_t inst = (2 << 30) | (2 << 25) | (0x34 << 19) | (0 << 14) | (0x49 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(2), 12.0f);
}

TEST(FPInstructionTest, FDIVs) {
    CpuState cpu;
    cpu.fpu.write_single(0, 10.0f);
    cpu.fpu.write_single(1, 2.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x4D (FDIVs), rs1=0, rs2=1, rd=2
    uint32_t inst = (2 << 30) | (2 << 25) | (0x34 << 19) | (0 << 14) | (0x4D << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(2), 5.0f);
}

TEST(FPInstructionTest, FSQRTs) {
    CpuState cpu;
    cpu.fpu.write_single(1, 16.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x29 (FSQRTs), rs2=1, rd=0
    uint32_t inst = (2 << 30) | (0 << 25) | (0x34 << 19) | (0 << 14) | (0x29 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(0), 4.0f);
}

TEST(FPInstructionTest, FCMPs) {
    CpuState cpu;
    cpu.fpu.write_single(0, 1.0f);
    cpu.fpu.write_single(1, 2.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop2: op=2, op3=0x35, opf=0x51 (FCMPs), rs1=0, rs2=1
    uint32_t inst = (2 << 30) | (0 << 25) | (0x35 << 19) | (0 << 14) | (0x51 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.fpu.fcc(), FCC::Less);
}

TEST(FPInstructionTest, FMOVs) {
    CpuState cpu;
    cpu.fpu.write_single(1, 3.14f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x01 (FMOVs), rs2=1, rd=0
    uint32_t inst = (2 << 30) | (0 << 25) | (0x34 << 19) | (0 << 14) | (0x01 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(0), 3.14f);
}

TEST(FPInstructionTest, FNEGs) {
    CpuState cpu;
    cpu.fpu.write_single(1, 5.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x05 (FNEGs), rs2=1, rd=0
    uint32_t inst = (2 << 30) | (0 << 25) | (0x34 << 19) | (0 << 14) | (0x05 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(0), -5.0f);
}

TEST(FPInstructionTest, FABSs) {
    CpuState cpu;
    cpu.fpu.write_single(1, -7.0f);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // FPop1: op=2, op3=0x34, opf=0x09 (FABSs), rs2=1, rd=0
    uint32_t inst = (2 << 30) | (0 << 25) | (0x34 << 19) | (0 << 14) | (0x09 << 5) | 1;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_FLOAT_EQ(cpu.fpu.read_single(0), 7.0f);
}

}  // namespace
}  // namespace sun4m
