#include <gtest/gtest.h>
#include "sun4m/instruction.hpp"
#include "sun4m/decoder.hpp"
#include "sun4m/cpu.hpp"

namespace sun4m {
namespace {

TEST(InstructionTest, SetHi) {
    // SETHI %hi(0x12345000), %g1
    // SETHI places imm22 into bits 31:10 of rd (rd = imm22 << 10)
    // To get 0x12345000, imm22 = 0x12345000 >> 10 = 0x48D14
    // Encoding: op=0, op2=4, rd=1, imm22=0x48D14
    uint32_t inst = (0 << 30) | (1 << 25) | (4 << 22) | 0x48D14;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    CpuState cpu;
    cpu.memory = nullptr;  // Not needed for SETHI
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(1), 0x12345000u);
}

TEST(InstructionTest, Add) {
    // ADD %g1, %g2, %g3
    CpuState cpu;
    cpu.registers.write_register(1, 10);
    cpu.registers.write_register(2, 20);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // op=2, op3=0 (ADD), rd=3, rs1=1, i=0, rs2=2
    uint32_t inst = (2 << 30) | (3 << 25) | (0 << 19) | (1 << 14) | (0 << 13) | 2;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(3), 30u);
}

TEST(InstructionTest, AddImmediate) {
    // ADD %g1, 5, %g3
    CpuState cpu;
    cpu.registers.write_register(1, 10);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // op=2, op3=0 (ADD), rd=3, rs1=1, i=1, simm13=5
    uint32_t inst = (2 << 30) | (3 << 25) | (0 << 19) | (1 << 14) | (1 << 13) | 5;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(3), 15u);
}

TEST(InstructionTest, Sub) {
    // SUB %g1, %g2, %g3
    CpuState cpu;
    cpu.registers.write_register(1, 30);
    cpu.registers.write_register(2, 10);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // op=2, op3=4 (SUB), rd=3, rs1=1, i=0, rs2=2
    uint32_t inst = (2 << 30) | (3 << 25) | (4 << 19) | (1 << 14) | (0 << 13) | 2;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(3), 20u);
}

TEST(InstructionTest, And) {
    // AND %g1, %g2, %g3
    CpuState cpu;
    cpu.registers.write_register(1, 0xFF00);
    cpu.registers.write_register(2, 0x0FF0);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // op=2, op3=1 (AND), rd=3, rs1=1, i=0, rs2=2
    uint32_t inst = (2 << 30) | (3 << 25) | (1 << 19) | (1 << 14) | (0 << 13) | 2;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(3), 0x0F00u);
}

TEST(InstructionTest, Or) {
    // OR %g1, %g2, %g3
    CpuState cpu;
    cpu.registers.write_register(1, 0xFF00);
    cpu.registers.write_register(2, 0x00FF);
    cpu.pc = 0x1000;
    cpu.npc = 0x1004;

    // op=2, op3=2 (OR), rd=3, rs1=1, i=0, rs2=2
    uint32_t inst = (2 << 30) | (3 << 25) | (2 << 19) | (1 << 14) | (0 << 13) | 2;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);

    decoded->execute(cpu);

    EXPECT_EQ(cpu.registers.read_register(3), 0xFFFFu);
}

}  // namespace
}  // namespace sun4m
