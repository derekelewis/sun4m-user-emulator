#include <gtest/gtest.h>
#include "sun4m/cpu.hpp"

namespace sun4m {
namespace {

TEST(ICCTest, AdditionSetsFlags) {
    ICC icc;
    icc.update(0, 1, 0xFFFFFFFF, false);  // 1 + 0xFFFFFFFF = 0 with carry
    EXPECT_TRUE(icc.z);   // Result is zero
    EXPECT_TRUE(icc.c);   // Carry out
    EXPECT_FALSE(icc.n);  // Not negative
}

TEST(ICCTest, SubtractionSetsFlags) {
    ICC icc;
    icc.update(0, 5, 5, true);  // 5 - 5 = 0
    EXPECT_TRUE(icc.z);
    EXPECT_FALSE(icc.c);  // No borrow (carry is set for no-borrow in sub)
}

TEST(ICCTest, NegativeResult) {
    ICC icc;
    icc.update(0x80000000, 0, 0, false);
    EXPECT_TRUE(icc.n);   // MSB is set
    EXPECT_FALSE(icc.z);
}

TEST(FPUStateTest, SinglePrecision) {
    FPUState fpu;
    fpu.write_single(0, 3.14f);
    EXPECT_FLOAT_EQ(fpu.read_single(0), 3.14f);
}

TEST(FPUStateTest, DoublePrecision) {
    FPUState fpu;
    fpu.write_double(0, 2.718281828);
    EXPECT_DOUBLE_EQ(fpu.read_double(0), 2.718281828);
}

TEST(FPUStateTest, FCCCompare) {
    FPUState fpu;
    fpu.compare(1.0, 2.0);
    EXPECT_EQ(fpu.fcc(), FCC::Less);

    fpu.compare(2.0, 1.0);
    EXPECT_EQ(fpu.fcc(), FCC::Greater);

    fpu.compare(1.0, 1.0);
    EXPECT_EQ(fpu.fcc(), FCC::Equal);
}

TEST(CpuStateTest, Construction) {
    CpuState cpu;
    EXPECT_EQ(cpu.pc, 0u);
    EXPECT_FALSE(cpu.halted);
}

}  // namespace
}  // namespace sun4m
