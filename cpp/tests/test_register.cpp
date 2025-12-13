#include <gtest/gtest.h>
#include "sun4m/register.hpp"

namespace sun4m {
namespace {

TEST(RegisterFileTest, GlobalRegisters) {
    RegisterFile regs;
    regs.write_register(1, 0xDEADBEEF);
    EXPECT_EQ(regs.read_register(1), 0xDEADBEEFu);
}

TEST(RegisterFileTest, RegisterZeroAlwaysZero) {
    RegisterFile regs;
    regs.write_register(0, 0xFFFFFFFF);
    EXPECT_EQ(regs.read_register(0), 0u);
}

TEST(RegisterFileTest, WindowedRegisters) {
    RegisterFile regs;
    // Write to out register
    regs.write_register(8, 0x12345678);  // %o0
    EXPECT_EQ(regs.read_register(8), 0x12345678u);

    // Write to local register
    regs.write_register(16, 0xCAFEBABE);  // %l0
    EXPECT_EQ(regs.read_register(16), 0xCAFEBABEu);

    // Write to in register
    regs.write_register(24, 0xBAADF00D);  // %i0
    EXPECT_EQ(regs.read_register(24), 0xBAADF00Du);
}

TEST(RegisterFileTest, WindowOverlap) {
    RegisterFile regs;

    // In current window, write to %o0
    regs.write_register(8, 0x11111111);

    // SAVE - decrement CWP
    regs.cwp = (regs.cwp - 1) & 63;

    // In new window, %i0 should be the old %o0
    EXPECT_EQ(regs.read_register(24), 0x11111111u);
}

TEST(RegisterFileTest, SaveRestore) {
    RegisterFile regs;
    uint8_t orig_cwp = regs.cwp;

    // SAVE
    regs.cwp = (regs.cwp - 1) & 63;
    EXPECT_NE(regs.cwp, orig_cwp);

    // RESTORE
    regs.cwp = (regs.cwp + 1) & 63;
    EXPECT_EQ(regs.cwp, orig_cwp);
}

}  // namespace
}  // namespace sun4m
