#include <gtest/gtest.h>
#include "sun4m/decoder.hpp"

namespace sun4m {
namespace {

TEST(DecoderTest, DecodeCall) {
    // CALL instruction: op=1
    uint32_t inst = (1 << 30) | 0x1000;  // CALL to offset 0x1000
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeSethi) {
    // SETHI: op=0, op2=4
    uint32_t inst = (0 << 30) | (1 << 25) | (4 << 22) | 0x12345;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeBranch) {
    // BA (Branch Always): op=0, op2=2, cond=8
    uint32_t inst = (0 << 30) | (8 << 25) | (2 << 22) | 0x100;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeAdd) {
    // ADD: op=2, op3=0
    uint32_t inst = (2 << 30) | (3 << 25) | (0 << 19) | (1 << 14) | 2;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeLoad) {
    // LD: op=3, op3=0
    uint32_t inst = (3 << 30) | (3 << 25) | (0 << 19) | (1 << 14) | 0;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeStore) {
    // ST: op=3, op3=4
    uint32_t inst = (3 << 30) | (3 << 25) | (4 << 19) | (1 << 14) | 0;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeTrap) {
    // TA (Trap Always): op=2, op3=0x3A, cond=8
    uint32_t inst = (2 << 30) | (8 << 25) | (0x3A << 19) | (1 << 14) | 0;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

TEST(DecoderTest, DecodeNop) {
    // NOP is SETHI %g0, 0
    uint32_t inst = (0 << 30) | (0 << 25) | (4 << 22) | 0;
    auto decoded = decode(inst);
    ASSERT_NE(decoded, nullptr);
}

}  // namespace
}  // namespace sun4m
