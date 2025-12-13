#include <gtest/gtest.h>
#include "sun4m/memory.hpp"

namespace sun4m {
namespace {

TEST(MemorySegmentTest, CreateSegment) {
    MemorySegment seg(0x1000, 0x100);
    EXPECT_EQ(seg.start, 0x1000u);
    EXPECT_EQ(seg.end, 0x1100u);
    EXPECT_EQ(seg.buffer.size(), 0x100u);
}

TEST(MemorySegmentTest, AddressInRange) {
    MemorySegment seg(0x1000, 0x100);
    // Check addresses using start/end members
    EXPECT_TRUE(0x1000 >= seg.start && 0x1000 < seg.end);
    EXPECT_TRUE(0x10FF >= seg.start && 0x10FF < seg.end);
    EXPECT_FALSE(0x0FFF >= seg.start && 0x0FFF < seg.end);
    EXPECT_FALSE(0x1100 >= seg.start && 0x1100 < seg.end);
}

TEST(SystemMemoryTest, AddSegment) {
    SystemMemory mem;
    auto* seg = mem.add_segment(0x1000, 0x100);
    ASSERT_NE(seg, nullptr);
    EXPECT_EQ(seg->start, 0x1000u);
}

TEST(SystemMemoryTest, ReadWriteU32) {
    SystemMemory mem;
    mem.add_segment(0x1000, 0x100);

    std::array<uint8_t, 4> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto write_result = mem.write(0x1000, data);
    EXPECT_TRUE(write_result.has_value());

    auto read_result = mem.read(0x1000, 4);
    ASSERT_TRUE(read_result.has_value());
    EXPECT_EQ((*read_result)[0], 0xDE);
    EXPECT_EQ((*read_result)[1], 0xAD);
    EXPECT_EQ((*read_result)[2], 0xBE);
    EXPECT_EQ((*read_result)[3], 0xEF);
}

TEST(SystemMemoryTest, ReadUnmappedFails) {
    SystemMemory mem;
    auto result = mem.read(0x1000, 4);
    EXPECT_FALSE(result.has_value());
}

TEST(SystemMemoryTest, WriteUnmappedFails) {
    SystemMemory mem;
    std::array<uint8_t, 4> data = {0, 0, 0, 0};
    auto result = mem.write(0x1000, data);
    EXPECT_FALSE(result.has_value());
}

}  // namespace
}  // namespace sun4m
