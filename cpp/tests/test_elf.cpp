#include <gtest/gtest.h>
#include "sun4m/elf.hpp"

namespace sun4m {
namespace {

TEST(ElfTest, InvalidMagic) {
    SystemMemory mem;
    // Need at least 52 bytes for header size check to pass
    std::vector<uint8_t> not_elf(52, 0x00);
    auto result = load_elf_info(mem, not_elf, 0);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), "not an ELF file");
}

TEST(ElfTest, TooSmall) {
    SystemMemory mem;
    std::vector<uint8_t> small_file(10, 0);
    auto result = load_elf_info(mem, small_file, 0);
    EXPECT_FALSE(result.has_value());
}

TEST(ElfTest, WrongClass) {
    SystemMemory mem;
    // Valid magic but wrong class (64-bit)
    std::vector<uint8_t> elf64(52, 0);
    elf64[0] = 0x7f;
    elf64[1] = 'E';
    elf64[2] = 'L';
    elf64[3] = 'F';
    elf64[4] = 2;  // ELFCLASS64 instead of ELFCLASS32

    auto result = load_elf_info(mem, elf64, 0);
    EXPECT_FALSE(result.has_value());
}

TEST(ElfTest, WrongEndian) {
    SystemMemory mem;
    // Valid magic, 32-bit, but little-endian
    std::vector<uint8_t> elf_le(52, 0);
    elf_le[0] = 0x7f;
    elf_le[1] = 'E';
    elf_le[2] = 'L';
    elf_le[3] = 'F';
    elf_le[4] = 1;  // ELFCLASS32
    elf_le[5] = 1;  // ELFDATA2LSB (little-endian)

    auto result = load_elf_info(mem, elf_le, 0);
    EXPECT_FALSE(result.has_value());
}

}  // namespace
}  // namespace sun4m
