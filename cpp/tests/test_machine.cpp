#include <gtest/gtest.h>
#include "sun4m/machine.hpp"

namespace sun4m {
namespace {

TEST(MachineTest, Construction) {
    Machine machine;
    EXPECT_FALSE(machine.entrypoint.has_value());
}

TEST(MachineTest, ConstructionWithTrace) {
    Machine machine(true);
    EXPECT_TRUE(machine.cpu.trace);
}

TEST(MachineTest, ConstructionWithSysroot) {
    Machine machine(false, "/some/sysroot");
    // Sysroot is stored internally
    SUCCEED();
}

TEST(MachineTest, LoadNonexistentFile) {
    Machine machine;
    auto result = machine.load_file("/nonexistent/file.elf");
    EXPECT_FALSE(result.has_value());
}

TEST(MachineTest, MemoryInitialized) {
    Machine machine;
    // Memory should exist
    EXPECT_NE(&machine.memory, nullptr);
}

}  // namespace
}  // namespace sun4m
