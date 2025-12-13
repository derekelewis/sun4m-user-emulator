#include <gtest/gtest.h>
#include "sun4m/syscall.hpp"
#include "sun4m/cpu.hpp"

namespace sun4m {
namespace {

// Syscall tests require a full CPU state setup
// These are placeholder tests for now

TEST(SyscallTest, ExitSyscall) {
    // sys_exit is syscall 1
    // Just verify the handler exists and is callable
    CpuState cpu;
    cpu.registers.write_register(8, 0);  // %o0 = exit code
    cpu.registers.write_register(1, 1);  // %g1 = syscall number (exit)

    // Note: Actually calling handle_syscall would require more setup
    // This is a placeholder test
    SUCCEED();
}

TEST(SyscallTest, WriteSyscall) {
    // sys_write is syscall 4
    SUCCEED();
}

TEST(SyscallTest, ReadSyscall) {
    // sys_read is syscall 3
    SUCCEED();
}

TEST(SyscallTest, BrkSyscall) {
    // sys_brk is syscall 45
    SUCCEED();
}

}  // namespace
}  // namespace sun4m
