#pragma once

#include "constants.hpp"
#include "memory.hpp"
#include "register.hpp"

#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

namespace sun4m {

// Forward declaration
class Instruction;

/// Represents an open file descriptor in the emulated process.
struct FileDescriptor {
    int fd;
    std::string path;
    int host_fd = -1;          // OS-level file descriptor
    int64_t position = 0;
    int flags = 0;
    bool is_special = false;   // True for stdin/stdout/stderr
    bool is_directory = false; // True for directory file descriptors
};

/// Manages file descriptors for the emulated process.
class FileDescriptorTable {
public:
    FileDescriptorTable(std::string_view sysroot = "",
                        std::vector<std::string> passthrough = {});

    /// Translate a guest path to a host path using the sysroot.
    [[nodiscard]] std::string translate_path(std::string_view guest_path) const;

    /// Open a file and return its file descriptor, or negative errno on error.
    int open(std::string_view path, int flags, int mode = 0644);

    /// Close a file descriptor. Returns 0 on success, negative errno on error.
    int close(int fd);

    /// Get a file descriptor entry, or nullptr if not found.
    [[nodiscard]] FileDescriptor* get(int fd);
    [[nodiscard]] const FileDescriptor* get(int fd) const;

    /// Read from a file descriptor. Returns bytes or negative errno.
    [[nodiscard]] std::expected<std::vector<uint8_t>, int> read(int fd, size_t count);

    /// Write to a file descriptor. Returns bytes written or negative errno.
    [[nodiscard]] std::expected<size_t, int> write(int fd, std::span<const uint8_t> data);

    /// Seek in a file. Returns new position or negative errno.
    [[nodiscard]] std::expected<int64_t, int> lseek(int fd, int64_t offset, int whence);

    /// Duplicate a file descriptor. Returns newfd or negative errno.
    int dup2(int oldfd, int newfd);

    /// Get the sysroot path
    [[nodiscard]] const std::string& sysroot() const { return sysroot_; }

    /// Get the passthrough paths
    [[nodiscard]] const std::vector<std::string>& passthrough() const { return passthrough_; }

private:
    std::unordered_map<int, std::unique_ptr<FileDescriptor>> table_;
    int next_fd_ = 3;  // Start after stdin/stdout/stderr
    std::string sysroot_;
    std::vector<std::string> passthrough_;
};

/// Integer Condition Codes (N, Z, V, C).
struct ICC {
    bool n = false;  // Negative
    bool z = false;  // Zero
    bool v = false;  // Overflow
    bool c = false;  // Carry

    /// Update ICC based on an ALU operation result.
    /// @param result The 32-bit result of the operation.
    /// @param op1 First operand (32-bit).
    /// @param op2 Second operand (32-bit).
    /// @param is_sub True for subtraction, False for addition.
    void update(uint32_t result, uint32_t op1, uint32_t op2, bool is_sub = false);
};

/// Floating-Point Unit state for SPARC V8.
///
/// The FPU has 32 single-precision (32-bit) registers that can also be
/// accessed as 16 double-precision (64-bit) register pairs using even
/// register numbers.
///
/// The FSR (Floating-point State Register) contains:
/// - Bits 11-10: FCC (Floating-point Condition Codes)
/// - Bits 4-0: Exception flags (not currently implemented)
/// - Bits 31-30: Rounding direction (not currently implemented)
class FPUState {
public:
    /// 32 single-precision registers stored as raw 32-bit integers
    /// (IEEE 754 binary32 representation)
    std::array<uint32_t, 32> f{};

    /// FSR - Floating-point State Register
    uint32_t fsr = 0;

    /// Read single-precision float from register.
    [[nodiscard]] float read_single(uint8_t reg) const;

    /// Write single-precision float to register.
    void write_single(uint8_t reg, float value);

    /// Read double-precision float from even register pair.
    [[nodiscard]] double read_double(uint8_t reg) const;

    /// Write double-precision float to even register pair.
    void write_double(uint8_t reg, double value);

    /// Read raw 32-bit value from FP register.
    [[nodiscard]] uint32_t read_raw(uint8_t reg) const;

    /// Write raw 32-bit value to FP register.
    void write_raw(uint8_t reg, uint32_t value);

    /// Get FCC (bits 11-10 of FSR).
    [[nodiscard]] FCC fcc() const;

    /// Set FCC (bits 11-10 of FSR).
    void set_fcc(FCC value);

    /// Compare two floats and set FCC accordingly.
    void compare(double a, double b);
};

/// Represents the architectural state of the emulated CPU.
class CpuState {
public:
    CpuState(SystemMemory* memory = nullptr,
             bool trace = false,
             std::string_view sysroot = "",
             std::vector<std::string> passthrough = {});

    /// Execute a single instruction and advance the PC/nPC pipeline.
    void step();

    /// Run until program exits, max_steps is reached, or CPU halts.
    /// Returns the exit code if the program terminated via exit syscall.
    int run(std::optional<int64_t> max_steps = std::nullopt);

    // Public state
    bool trace = false;
    uint32_t pc = 0;
    std::optional<uint32_t> npc;
    uint32_t psr = 0;
    uint32_t y = 0;  // Y register for multiply/divide
    ICC icc;
    FPUState fpu;
    RegisterFile registers;
    SystemMemory* memory;  // Non-owning pointer (Machine owns it)
    bool annul_next = false;
    uint32_t brk = 0;  // Program break address for brk syscall
    FileDescriptorTable fd_table;
    std::string exe_path;  // Path to the executable (for /proc/self/exe)
    std::optional<std::tuple<uint16_t, uint16_t, uint16_t, uint16_t>> window_size;
    bool halted = false;
    int exit_code = 0;

private:
    std::unique_ptr<SystemMemory> owned_memory_;  // For standalone usage
};

} // namespace sun4m
