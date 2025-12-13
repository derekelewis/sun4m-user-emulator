#pragma once

#include "cpu.hpp"
#include "elf.hpp"
#include "memory.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sun4m {

// Auxiliary vector types (from elf.h)
inline constexpr uint32_t AT_NULL = 0;
inline constexpr uint32_t AT_IGNORE = 1;
inline constexpr uint32_t AT_EXECFD = 2;
inline constexpr uint32_t AT_PHDR = 3;
inline constexpr uint32_t AT_PHENT = 4;
inline constexpr uint32_t AT_PHNUM = 5;
inline constexpr uint32_t AT_PAGESZ = 6;
inline constexpr uint32_t AT_BASE = 7;
inline constexpr uint32_t AT_FLAGS = 8;
inline constexpr uint32_t AT_ENTRY = 9;
inline constexpr uint32_t AT_NOTELF = 10;
inline constexpr uint32_t AT_UID = 11;
inline constexpr uint32_t AT_EUID = 12;
inline constexpr uint32_t AT_GID = 13;
inline constexpr uint32_t AT_EGID = 14;
inline constexpr uint32_t AT_PLATFORM = 15;
inline constexpr uint32_t AT_HWCAP = 16;
inline constexpr uint32_t AT_CLKTCK = 17;
inline constexpr uint32_t AT_RANDOM = 25;
inline constexpr uint32_t AT_HWCAP2 = 26;
inline constexpr uint32_t AT_EXECFN = 31;

/// Main emulator class that owns memory and CPU state.
class Machine {
public:
    Machine(bool trace = false,
            std::string_view sysroot = "",
            std::vector<std::string> passthrough = {});

    /// Load an ELF file and set up execution environment.
    /// For dynamically linked executables, also loads the interpreter.
    /// @param file Path to the ELF executable
    /// @param argv Command-line arguments (defaults to [file])
    /// @return Entry point address on success, error string on failure
    [[nodiscard]] std::expected<uint32_t, std::string>
    load_file(const std::filesystem::path& file,
              const std::vector<std::string>& argv = {});

    SystemMemory memory;
    CpuState cpu;
    std::optional<uint32_t> entrypoint;

private:
    bool trace_;
    std::string sysroot_;

    /// Resolve a guest path to host path using sysroot.
    [[nodiscard]] std::string resolve_path(std::string_view guest_path) const;

    /// Set up the stack with argc, argv, envp, auxv per SPARC ABI.
    [[nodiscard]] uint32_t setup_stack(
        uint32_t stack_top,
        const std::vector<std::string>& argv,
        const ElfInfo& main_info,
        const ElfInfo* interp_info
    );
};

} // namespace sun4m
