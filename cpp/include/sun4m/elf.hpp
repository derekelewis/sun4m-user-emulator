#pragma once

#include "memory.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace sun4m {

// ELF constants
inline constexpr uint8_t ELFCLASS32 = 1;
inline constexpr uint8_t ELFDATA2MSB = 2;
inline constexpr uint8_t ELF_VERSION_CURRENT = 1;
inline constexpr uint16_t EM_SPARC = 2;

// ELF types
inline constexpr uint16_t ET_EXEC = 2;  // Executable file
inline constexpr uint16_t ET_DYN = 3;   // Shared object file

// Program header types
inline constexpr uint32_t PT_NULL = 0;
inline constexpr uint32_t PT_LOAD = 1;
inline constexpr uint32_t PT_DYNAMIC = 2;
inline constexpr uint32_t PT_INTERP = 3;
inline constexpr uint32_t PT_NOTE = 4;
inline constexpr uint32_t PT_PHDR = 6;

// Dynamic section tags
inline constexpr uint32_t DT_NULL = 0;
inline constexpr uint32_t DT_NEEDED = 1;
inline constexpr uint32_t DT_RELA = 7;
inline constexpr uint32_t DT_RELASZ = 8;
inline constexpr uint32_t DT_RELAENT = 9;

// SPARC relocation types
inline constexpr uint8_t R_SPARC_NONE = 0;
inline constexpr uint8_t R_SPARC_RELATIVE = 22;

// Program header size for 32-bit ELF
inline constexpr uint32_t PHDR_SIZE = 32;

/// Information extracted from an ELF file after loading.
struct ElfInfo {
    uint32_t entry_point;      // Entry point address (adjusted for base)
    uint32_t phdr_addr;        // Address where program headers are loaded
    uint32_t phdr_count;       // Number of program headers
    uint32_t phdr_size;        // Size of each program header entry
    std::optional<std::string> interpreter_path;  // Path to dynamic linker
    uint32_t base_address;     // Base address where ELF was loaded
    uint16_t elf_type;         // ET_EXEC or ET_DYN
    std::vector<uint8_t> program_headers;  // Raw program header bytes
};

/// Exception for malformed ELF files.
class ElfFormatError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Load an ELF image into memory and return detailed ElfInfo.
///
/// @param memory The SystemMemory to load segments into
/// @param elf_bytes The raw ELF file contents
/// @param base_addr Base address to add to all virtual addresses (for PIE/shared libs)
/// @return ElfInfo with entry point, program header info, interpreter path, etc.
[[nodiscard]] std::expected<ElfInfo, std::string>
load_elf_info(SystemMemory& memory, std::span<const uint8_t> elf_bytes, uint32_t base_addr = 0);

/// Load an ELF image into memory and return its entry point.
/// This is a backward-compatible wrapper around load_elf_info.
[[nodiscard]] std::expected<uint32_t, std::string>
load_elf(SystemMemory& memory, std::span<const uint8_t> elf_bytes, uint32_t base_addr = 0);

} // namespace sun4m
