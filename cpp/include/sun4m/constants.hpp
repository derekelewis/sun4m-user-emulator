#pragma once

#include <cstdint>

namespace sun4m {

// Memory protection flags (matching Linux)
enum class Prot : uint32_t {
    None  = 0x0,
    Read  = 0x1,
    Write = 0x2,
    Exec  = 0x4
};

// Enable bitwise operations on Prot
constexpr Prot operator|(Prot a, Prot b) {
    return static_cast<Prot>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

constexpr Prot operator&(Prot a, Prot b) {
    return static_cast<Prot>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

constexpr Prot& operator|=(Prot& a, Prot b) {
    a = a | b;
    return a;
}

constexpr Prot& operator&=(Prot& a, Prot b) {
    a = a & b;
    return a;
}

constexpr bool operator!(Prot p) {
    return static_cast<uint32_t>(p) == 0;
}

// Page size
inline constexpr uint32_t PAGE_SIZE = 4096;

// Memory layout constants
inline constexpr uint32_t HEAP_START  = 0x10000000;  // 256MB
inline constexpr uint32_t MMAP_BASE   = 0x40000000;  // 1GB
inline constexpr uint32_t MMAP_END    = 0x80000000;  // 2GB
inline constexpr uint32_t STACK_BASE  = 0xD0000000;  // 3.25GB
inline constexpr uint32_t STACK_SIZE  = 0x01000000;  // 16MB
inline constexpr uint32_t TLS_START   = 0xFFFF0000;  // Near top of address space
inline constexpr uint32_t TLS_SIZE    = 0x00010000;  // 64KB
inline constexpr uint32_t INTERP_BASE = MMAP_BASE;   // Dynamic linker base

// FCC (Floating-point Condition Codes) values
enum class FCC : uint8_t {
    Equal     = 0,
    Less      = 1,
    Greater   = 2,
    Unordered = 3  // NaN
};

/// Sign-extend a value from the given number of bits to 32 bits.
///
/// @param value The unsigned value to sign-extend
/// @param bits The number of bits in the original value
/// @return The sign-extended value as a signed 32-bit integer
[[nodiscard]] constexpr int32_t sign_extend(uint32_t value, uint8_t bits) {
    const uint32_t sign_bit = 1U << (bits - 1);
    return static_cast<int32_t>((value & (sign_bit - 1)) - (value & sign_bit));
}

/// Sign-extend a 13-bit value (common in SPARC instructions)
[[nodiscard]] constexpr int32_t sign_extend_13(uint32_t value) {
    return sign_extend(value, 13);
}

/// Sign-extend a 22-bit value (branch displacements)
[[nodiscard]] constexpr int32_t sign_extend_22(uint32_t value) {
    return sign_extend(value, 22);
}

/// Sign-extend a 30-bit value (CALL displacement)
[[nodiscard]] constexpr int32_t sign_extend_30(uint32_t value) {
    return sign_extend(value, 30);
}

} // namespace sun4m
