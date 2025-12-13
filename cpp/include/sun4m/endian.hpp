#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <span>

namespace sun4m {

/// SPARC is big-endian, host (x86-64 Linux) is little-endian.
/// These utilities handle the conversion.

/// Byte-swap a 16-bit value
[[nodiscard]] constexpr uint16_t bswap16(uint16_t val) {
    return std::byteswap(val);
}

/// Byte-swap a 32-bit value
[[nodiscard]] constexpr uint32_t bswap32(uint32_t val) {
    return std::byteswap(val);
}

/// Byte-swap a 64-bit value
[[nodiscard]] constexpr uint64_t bswap64(uint64_t val) {
    return std::byteswap(val);
}

/// Read a big-endian 16-bit value from a buffer
[[nodiscard]] inline uint16_t read_be16(std::span<const uint8_t> bytes) {
    uint16_t val;
    std::memcpy(&val, bytes.data(), 2);
    if constexpr (std::endian::native == std::endian::little) {
        return bswap16(val);
    }
    return val;
}

/// Read a big-endian 32-bit value from a buffer
[[nodiscard]] inline uint32_t read_be32(std::span<const uint8_t> bytes) {
    uint32_t val;
    std::memcpy(&val, bytes.data(), 4);
    if constexpr (std::endian::native == std::endian::little) {
        return bswap32(val);
    }
    return val;
}

/// Read a big-endian 64-bit value from a buffer
[[nodiscard]] inline uint64_t read_be64(std::span<const uint8_t> bytes) {
    uint64_t val;
    std::memcpy(&val, bytes.data(), 8);
    if constexpr (std::endian::native == std::endian::little) {
        return bswap64(val);
    }
    return val;
}

/// Write a big-endian 16-bit value to a buffer
inline void write_be16(std::span<uint8_t> bytes, uint16_t val) {
    if constexpr (std::endian::native == std::endian::little) {
        val = bswap16(val);
    }
    std::memcpy(bytes.data(), &val, 2);
}

/// Write a big-endian 32-bit value to a buffer
inline void write_be32(std::span<uint8_t> bytes, uint32_t val) {
    if constexpr (std::endian::native == std::endian::little) {
        val = bswap32(val);
    }
    std::memcpy(bytes.data(), &val, 4);
}

/// Write a big-endian 64-bit value to a buffer
inline void write_be64(std::span<uint8_t> bytes, uint64_t val) {
    if constexpr (std::endian::native == std::endian::little) {
        val = bswap64(val);
    }
    std::memcpy(bytes.data(), &val, 8);
}

/// Read a signed big-endian 16-bit value from a buffer
[[nodiscard]] inline int16_t read_be16_signed(std::span<const uint8_t> bytes) {
    return static_cast<int16_t>(read_be16(bytes));
}

/// Read a signed big-endian 32-bit value from a buffer
[[nodiscard]] inline int32_t read_be32_signed(std::span<const uint8_t> bytes) {
    return static_cast<int32_t>(read_be32(bytes));
}

/// Read an unsigned 8-bit value (no byte-swap needed)
[[nodiscard]] inline uint8_t read_u8(std::span<const uint8_t> bytes) {
    return bytes[0];
}

/// Read a signed 8-bit value
[[nodiscard]] inline int8_t read_s8(std::span<const uint8_t> bytes) {
    return static_cast<int8_t>(bytes[0]);
}

} // namespace sun4m
