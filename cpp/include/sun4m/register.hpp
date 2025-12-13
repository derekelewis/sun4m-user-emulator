#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sun4m {

/// A single register window containing inputs and locals.
/// SPARC overlapping windows: the caller's outputs are the callee's inputs.
/// This is achieved by accessing outputs via windows[cwp-1].i
class Window {
public:
    std::array<uint32_t, 8> i{};  // inputs (also serves as previous window's outputs)
    std::array<uint32_t, 8> l{};  // locals
};

/// SPARC register file with overlapping register windows.
///
/// The default of 64 windows is intentionally larger than real hardware
/// (typically 7-32 windows) to avoid implementing window overflow/underflow
/// traps. With 64 windows, deeply nested call chains won't exhaust the
/// window pool, eliminating the need to spill/fill registers to/from memory.
///
/// Register mapping:
///   0-7:   globals (g0-g7), where g0 always returns 0
///   8-15:  outputs (o0-o7), accessed via windows[cwp-1].i
///   16-23: locals (l0-l7), accessed via windows[cwp].l
///   24-31: inputs (i0-i7), accessed via windows[cwp].i
class RegisterFile {
public:
    explicit RegisterFile(size_t n_windows = 64);

    /// Read a register value (0-31)
    [[nodiscard]] uint32_t read_register(uint8_t reg) const;

    /// Write a register value (0-31). Value is masked to 32 bits.
    void write_register(uint8_t reg, uint32_t value);

    size_t n_windows;
    std::vector<Window> windows;
    std::array<uint32_t, 8> g{};  // globals (g[0] always returns 0)
    size_t cwp = 0;               // current window pointer
};

} // namespace sun4m
