#include "sun4m/register.hpp"

#include <stdexcept>

namespace sun4m {

RegisterFile::RegisterFile(size_t n_windows)
    : n_windows(n_windows)
    , windows(n_windows)
{
}

uint32_t RegisterFile::read_register(uint8_t reg) const {
    if (reg < 8) {
        // globals
        if (reg == 0) {
            // g[0] must always be 0
            return 0;
        }
        return g[reg];
    } else if (reg < 16) {
        // outputs: accessed via windows[cwp-1].i
        // Use modular arithmetic for wrap-around
        size_t prev_window = (cwp + n_windows - 1) % n_windows;
        return windows[prev_window].i[reg - 8];
    } else if (reg < 24) {
        // locals
        return windows[cwp].l[reg - 16];
    } else if (reg < 32) {
        // inputs
        return windows[cwp].i[reg - 24];
    } else {
        throw std::out_of_range("invalid register number");
    }
}

void RegisterFile::write_register(uint8_t reg, uint32_t value) {
    // Mask to 32 bits (already uint32_t, but ensures no high bits from casts)
    value &= 0xFFFFFFFF;

    if (reg < 8) {
        // globals
        if (reg == 0) {
            // g[0] must always be 0 - ignore writes
            return;
        }
        g[reg] = value;
    } else if (reg < 16) {
        // outputs: accessed via windows[cwp-1].i
        size_t prev_window = (cwp + n_windows - 1) % n_windows;
        windows[prev_window].i[reg - 8] = value;
    } else if (reg < 24) {
        // locals
        windows[cwp].l[reg - 16] = value;
    } else if (reg < 32) {
        // inputs
        windows[cwp].i[reg - 24] = value;
    } else {
        throw std::out_of_range("invalid register number");
    }
}

} // namespace sun4m
