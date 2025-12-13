#pragma once

#include "instruction.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace sun4m {

/// Decode a 32-bit SPARC instruction word into an Instruction object.
/// @param inst The 32-bit instruction word (already converted from big-endian)
/// @return A unique_ptr to the appropriate Instruction subclass
[[nodiscard]] std::unique_ptr<Instruction> decode(uint32_t inst);

/// FP load/store op3 codes (op=3)
inline constexpr std::array<uint8_t, 6> FP_LOAD_STORE_OP3 = {
    0b100000,  // LDF
    0b100001,  // LDFSR
    0b100011,  // LDDF
    0b100100,  // STF
    0b100101,  // STFSR
    0b100111,  // STDF
};

/// Check if an op3 code is a floating-point load/store
[[nodiscard]] constexpr bool is_fp_load_store(uint8_t op3) {
    for (auto fp_op3 : FP_LOAD_STORE_OP3) {
        if (op3 == fp_op3) return true;
    }
    return false;
}

} // namespace sun4m
