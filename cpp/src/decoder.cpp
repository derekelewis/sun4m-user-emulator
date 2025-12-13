#include "sun4m/decoder.hpp"

namespace sun4m {

std::unique_ptr<Instruction> decode(uint32_t inst) {
    uint8_t op = (inst >> 30) & 0b11;

    switch (op) {
        case 1:
            // CALL instruction
            return std::make_unique<CallInstruction>(inst);

        case 0: {
            // Format 2: SETHI, Bicc, FBfcc
            uint8_t op2 = (inst >> 22) & 0b111;
            if (op2 == 0b110) {
                // FBfcc (floating-point branch)
                return std::make_unique<FBfccInstruction>(inst);
            }
            return std::make_unique<Format2Instruction>(inst);
        }

        case 2: {
            // Format 3: Arithmetic/Logical or Trap
            uint8_t op3 = (inst >> 19) & 0b111111;
            if (op3 == 0b111010) {
                // Trap instruction
                return std::make_unique<TrapInstruction>(inst);
            } else if (op3 == 0b110100) {
                // FPop1 (FP arithmetic/conversions)
                return std::make_unique<FPop1Instruction>(inst);
            } else if (op3 == 0b110101) {
                // FPop2 (FP compare)
                return std::make_unique<FPop2Instruction>(inst);
            }
            return std::make_unique<Format3Instruction>(inst);
        }

        case 3: {
            // Format 3: Load/Store
            uint8_t op3 = (inst >> 19) & 0b111111;
            if (is_fp_load_store(op3)) {
                return std::make_unique<FPLoadStoreInstruction>(inst);
            }
            return std::make_unique<Format3Instruction>(inst);
        }

        default:
            // Should never happen (op is 2 bits)
            return std::make_unique<Format3Instruction>(inst);
    }
}

} // namespace sun4m
