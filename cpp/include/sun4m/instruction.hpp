#pragma once

#include <cstdint>
#include <memory>

namespace sun4m {

// Forward declaration
class CpuState;

/// Base class for all SPARC instructions.
class Instruction {
public:
    explicit Instruction(uint32_t inst) : inst_(inst) {}
    virtual ~Instruction() = default;

    /// Execute the instruction, modifying CPU state.
    virtual void execute(CpuState& cpu) = 0;

    /// Get the raw instruction word.
    [[nodiscard]] uint32_t raw() const { return inst_; }

protected:
    uint32_t inst_;
};

/// CALL instruction (op=1).
/// Stores PC in %o7 and jumps to PC + disp30*4.
class CallInstruction : public Instruction {
public:
    explicit CallInstruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    int32_t disp30_;
};

/// Format 2 instructions (op=0): SETHI and Bicc.
class Format2Instruction : public Instruction {
public:
    explicit Format2Instruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t op2_;
    uint8_t rd_;
    uint32_t imm22_;
    uint8_t cond_;
    bool annul_;
    int32_t disp22_;

    void execute_sethi(CpuState& cpu);
    void execute_bicc(CpuState& cpu);
};

/// Trap instruction (op=2, op3=0b111010).
/// Handles software traps including syscalls.
class TrapInstruction : public Instruction {
public:
    explicit TrapInstruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t op3_;
    uint8_t rs1_;
    bool i_;
    uint8_t cond_;
    uint8_t imm7_;
    uint8_t rs2_;
};

/// Format 3 instructions (op=2 or op=3): arithmetic, logical, load/store.
class Format3Instruction : public Instruction {
public:
    explicit Format3Instruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t op_;
    uint8_t rd_;
    uint8_t op3_;
    uint8_t rs1_;
    bool i_;
    int32_t simm13_;
    uint8_t rs2_;

    [[nodiscard]] uint32_t get_operand2(const CpuState& cpu) const;
    void execute_load_store(CpuState& cpu);
    void execute_arithmetic(CpuState& cpu);
};

/// Floating-point load/store instructions (op=3, FP op3 codes).
class FPLoadStoreInstruction : public Instruction {
public:
    explicit FPLoadStoreInstruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t op3_;
    uint8_t rd_;
    uint8_t rs1_;
    bool i_;
    int32_t simm13_;
    uint8_t rs2_;
};

/// FPop1 - Floating-point operate instructions (op=2, op3=0b110100).
/// Handles arithmetic, conversions, and utility FP operations.
class FPop1Instruction : public Instruction {
public:
    explicit FPop1Instruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t rd_;
    uint8_t rs1_;
    uint8_t rs2_;
    uint16_t opf_;
};

/// FPop2 - Floating-point compare instructions (op=2, op3=0b110101).
class FPop2Instruction : public Instruction {
public:
    explicit FPop2Instruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t rs1_;
    uint8_t rs2_;
    uint16_t opf_;
};

/// FBfcc - Floating-point branch on condition codes (op=0, op2=0b110).
class FBfccInstruction : public Instruction {
public:
    explicit FBfccInstruction(uint32_t inst);
    void execute(CpuState& cpu) override;

private:
    uint8_t cond_;
    bool annul_;
    int32_t disp22_;
};

} // namespace sun4m
