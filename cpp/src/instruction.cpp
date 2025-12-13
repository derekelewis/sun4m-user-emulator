#include "sun4m/instruction.hpp"
#include "sun4m/cpu.hpp"
#include "sun4m/constants.hpp"
#include "sun4m/endian.hpp"
#include "sun4m/syscall.hpp"

#include <cmath>
#include <stdexcept>

namespace sun4m {

// ============================================================================
// CallInstruction
// ============================================================================

CallInstruction::CallInstruction(uint32_t inst) : Instruction(inst) {
    // disp30 is the lower 30 bits, sign extended
    uint32_t raw_disp = inst & ((1U << 30) - 1);
    if (raw_disp & (1U << 29)) {
        // Sign extend
        disp30_ = static_cast<int32_t>(raw_disp | (0b11U << 30));
    } else {
        disp30_ = static_cast<int32_t>(raw_disp);
    }
}

void CallInstruction::execute(CpuState& cpu) {
    // disp30 is word offset, multiply by 4
    cpu.npc = (cpu.pc + (disp30_ << 2)) & 0xFFFFFFFF;
    // Write pc to %o7 for return address (RETL = JMPL %o7 + 8, %g0)
    cpu.registers.write_register(15, cpu.pc);
}

// ============================================================================
// Format2Instruction
// ============================================================================

Format2Instruction::Format2Instruction(uint32_t inst) : Instruction(inst) {
    op2_ = (inst >> 22) & 0b111;

    if (op2_ == 0b100) {
        // SETHI
        rd_ = (inst >> 25) & 0b11111;
        imm22_ = inst & 0x3FFFFF;
    } else if (op2_ == 0b010) {
        // Bicc (branch on integer condition codes)
        cond_ = (inst >> 25) & 0b1111;
        annul_ = (inst >> 29) & 0b1;
        disp22_ = sign_extend_22(inst & 0x3FFFFF);
    }
}

void Format2Instruction::execute(CpuState& cpu) {
    switch (op2_) {
        case 0b000:
            // UNIMP - illegal instruction trap
            // In user-mode emulation, halt with error
            cpu.halted = true;
            cpu.exit_code = 128 + 4;  // SIGILL
            break;
        case 0b100:
            execute_sethi(cpu);
            break;
        case 0b010:
            execute_bicc(cpu);
            break;
        default:
            throw std::runtime_error("Unknown Format2 op2");
    }
}

void Format2Instruction::execute_sethi(CpuState& cpu) {
    uint32_t value = imm22_ << 10;
    cpu.registers.write_register(rd_, value);
}

void Format2Instruction::execute_bicc(CpuState& cpu) {
    const auto& icc = cpu.icc;
    bool take_branch = false;

    switch (cond_) {
        case 0b0000:  // BN (never)
            take_branch = false;
            break;
        case 0b1000:  // BA (always)
            take_branch = true;
            break;
        case 0b1001:  // BNE (not equal, Z=0)
            take_branch = !icc.z;
            break;
        case 0b0001:  // BE (equal, Z=1)
            take_branch = icc.z;
            break;
        case 0b1010:  // BG (greater, Z=0 and (N xor V)=0)
            take_branch = !icc.z && (icc.n == icc.v);
            break;
        case 0b0010:  // BLE (less or equal, Z=1 or (N xor V)=1)
            take_branch = icc.z || (icc.n != icc.v);
            break;
        case 0b1011:  // BGE (greater or equal, (N xor V)=0)
            take_branch = (icc.n == icc.v);
            break;
        case 0b0011:  // BL (less, (N xor V)=1)
            take_branch = (icc.n != icc.v);
            break;
        case 0b1100:  // BGU (greater unsigned, C=0 and Z=0)
            take_branch = !icc.c && !icc.z;
            break;
        case 0b0100:  // BLEU (less or equal unsigned, C=1 or Z=1)
            take_branch = icc.c || icc.z;
            break;
        case 0b1101:  // BCC (carry clear, C=0)
            take_branch = !icc.c;
            break;
        case 0b0101:  // BCS (carry set, C=1)
            take_branch = icc.c;
            break;
        case 0b1110:  // BPOS (positive, N=0)
            take_branch = !icc.n;
            break;
        case 0b0110:  // BNEG (negative, N=1)
            take_branch = icc.n;
            break;
        case 0b1111:  // BVC (overflow clear, V=0)
            take_branch = !icc.v;
            break;
        case 0b0111:  // BVS (overflow set, V=1)
            take_branch = icc.v;
            break;
        default:
            throw std::runtime_error("Unknown branch condition");
    }

    bool is_unconditional = (cond_ == 0b1000 || cond_ == 0b0000);

    if (take_branch) {
        cpu.npc = (cpu.pc + (disp22_ << 2)) & 0xFFFFFFFF;
        if (annul_ && is_unconditional) {
            cpu.annul_next = true;
        }
    } else if (annul_) {
        cpu.annul_next = true;
    }
}

// ============================================================================
// TrapInstruction
// ============================================================================

TrapInstruction::TrapInstruction(uint32_t inst) : Instruction(inst) {
    op3_ = (inst >> 19) & 0b111111;
    rs1_ = (inst >> 14) & 0b11111;
    i_ = (inst >> 13) & 0b1;
    cond_ = (inst >> 25) & 0b1111;
    if (i_) {
        imm7_ = inst & 0b1111111;
    } else {
        rs2_ = inst & 0b11111;
    }
}

void TrapInstruction::execute(CpuState& cpu) {
    uint32_t trap_num;
    if (i_) {
        trap_num = (cpu.registers.read_register(rs1_) + imm7_) % 128;
    } else {
        trap_num = (cpu.registers.read_register(rs1_) +
                    cpu.registers.read_register(rs2_)) % 128;
    }

    if (trap_num == 0x03) {
        // Flush Windows trap - no-op with sufficient windows
    } else if (trap_num == 0x10) {
        // Software interrupt 0x10 - syscall trap
        if (cond_ == 0b1000) {  // TA (Trap Always)
            Syscall syscall_handler(cpu);
            syscall_handler.handle();
        }
    } else {
        throw std::runtime_error("Unimplemented trap number: " + std::to_string(trap_num));
    }
}

// ============================================================================
// Format3Instruction
// ============================================================================

Format3Instruction::Format3Instruction(uint32_t inst) : Instruction(inst) {
    op_ = (inst >> 30) & 0b11;
    rd_ = (inst >> 25) & 0b11111;
    op3_ = (inst >> 19) & 0b111111;
    rs1_ = (inst >> 14) & 0b11111;
    i_ = (inst >> 13) & 0b1;
    if (i_) {
        simm13_ = sign_extend_13(inst & 0x1FFF);
    } else {
        rs2_ = inst & 0b11111;
    }
}

uint32_t Format3Instruction::get_operand2(const CpuState& cpu) const {
    if (i_) {
        return static_cast<uint32_t>(simm13_);
    } else {
        return cpu.registers.read_register(rs2_);
    }
}

void Format3Instruction::execute(CpuState& cpu) {
    if (op_ == 3) {
        execute_load_store(cpu);
    } else {
        execute_arithmetic(cpu);
    }
}

void Format3Instruction::execute_load_store(CpuState& cpu) {
    uint32_t rs1_val = cpu.registers.read_register(rs1_);
    uint32_t addr;
    if (i_) {
        addr = (rs1_val + simm13_) & 0xFFFFFFFF;
    } else {
        uint32_t rs2_val = cpu.registers.read_register(rs2_);
        addr = (rs1_val + rs2_val) & 0xFFFFFFFF;
    }

    switch (op3_) {
        case 0b000000: {  // LD (load word)
            auto result = cpu.memory->read(addr, 4);
            if (!result) throw std::runtime_error("Memory read error");
            cpu.registers.write_register(rd_, read_be32(*result));
            break;
        }
        case 0b000001: {  // LDUB (load unsigned byte)
            auto result = cpu.memory->read(addr, 1);
            if (!result) throw std::runtime_error("Memory read error");
            cpu.registers.write_register(rd_, (*result)[0]);
            break;
        }
        case 0b001001: {  // LDSB (load signed byte)
            auto result = cpu.memory->read(addr, 1);
            if (!result) throw std::runtime_error("Memory read error");
            int8_t val = static_cast<int8_t>((*result)[0]);
            cpu.registers.write_register(rd_, static_cast<uint32_t>(static_cast<int32_t>(val)));
            break;
        }
        case 0b000010: {  // LDUH (load unsigned halfword)
            auto result = cpu.memory->read(addr, 2);
            if (!result) throw std::runtime_error("Memory read error");
            cpu.registers.write_register(rd_, read_be16(*result));
            break;
        }
        case 0b001010: {  // LDSH (load signed halfword)
            auto result = cpu.memory->read(addr, 2);
            if (!result) throw std::runtime_error("Memory read error");
            int16_t val = static_cast<int16_t>(read_be16(*result));
            cpu.registers.write_register(rd_, static_cast<uint32_t>(static_cast<int32_t>(val)));
            break;
        }
        case 0b000011: {  // LDD (load doubleword)
            if (addr & 0x7) throw std::runtime_error("LDD: address not 8-byte aligned");
            if (rd_ & 0x1) throw std::runtime_error("LDD: rd must be even");
            auto high = cpu.memory->read(addr, 4);
            auto low = cpu.memory->read(addr + 4, 4);
            if (!high || !low) throw std::runtime_error("Memory read error");
            cpu.registers.write_register(rd_, read_be32(*high));
            cpu.registers.write_register(rd_ + 1, read_be32(*low));
            break;
        }
        case 0b000100: {  // ST (store word)
            uint32_t val = cpu.registers.read_register(rd_);
            std::array<uint8_t, 4> buf;
            write_be32(buf, val);
            auto result = cpu.memory->write(addr, buf);
            if (!result) throw std::runtime_error("Memory write error");
            break;
        }
        case 0b000101: {  // STB (store byte)
            uint8_t val = cpu.registers.read_register(rd_) & 0xFF;
            std::array<uint8_t, 1> buf = {val};
            auto result = cpu.memory->write(addr, buf);
            if (!result) throw std::runtime_error("Memory write error");
            break;
        }
        case 0b000110: {  // STH (store halfword)
            uint16_t val = cpu.registers.read_register(rd_) & 0xFFFF;
            std::array<uint8_t, 2> buf;
            write_be16(buf, val);
            auto result = cpu.memory->write(addr, buf);
            if (!result) throw std::runtime_error("Memory write error");
            break;
        }
        case 0b000111: {  // STD (store doubleword)
            if (addr & 0x7) throw std::runtime_error("STD: address not 8-byte aligned");
            if (rd_ & 0x1) throw std::runtime_error("STD: rd must be even");
            uint32_t high = cpu.registers.read_register(rd_);
            uint32_t low = cpu.registers.read_register(rd_ + 1);
            std::array<uint8_t, 4> high_buf, low_buf;
            write_be32(high_buf, high);
            write_be32(low_buf, low);
            (void)cpu.memory->write(addr, high_buf);
            (void)cpu.memory->write(addr + 4, low_buf);
            break;
        }
        case 0b111111: {  // SWAP (atomic swap)
            auto old_result = cpu.memory->read(addr, 4);
            if (!old_result) throw std::runtime_error("Memory read error");
            uint32_t old_val = read_be32(*old_result);
            uint32_t new_val = cpu.registers.read_register(rd_);
            std::array<uint8_t, 4> buf;
            write_be32(buf, new_val);
            (void)cpu.memory->write(addr, buf);
            cpu.registers.write_register(rd_, old_val);
            break;
        }
        case 0b001101: {  // LDSTUB (Load-Store Unsigned Byte)
            auto old_result = cpu.memory->read(addr, 1);
            if (!old_result) throw std::runtime_error("Memory read error");
            uint8_t old_byte = (*old_result)[0];
            std::array<uint8_t, 1> buf = {0xFF};
            (void)cpu.memory->write(addr, buf);
            cpu.registers.write_register(rd_, old_byte);
            break;
        }
        default:
            throw std::runtime_error("Unimplemented load/store opcode");
    }
}

void Format3Instruction::execute_arithmetic(CpuState& cpu) {
    switch (op3_) {
        case 0b000000: {  // ADD
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = (op1 + op2) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b010000: {  // ADDCC
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = (op1 + op2) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            cpu.icc.update(result, op1, op2, false);
            break;
        }
        case 0b000100: {  // SUB
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = (op1 - op2) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b010100: {  // SUBCC
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = (op1 - op2) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            cpu.icc.update(result, op1, op2, true);
            break;
        }
        case 0b100001: {  // TSUBcc (Tagged Subtract)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = (op1 - op2) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            cpu.icc.update(result, op1, op2, true);
            break;
        }
        case 0b001000: {  // ADDX (Add with Carry)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t carry = cpu.icc.c ? 1 : 0;
            uint32_t result = (op1 + op2 + carry) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b001100: {  // SUBX (Subtract with Carry)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t borrow = cpu.icc.c ? 1 : 0;
            uint32_t result = (op1 - op2 - borrow) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b000001: {  // AND
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 & op2;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b010001: {  // ANDCC
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 & op2;
            cpu.registers.write_register(rd_, result);
            cpu.icc.update(result, op1, op2, false);
            break;
        }
        case 0b000101: {  // ANDN (AND NOT)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 & (~op2);
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b000010: {  // OR
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 | op2;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b010010: {  // ORCC
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 | op2;
            cpu.registers.write_register(rd_, result);
            cpu.icc.update(result, op1, op2, false);
            break;
        }
        case 0b000110: {  // ORN (OR NOT)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 | (~op2);
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b000011: {  // XOR
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = op1 ^ op2;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b000111: {  // XNOR
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            uint32_t result = ~(op1 ^ op2);
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b100101: {  // SLL (Shift Left Logical)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t shift = i_ ? (simm13_ & 0x1F) : (cpu.registers.read_register(rs2_) & 0x1F);
            uint32_t result = (op1 << shift) & 0xFFFFFFFF;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b100110: {  // SRL (Shift Right Logical)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t shift = i_ ? (simm13_ & 0x1F) : (cpu.registers.read_register(rs2_) & 0x1F);
            uint32_t result = op1 >> shift;
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b100111: {  // SRA (Shift Right Arithmetic)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t shift = i_ ? (simm13_ & 0x1F) : (cpu.registers.read_register(rs2_) & 0x1F);
            int32_t signed_op1 = static_cast<int32_t>(op1);
            uint32_t result = static_cast<uint32_t>(signed_op1 >> shift);
            cpu.registers.write_register(rd_, result);
            break;
        }
        case 0b001010: {  // UMUL (Unsigned Multiply)
            uint64_t op1 = cpu.registers.read_register(rs1_);
            uint64_t op2 = get_operand2(cpu);
            uint64_t result64 = op1 * op2;
            cpu.y = static_cast<uint32_t>(result64 >> 32);
            cpu.registers.write_register(rd_, static_cast<uint32_t>(result64));
            break;
        }
        case 0b001011: {  // SMUL (Signed Multiply)
            int32_t op1 = static_cast<int32_t>(cpu.registers.read_register(rs1_));
            int32_t op2 = static_cast<int32_t>(get_operand2(cpu));
            int64_t result64 = static_cast<int64_t>(op1) * static_cast<int64_t>(op2);
            uint64_t uresult = static_cast<uint64_t>(result64);
            cpu.y = static_cast<uint32_t>(uresult >> 32);
            cpu.registers.write_register(rd_, static_cast<uint32_t>(uresult));
            break;
        }
        case 0b001110: {  // UDIV (Unsigned Divide)
            uint64_t dividend = (static_cast<uint64_t>(cpu.y) << 32) |
                               cpu.registers.read_register(rs1_);
            uint32_t divisor = get_operand2(cpu);
            if (divisor == 0) throw std::runtime_error("Division by zero");
            uint64_t quotient = dividend / divisor;
            if (quotient > 0xFFFFFFFF) quotient = 0xFFFFFFFF;
            cpu.registers.write_register(rd_, static_cast<uint32_t>(quotient));
            break;
        }
        case 0b001111: {  // SDIV (Signed Divide)
            int64_t dividend = (static_cast<int64_t>(cpu.y) << 32) |
                              cpu.registers.read_register(rs1_);
            int32_t divisor = static_cast<int32_t>(get_operand2(cpu));
            if (divisor == 0) throw std::runtime_error("Division by zero");
            int64_t quotient = dividend / divisor;
            if (quotient > 0x7FFFFFFF) quotient = 0x7FFFFFFF;
            else if (quotient < -0x80000000LL) quotient = -0x80000000LL;
            cpu.registers.write_register(rd_, static_cast<uint32_t>(quotient));
            break;
        }
        case 0b101000: {  // RDY (Read Y)
            cpu.registers.write_register(rd_, cpu.y);
            break;
        }
        case 0b110000: {  // WRY (Write Y)
            uint32_t op1 = cpu.registers.read_register(rs1_);
            uint32_t op2 = get_operand2(cpu);
            cpu.y = op1 ^ op2;
            break;
        }
        case 0b111000: {  // JMPL
            cpu.registers.write_register(rd_, cpu.pc);
            if (i_) {
                cpu.npc = (cpu.registers.read_register(rs1_) + simm13_) & 0xFFFFFFFF;
            } else {
                cpu.npc = (cpu.registers.read_register(rs1_) +
                          cpu.registers.read_register(rs2_)) & 0xFFFFFFFF;
            }
            break;
        }
        case 0b111100: {  // SAVE
            uint32_t sp = cpu.registers.read_register(rs1_);
            if (i_) {
                sp = (sp + simm13_) & 0xFFFFFFFF;
            } else {
                sp = (sp + cpu.registers.read_register(rs2_)) & 0xFFFFFFFF;
            }
            size_t n_windows = cpu.registers.n_windows;
            cpu.registers.cwp = (cpu.registers.cwp + n_windows - 1) % n_windows;
            cpu.registers.write_register(rd_, sp);
            break;
        }
        case 0b111101: {  // RESTORE
            uint32_t sp = cpu.registers.read_register(rs1_);
            if (i_) {
                sp = (sp + simm13_) & 0xFFFFFFFF;
            } else {
                sp = (sp + cpu.registers.read_register(rs2_)) & 0xFFFFFFFF;
            }
            size_t n_windows = cpu.registers.n_windows;
            cpu.registers.cwp = (cpu.registers.cwp + 1) % n_windows;
            cpu.registers.write_register(rd_, sp);
            break;
        }
        default:
            throw std::runtime_error("Unimplemented arithmetic opcode: " + std::to_string(op3_));
    }
}

// ============================================================================
// FPLoadStoreInstruction
// ============================================================================

FPLoadStoreInstruction::FPLoadStoreInstruction(uint32_t inst) : Instruction(inst) {
    op3_ = (inst >> 19) & 0b111111;
    rd_ = (inst >> 25) & 0b11111;
    rs1_ = (inst >> 14) & 0b11111;
    i_ = (inst >> 13) & 0b1;
    if (i_) {
        simm13_ = sign_extend_13(inst & 0x1FFF);
    } else {
        rs2_ = inst & 0b11111;
    }
}

void FPLoadStoreInstruction::execute(CpuState& cpu) {
    uint32_t rs1_val = cpu.registers.read_register(rs1_);
    uint32_t addr;
    if (i_) {
        addr = (rs1_val + simm13_) & 0xFFFFFFFF;
    } else {
        uint32_t rs2_val = cpu.registers.read_register(rs2_);
        addr = (rs1_val + rs2_val) & 0xFFFFFFFF;
    }

    switch (op3_) {
        case 0b100000: {  // LDF (load float, single)
            if (addr & 0x3) throw std::runtime_error("LDF: address not 4-byte aligned");
            auto data = cpu.memory->read(addr, 4);
            if (!data) throw std::runtime_error("Memory read error");
            cpu.fpu.write_raw(rd_, read_be32(*data));
            break;
        }
        case 0b100011: {  // LDDF (load double float)
            if (rd_ & 1) throw std::runtime_error("LDDF: rd must be even");
            if (addr & 0x7) throw std::runtime_error("LDDF: address not 8-byte aligned");
            auto high = cpu.memory->read(addr, 4);
            auto low = cpu.memory->read(addr + 4, 4);
            if (!high || !low) throw std::runtime_error("Memory read error");
            cpu.fpu.write_raw(rd_, read_be32(*high));
            cpu.fpu.write_raw(rd_ + 1, read_be32(*low));
            break;
        }
        case 0b100001: {  // LDFSR (load FSR)
            if (addr & 0x3) throw std::runtime_error("LDFSR: address not 4-byte aligned");
            auto data = cpu.memory->read(addr, 4);
            if (!data) throw std::runtime_error("Memory read error");
            cpu.fpu.fsr = read_be32(*data);
            break;
        }
        case 0b100100: {  // STF (store float, single)
            if (addr & 0x3) throw std::runtime_error("STF: address not 4-byte aligned");
            uint32_t val = cpu.fpu.read_raw(rd_);
            std::array<uint8_t, 4> buf;
            write_be32(buf, val);
            (void)cpu.memory->write(addr, buf);
            break;
        }
        case 0b100111: {  // STDF (store double float)
            if (rd_ & 1) throw std::runtime_error("STDF: rd must be even");
            if (addr & 0x7) throw std::runtime_error("STDF: address not 8-byte aligned");
            uint32_t high = cpu.fpu.read_raw(rd_);
            uint32_t low = cpu.fpu.read_raw(rd_ + 1);
            std::array<uint8_t, 4> high_buf, low_buf;
            write_be32(high_buf, high);
            write_be32(low_buf, low);
            (void)cpu.memory->write(addr, high_buf);
            (void)cpu.memory->write(addr + 4, low_buf);
            break;
        }
        case 0b100101: {  // STFSR (store FSR)
            if (addr & 0x3) throw std::runtime_error("STFSR: address not 4-byte aligned");
            std::array<uint8_t, 4> buf;
            write_be32(buf, cpu.fpu.fsr);
            (void)cpu.memory->write(addr, buf);
            break;
        }
        default:
            throw std::runtime_error("Unimplemented FP load/store opcode");
    }
}

// ============================================================================
// FPop1Instruction
// ============================================================================

FPop1Instruction::FPop1Instruction(uint32_t inst) : Instruction(inst) {
    rd_ = (inst >> 25) & 0b11111;
    rs1_ = (inst >> 14) & 0b11111;
    rs2_ = inst & 0b11111;
    opf_ = (inst >> 5) & 0x1FF;
}

void FPop1Instruction::execute(CpuState& cpu) {
    auto& fpu = cpu.fpu;

    switch (opf_) {
        // Move/Negate/Abs
        case 0x001:  // FMOVs
            fpu.write_raw(rd_, fpu.read_raw(rs2_));
            break;
        case 0x005:  // FNEGs
            fpu.write_raw(rd_, fpu.read_raw(rs2_) ^ 0x80000000);
            break;
        case 0x009:  // FABSs
            fpu.write_raw(rd_, fpu.read_raw(rs2_) & 0x7FFFFFFF);
            break;

        // Square root
        case 0x029: {  // FSQRTs
            float fs = fpu.read_single(rs2_);
            fpu.write_single(rd_, fs < 0 ? std::nanf("") : std::sqrt(fs));
            break;
        }
        case 0x02A: {  // FSQRTd
            double fd = fpu.read_double(rs2_);
            fpu.write_double(rd_, fd < 0 ? std::nan("") : std::sqrt(fd));
            break;
        }

        // Add
        case 0x041:  // FADDs
            fpu.write_single(rd_, fpu.read_single(rs1_) + fpu.read_single(rs2_));
            break;
        case 0x042:  // FADDd
            fpu.write_double(rd_, fpu.read_double(rs1_) + fpu.read_double(rs2_));
            break;

        // Subtract
        case 0x045:  // FSUBs
            fpu.write_single(rd_, fpu.read_single(rs1_) - fpu.read_single(rs2_));
            break;
        case 0x046:  // FSUBd
            fpu.write_double(rd_, fpu.read_double(rs1_) - fpu.read_double(rs2_));
            break;

        // Multiply
        case 0x049:  // FMULs
            fpu.write_single(rd_, fpu.read_single(rs1_) * fpu.read_single(rs2_));
            break;
        case 0x04A:  // FMULd
            fpu.write_double(rd_, fpu.read_double(rs1_) * fpu.read_double(rs2_));
            break;

        // Divide
        case 0x04D:  // FDIVs
            fpu.write_single(rd_, fpu.read_single(rs1_) / fpu.read_single(rs2_));
            break;
        case 0x04E:  // FDIVd
            fpu.write_double(rd_, fpu.read_double(rs1_) / fpu.read_double(rs2_));
            break;

        // FsMULd
        case 0x069:  // FsMULd
            fpu.write_double(rd_, static_cast<double>(fpu.read_single(rs1_)) *
                                 static_cast<double>(fpu.read_single(rs2_)));
            break;

        // Integer to float
        case 0x0C4: {  // FiTOs
            uint32_t raw = fpu.read_raw(rs2_);
            int32_t ival = static_cast<int32_t>(raw);
            fpu.write_single(rd_, static_cast<float>(ival));
            break;
        }
        case 0x0C8: {  // FiTOd
            uint32_t raw = fpu.read_raw(rs2_);
            int32_t ival = static_cast<int32_t>(raw);
            fpu.write_double(rd_, static_cast<double>(ival));
            break;
        }

        // Float to integer
        case 0x0D1: {  // FsTOi
            float fval = fpu.read_single(rs2_);
            int32_t ival;
            if (std::isnan(fval)) ival = INT32_MAX;
            else if (std::isinf(fval)) ival = fval > 0 ? INT32_MAX : INT32_MIN;
            else if (fval >= 2147483648.0f) ival = INT32_MAX;
            else if (fval < -2147483648.0f) ival = INT32_MIN;
            else ival = static_cast<int32_t>(fval);
            fpu.write_raw(rd_, static_cast<uint32_t>(ival));
            break;
        }
        case 0x0D2: {  // FdTOi
            double fval = fpu.read_double(rs2_);
            int32_t ival;
            if (std::isnan(fval)) ival = INT32_MAX;
            else if (std::isinf(fval)) ival = fval > 0 ? INT32_MAX : INT32_MIN;
            else if (fval >= 2147483648.0) ival = INT32_MAX;
            else if (fval < -2147483648.0) ival = INT32_MIN;
            else ival = static_cast<int32_t>(fval);
            fpu.write_raw(rd_, static_cast<uint32_t>(ival));
            break;
        }

        // Single/double conversions
        case 0x0C9:  // FsTOd
            fpu.write_double(rd_, static_cast<double>(fpu.read_single(rs2_)));
            break;
        case 0x0C6:  // FdTOs
            fpu.write_single(rd_, static_cast<float>(fpu.read_double(rs2_)));
            break;

        default:
            throw std::runtime_error("Unimplemented FPop1 opf");
    }
}

// ============================================================================
// FPop2Instruction
// ============================================================================

FPop2Instruction::FPop2Instruction(uint32_t inst) : Instruction(inst) {
    rs1_ = (inst >> 14) & 0b11111;
    rs2_ = inst & 0b11111;
    opf_ = (inst >> 5) & 0x1FF;
}

void FPop2Instruction::execute(CpuState& cpu) {
    auto& fpu = cpu.fpu;

    switch (opf_) {
        case 0x051:  // FCMPs
        case 0x055:  // FCMPEs
            fpu.compare(fpu.read_single(rs1_), fpu.read_single(rs2_));
            break;
        case 0x052:  // FCMPd
        case 0x056:  // FCMPEd
            fpu.compare(fpu.read_double(rs1_), fpu.read_double(rs2_));
            break;
        default:
            throw std::runtime_error("Unimplemented FPop2 opf");
    }
}

// ============================================================================
// FBfccInstruction
// ============================================================================

FBfccInstruction::FBfccInstruction(uint32_t inst) : Instruction(inst) {
    cond_ = (inst >> 25) & 0b1111;
    annul_ = (inst >> 29) & 0b1;
    disp22_ = sign_extend_22(inst & 0x3FFFFF);
}

void FBfccInstruction::execute(CpuState& cpu) {
    FCC fcc = cpu.fpu.fcc();
    bool take_branch = false;

    switch (cond_) {
        case 0b0000:  // FBN (never)
            take_branch = false;
            break;
        case 0b1000:  // FBA (always)
            take_branch = true;
            break;
        case 0b0111:  // FBU (unordered)
            take_branch = (fcc == FCC::Unordered);
            break;
        case 0b0110:  // FBG (greater)
            take_branch = (fcc == FCC::Greater);
            break;
        case 0b0101:  // FBUG (unordered or greater)
            take_branch = (fcc == FCC::Unordered || fcc == FCC::Greater);
            break;
        case 0b0100:  // FBL (less)
            take_branch = (fcc == FCC::Less);
            break;
        case 0b0011:  // FBUL (unordered or less)
            take_branch = (fcc == FCC::Unordered || fcc == FCC::Less);
            break;
        case 0b0010:  // FBLG (less or greater)
            take_branch = (fcc == FCC::Less || fcc == FCC::Greater);
            break;
        case 0b0001:  // FBNE (not equal)
            take_branch = (fcc != FCC::Equal);
            break;
        case 0b1001:  // FBE (equal)
            take_branch = (fcc == FCC::Equal);
            break;
        case 0b1010:  // FBUE (unordered or equal)
            take_branch = (fcc == FCC::Unordered || fcc == FCC::Equal);
            break;
        case 0b1011:  // FBGE (greater or equal)
            take_branch = (fcc == FCC::Greater || fcc == FCC::Equal);
            break;
        case 0b1100:  // FBUGE (unordered, greater or equal)
            take_branch = (fcc == FCC::Unordered || fcc == FCC::Greater || fcc == FCC::Equal);
            break;
        case 0b1101:  // FBLE (less or equal)
            take_branch = (fcc == FCC::Less || fcc == FCC::Equal);
            break;
        case 0b1110:  // FBULE (unordered, less or equal)
            take_branch = (fcc == FCC::Unordered || fcc == FCC::Less || fcc == FCC::Equal);
            break;
        case 0b1111:  // FBO (ordered)
            take_branch = (fcc != FCC::Unordered);
            break;
        default:
            throw std::runtime_error("Unknown FBfcc condition");
    }

    bool is_unconditional = (cond_ == 0b1000 || cond_ == 0b0000);

    if (take_branch) {
        cpu.npc = (cpu.pc + (disp22_ << 2)) & 0xFFFFFFFF;
        if (annul_ && is_unconditional) {
            cpu.annul_next = true;
        }
    } else if (annul_) {
        cpu.annul_next = true;
    }
}

} // namespace sun4m
