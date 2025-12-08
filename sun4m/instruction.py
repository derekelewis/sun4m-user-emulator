from __future__ import annotations

from typing import TYPE_CHECKING

from .syscall import Syscall

if TYPE_CHECKING:
    from .cpu import CpuState


class Instruction:
    def __init__(self, inst: int):
        self.inst = inst

    def execute(self, cpu_state: CpuState):
        pass


class CallInstruction(Instruction):
    def __init__(self, inst: int):
        super().__init__(inst)
        self.disp30: int = self.inst & ((1 << 30) - 1)  # erase op bits
        if self.disp30 & (0b1 << 29):  # sign extend
            self.disp30 |= 0b11 << 30

    def execute(self, cpu_state: CpuState):
        # disp30 is word offset, so we need to multiply by 4 & wraparound on overflow
        cpu_state.npc = (cpu_state.pc + (self.disp30 << 2)) & 0xFFFFFFFF
        # Write pc to %o7 to ensure we have a return address. Otherwise, the return will be 0.
        # We use pc since the RETL = JMPL %o7 + 8, %g0, which jump past the delay slot on return.
        cpu_state.registers.write_register(15, cpu_state.pc)


class Format2Instruction(Instruction):
    def __init__(self, inst: int):
        super().__init__(inst)
        self.op2: int = self.inst >> 22 & 0b111
        if self.op2 == 0b100:  # SETHI
            self.rd: int = self.inst >> 25 & 0b11111
            self.imm22: int = self.inst & 0b11_1111_1111_1111_1111_1111
        elif self.op2 == 0b010:  # Bicc (branch on integer condition codes)
            self.cond: int = self.inst >> 25 & 0b1111
            self.a: int = self.inst >> 29 & 0b1  # annul bit
            disp22: int = self.inst & 0x3FFFFF
            # Sign extend disp22
            if disp22 & 0x200000:  # bit 21 set = negative
                disp22 |= 0xFFC00000  # sign extend to 32 bits
                self.disp22: int = disp22 - 0x100000000  # convert to signed Python int
            else:
                self.disp22 = disp22

    def execute(self, cpu_state: CpuState):
        match self.op2:
            case 0b100:  # SETHI instruction
                value: int = self.imm22 << 10
                cpu_state.registers.write_register(self.rd, value)
            case 0b010:  # Bicc (branch on integer condition codes)
                self._execute_bicc(cpu_state)

    def _execute_bicc(self, cpu_state: CpuState) -> None:
        """Execute branch on integer condition codes."""
        icc = cpu_state.icc
        take_branch: bool = False

        match self.cond:
            case 0b0000:  # BN (never)
                take_branch = False
            case 0b1000:  # BA (always)
                take_branch = True
            case 0b1001:  # BNE (not equal, Z=0)
                take_branch = not icc.z
            case 0b0001:  # BE (equal, Z=1)
                take_branch = icc.z
            case 0b1010:  # BG (greater, Z=0 and (N xor V)=0)
                take_branch = not icc.z and (icc.n == icc.v)
            case 0b0010:  # BLE (less or equal, Z=1 or (N xor V)=1)
                take_branch = icc.z or (icc.n != icc.v)
            case 0b1011:  # BGE (greater or equal, (N xor V)=0)
                take_branch = icc.n == icc.v
            case 0b0011:  # BL (less, (N xor V)=1)
                take_branch = icc.n != icc.v
            case 0b1100:  # BGU (greater unsigned, C=0 and Z=0)
                take_branch = not icc.c and not icc.z
            case 0b0100:  # BLEU (less or equal unsigned, C=1 or Z=1)
                take_branch = icc.c or icc.z
            case 0b1101:  # BCC (carry clear, C=0)
                take_branch = not icc.c
            case 0b0101:  # BCS (carry set, C=1)
                take_branch = icc.c
            case 0b1110:  # BPOS (positive, N=0)
                take_branch = not icc.n
            case 0b0110:  # BNEG (negative, N=1)
                take_branch = icc.n
            case 0b1111:  # BVC (overflow clear, V=0)
                take_branch = not icc.v
            case 0b0111:  # BVS (overflow set, V=1)
                take_branch = icc.v
            case _:
                raise ValueError(f"unknown branch condition: {self.cond:#06b}")

        # Check if this is an unconditional branch (BA or BN)
        is_unconditional = self.cond in (0b1000, 0b0000)  # BA or BN

        if take_branch:
            # Branch target is PC + (disp22 * 4)
            cpu_state.npc = (cpu_state.pc + (self.disp22 << 2)) & 0xFFFFFFFF
            # For unconditional branches with annul, skip the delay slot
            if self.a and is_unconditional:
                cpu_state.annul_next = True
        elif self.a:
            # Conditional branch not taken with annul: skip the delay slot
            cpu_state.annul_next = True

    def __str__(self) -> str:
        if self.op2 == 0b100:
            return f"rd: {self.rd}, op2: {self.op2}, imm22: {self.imm22}"
        elif self.op2 == 0b010:
            return f"cond: {self.cond}, a: {self.a}, op2: {self.op2}, disp22: {self.disp22}"
        return f"op2: {self.op2}"


class TrapInstruction(Instruction):
    def __init__(self, inst: int):
        super().__init__(inst)
        self.op3: int = self.inst >> 19 & 0b111111
        self.rs1: int = self.inst >> 14 & 0b11111
        self.i: int = self.inst >> 13 & 0b1
        self.cond: int = self.inst >> 25 & 0b1111
        if self.i:
            self.imm7: int = self.inst & 0b1111111  # not signed
        else:
            self.rs2: int = self.inst & 0b11111

    def execute(self, cpu_state: CpuState) -> None:
        trap_num: int
        if self.i:
            trap_num = (cpu_state.registers.read_register(self.rs1) + self.imm7) % 128
        else:
            trap_num = (
                cpu_state.registers.read_register(self.rs1)
                + cpu_state.registers.read_register(self.rs2)
            ) % 128

        if trap_num == 0x03:  # Flush Windows trap
            # This trap flushes register windows to the stack.
            # For user mode with sufficient windows, we just return.
            # A full implementation would spill windows to memory.
            pass
        elif trap_num == 0x10:  # Software interrupt 0x10 - syscall trap
            if self.cond == 0b1000:  # TA (Trap Always)
                syscall_handler: Syscall = Syscall(cpu_state)
                syscall_handler.handle()
        else:
            raise ValueError(f"unimplemented trap number: {trap_num:#x}")

    def __str__(self) -> str:
        inst_string: str = (
            f"op3: {self.op3}, rs1: {self.rs1}, i: {self.i}, cond: {self.cond}"
        )
        if self.i:
            inst_string += f", imm7: {self.imm7}"
        else:
            inst_string += f", rs2: {self.rs2}"
        return inst_string


class Format3Instruction(Instruction):
    def __init__(self, inst: int):
        super().__init__(inst)
        self.op: int = (
            self.inst >> 30 & 0b11
        )  # op=2 for arithmetic, op=3 for load/store
        self.rd: int = self.inst >> 25 & 0b11111
        self.op3: int = self.inst >> 19 & 0b111111
        self.rs1: int = self.inst >> 14 & 0b11111
        self.i: int = self.inst >> 13 & 0b1
        if self.i:
            self.simm13: int = self.inst & 0b1111111111111
            if self.simm13 >> 12:  # negative signed
                self.simm13 -= 0x2000  # get the negative value
        else:
            self.rs2: int = self.inst & 0b11111

    def _get_operand2(self, cpu_state: CpuState) -> int:
        """Get the second operand (either simm13 or rs2 register value)."""
        if self.i:
            return self.simm13
        else:
            return cpu_state.registers.read_register(self.rs2)

    def execute(self, cpu_state: CpuState) -> None:
        if self.op == 3:  # Load/Store instructions
            self._execute_load_store(cpu_state)
        else:  # op == 2: Arithmetic/Logical instructions
            self._execute_arithmetic(cpu_state)

    def _execute_load_store(self, cpu_state: CpuState) -> None:
        # Compute effective address: rs1 + (simm13 or rs2)
        rs1_val = cpu_state.registers.read_register(self.rs1)
        if self.i:
            memory_address = (rs1_val + self.simm13) & 0xFFFFFFFF
        else:
            rs2_val = cpu_state.registers.read_register(self.rs2)
            memory_address = (rs1_val + rs2_val) & 0xFFFFFFFF

        match self.op3:
            case 0b000000:  # LD (load word)
                # TODO: raise exception on unaligned memory access
                load_word = cpu_state.memory.read(memory_address, 4)
                cpu_state.registers.write_register(
                    self.rd, int.from_bytes(load_word, "big")
                )
            case 0b000001:  # LDUB (load unsigned byte)
                load_byte = cpu_state.memory.read(memory_address, 1)
                cpu_state.registers.write_register(self.rd, load_byte[0])
            case 0b001001:  # LDSB (load signed byte)
                load_byte = cpu_state.memory.read(memory_address, 1)
                value = load_byte[0]
                if value & 0x80:  # sign extend
                    value |= 0xFFFFFF00
                cpu_state.registers.write_register(self.rd, value)
            case 0b000010:  # LDUH (load unsigned halfword)
                load_half = cpu_state.memory.read(memory_address, 2)
                cpu_state.registers.write_register(
                    self.rd, int.from_bytes(load_half, "big")
                )
            case 0b001010:  # LDSH (load signed halfword)
                load_half = cpu_state.memory.read(memory_address, 2)
                value = int.from_bytes(load_half, "big")
                if value & 0x8000:  # sign extend
                    value |= 0xFFFF0000
                cpu_state.registers.write_register(self.rd, value)
            case 0b000011:  # LDD (load doubleword)
                # SPARC V8 requires 8-byte alignment and even rd
                if memory_address & 0x7:
                    raise ValueError(
                        f"LDD: address {memory_address:#x} not 8-byte aligned"
                    )
                if self.rd & 0x1:
                    raise ValueError(f"LDD: rd={self.rd} must be even")
                # Load 8 bytes into rd and rd+1
                load_high = cpu_state.memory.read(memory_address, 4)
                load_low = cpu_state.memory.read(memory_address + 4, 4)
                cpu_state.registers.write_register(
                    self.rd, int.from_bytes(load_high, "big")
                )
                cpu_state.registers.write_register(
                    self.rd + 1, int.from_bytes(load_low, "big")
                )
            case 0b000100:  # ST (store word)
                # TODO: raise exception on unaligned memory access
                store_word = cpu_state.registers.read_register(self.rd) & 0xFFFFFFFF
                cpu_state.memory.write(
                    memory_address, store_word.to_bytes(4, byteorder="big")
                )
            case 0b000101:  # STB (store byte)
                store_val = cpu_state.registers.read_register(self.rd) & 0xFF
                cpu_state.memory.write(memory_address, bytes([store_val]))
            case 0b000110:  # STH (store halfword)
                store_val = cpu_state.registers.read_register(self.rd) & 0xFFFF
                cpu_state.memory.write(
                    memory_address, store_val.to_bytes(2, byteorder="big")
                )
            case 0b000111:  # STD (store doubleword)
                # SPARC V8 requires 8-byte alignment and even rd
                if memory_address & 0x7:
                    raise ValueError(
                        f"STD: address {memory_address:#x} not 8-byte aligned"
                    )
                if self.rd & 0x1:
                    raise ValueError(f"STD: rd={self.rd} must be even")
                # Store from rd and rd+1 to memory
                high_word = cpu_state.registers.read_register(self.rd) & 0xFFFFFFFF
                low_word = cpu_state.registers.read_register(self.rd + 1) & 0xFFFFFFFF
                cpu_state.memory.write(
                    memory_address, high_word.to_bytes(4, byteorder="big")
                )
                cpu_state.memory.write(
                    memory_address + 4, low_word.to_bytes(4, byteorder="big")
                )
            case 0b111111:  # SWAP (atomic swap)
                # Load word from memory, store rd to memory
                old_value = cpu_state.memory.read(memory_address, 4)
                new_value = cpu_state.registers.read_register(self.rd) & 0xFFFFFFFF
                cpu_state.memory.write(
                    memory_address, new_value.to_bytes(4, byteorder="big")
                )
                cpu_state.registers.write_register(
                    self.rd, int.from_bytes(old_value, "big")
                )
            case 0b001101:  # LDSTUB (Load-Store Unsigned Byte)
                # Atomically read byte and write 0xFF
                old_byte = cpu_state.memory.read(memory_address, 1)
                cpu_state.memory.write(memory_address, bytes([0xFF]))
                cpu_state.registers.write_register(self.rd, old_byte[0])
            case _:
                raise ValueError(f"unimplemented load/store opcode: {self.op3:#08b}")

    def _execute_arithmetic(self, cpu_state: CpuState) -> None:
        match self.op3:
            case 0b000000:  # ADD instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = (op1 + op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b010000:  # ADDCC instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = (op1 + op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
                cpu_state.icc.update(result, op1, op2, is_sub=False)
            case 0b000100:  # SUB instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = (op1 - op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b010100:  # SUBCC instruction (used for CMP when rd=%g0)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = (op1 - op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
                cpu_state.icc.update(result, op1, op2, is_sub=True)
            case 0b100001:  # TSUBcc (Tagged Subtract with CC)
                # Simplified: treat like SUBCC, ignoring tag overflow
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = (op1 - op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
                cpu_state.icc.update(result, op1, op2, is_sub=True)
            case 0b001000:  # ADDX instruction (Add with Carry)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                carry = 1 if cpu_state.icc.c else 0
                result = (op1 + op2 + carry) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b001100:  # SUBX instruction (Subtract with Carry)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                # C=1 means there was a borrow from previous subtraction
                borrow = 1 if cpu_state.icc.c else 0
                result = (op1 - op2 - borrow) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b000001:  # AND instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 & op2
                cpu_state.registers.write_register(self.rd, result)
            case 0b010001:  # ANDCC instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 & op2
                cpu_state.registers.write_register(self.rd, result)
                cpu_state.icc.update(result, op1, op2, is_sub=False)
            case 0b000101:  # ANDN instruction (AND NOT)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 & (~op2 & 0xFFFFFFFF)
                cpu_state.registers.write_register(self.rd, result)
            case 0b000010:  # OR instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 | op2
                cpu_state.registers.write_register(self.rd, result)
            case 0b010010:  # ORCC instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 | op2
                cpu_state.registers.write_register(self.rd, result)
                cpu_state.icc.update(result, op1, op2, is_sub=False)
            case 0b000110:  # ORN instruction (OR NOT)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 | (~op2 & 0xFFFFFFFF)
                cpu_state.registers.write_register(self.rd, result)
            case 0b000011:  # XOR instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = op1 ^ op2
                cpu_state.registers.write_register(self.rd, result)
            case 0b000111:  # XNOR instruction
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                result = ~(op1 ^ op2) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b100101:  # SLL instruction (Shift Left Logical)
                op1 = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    shift_count = self.simm13 & 0x1F  # Only lower 5 bits
                else:
                    shift_count = cpu_state.registers.read_register(self.rs2) & 0x1F
                result = (op1 << shift_count) & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b100110:  # SRL instruction (Shift Right Logical)
                op1 = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    shift_count = self.simm13 & 0x1F  # Only lower 5 bits
                else:
                    shift_count = cpu_state.registers.read_register(self.rs2) & 0x1F
                result = op1 >> shift_count
                cpu_state.registers.write_register(self.rd, result)
            case 0b100111:  # SRA instruction (Shift Right Arithmetic)
                op1 = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    shift_count = self.simm13 & 0x1F  # Only lower 5 bits
                else:
                    shift_count = cpu_state.registers.read_register(self.rs2) & 0x1F
                # Arithmetic shift: preserve sign bit
                if op1 & 0x80000000:  # negative
                    result = (op1 >> shift_count) | (
                        ((1 << shift_count) - 1) << (32 - shift_count)
                    )
                else:
                    result = op1 >> shift_count
                result = result & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b001010:  # UMUL instruction (Unsigned Multiply)
                op1 = cpu_state.registers.read_register(self.rs1) & 0xFFFFFFFF
                op2 = self._get_operand2(cpu_state) & 0xFFFFFFFF
                result64 = op1 * op2
                cpu_state.y = (result64 >> 32) & 0xFFFFFFFF
                result = result64 & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b001011:  # SMUL instruction (Signed Multiply)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                # Sign extend to 64 bits
                if op1 & 0x80000000:
                    op1_signed = op1 - 0x100000000
                else:
                    op1_signed = op1
                if op2 & 0x80000000:
                    op2_signed = op2 - 0x100000000
                else:
                    op2_signed = op2
                result64 = op1_signed * op2_signed
                # Handle negative results
                if result64 < 0:
                    result64 = result64 & 0xFFFFFFFFFFFFFFFF
                cpu_state.y = (result64 >> 32) & 0xFFFFFFFF
                result = result64 & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b001110:  # UDIV instruction (Unsigned Divide)
                # Dividend is Y:rs1 (64-bit unsigned), divisor is rs2/simm13
                y = cpu_state.y
                rs1_val = cpu_state.registers.read_register(self.rs1)
                dividend = (y << 32) | rs1_val
                op2 = self._get_operand2(cpu_state)
                divisor = op2 & 0xFFFFFFFF
                if divisor == 0:
                    raise ValueError("division by zero")
                quotient = dividend // divisor
                # Clamp to 32-bit unsigned range
                if quotient > 0xFFFFFFFF:
                    quotient = 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, quotient)
            case 0b001111:  # SDIV instruction (Signed Divide)
                # Dividend is Y:rs1 (64-bit), divisor is rs2/simm13
                y = cpu_state.y
                rs1_val = cpu_state.registers.read_register(self.rs1)
                dividend = (y << 32) | rs1_val
                # Sign extend dividend if negative
                if dividend & 0x8000000000000000:
                    dividend = dividend - 0x10000000000000000
                op2 = self._get_operand2(cpu_state)
                if op2 & 0x80000000:
                    divisor = op2 - 0x100000000
                else:
                    divisor = op2
                if divisor == 0:
                    raise ValueError("division by zero")
                quotient = int(dividend / divisor)  # Python's // rounds toward -inf
                # Clamp to 32-bit signed range
                if quotient > 0x7FFFFFFF:
                    quotient = 0x7FFFFFFF
                elif quotient < -0x80000000:
                    quotient = -0x80000000
                result = quotient & 0xFFFFFFFF
                cpu_state.registers.write_register(self.rd, result)
            case 0b101000:  # RDY instruction (Read Y register)
                cpu_state.registers.write_register(self.rd, cpu_state.y)
            case 0b110000:  # WRY instruction (Write Y register)
                op1 = cpu_state.registers.read_register(self.rs1)
                op2 = self._get_operand2(cpu_state)
                cpu_state.y = (op1 ^ op2) & 0xFFFFFFFF
            case 0b111000:  # JMPL instruction
                # TODO: check for alignment
                cpu_state.registers.write_register(self.rd, cpu_state.pc)
                if self.i:
                    cpu_state.npc = (
                        cpu_state.registers.read_register(self.rs1) + self.simm13
                    ) & 0xFFFFFFFF
                else:
                    cpu_state.npc = (
                        cpu_state.registers.read_register(self.rs1)
                        + cpu_state.registers.read_register(self.rs2)
                    ) & 0xFFFFFFFF
            case 0b111100:  # SAVE instruction
                # Calculate the result BEFORE changing CWP
                sp = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    sp = sp + self.simm13
                else:
                    sp = sp + cpu_state.registers.read_register(self.rs2)

                # Decrement CWP (wraps around with large window pool)
                n_windows = cpu_state.registers.n_windows
                cpu_state.registers.cwp = (cpu_state.registers.cwp - 1) % n_windows
                cpu_state.registers.write_register(self.rd, sp)
            case 0b111101:  # RESTORE instruction
                # Calculate the result BEFORE changing CWP
                sp = cpu_state.registers.read_register(self.rs1)
                if self.i:
                    sp = sp + self.simm13
                else:
                    sp = sp + cpu_state.registers.read_register(self.rs2)

                # Increment CWP (wraps around with large window pool)
                n_windows = cpu_state.registers.n_windows
                cpu_state.registers.cwp = (cpu_state.registers.cwp + 1) % n_windows
                cpu_state.registers.write_register(self.rd, sp)
            case _:
                raise ValueError(f"unimplemented arithmetic opcode: {self.op3:#08b}")

    def __str__(self) -> str:
        inst_string: str = (
            f"rd: {self.rd}, op3: {self.op3}, rs1: {self.rs1}, i: {self.i}"
        )
        if self.i:
            inst_string += f", simm13: {self.simm13}"
        else:
            inst_string += f", rs2: {self.rs2}"
        return inst_string


class FPLoadStoreInstruction(Instruction):
    """Floating-point load/store instructions (Format 3, op=3).

    Handles: LDF, LDDF, LDFSR, STF, STDF, STFSR
    """

    def __init__(self, inst: int):
        super().__init__(inst)
        self.op3: int = (inst >> 19) & 0b111111
        self.rd: int = (inst >> 25) & 0b11111  # FP register
        self.rs1: int = (inst >> 14) & 0b11111
        self.i: int = (inst >> 13) & 0b1
        if self.i:
            simm13 = inst & 0b1111111111111
            if simm13 >> 12:  # negative signed
                simm13 -= 0x2000
            self.simm13: int = simm13
        else:
            self.rs2: int = inst & 0b11111

    def execute(self, cpu_state: CpuState) -> None:
        # Compute effective address
        rs1_val = cpu_state.registers.read_register(self.rs1)
        if self.i:
            addr = (rs1_val + self.simm13) & 0xFFFFFFFF
        else:
            rs2_val = cpu_state.registers.read_register(self.rs2)
            addr = (rs1_val + rs2_val) & 0xFFFFFFFF

        match self.op3:
            case 0b100000:  # LDF (load float, single)
                data = cpu_state.memory.read(addr, 4)
                cpu_state.fpu.write_raw(self.rd, int.from_bytes(data, "big"))
            case 0b100011:  # LDDF (load double float)
                if self.rd & 1:
                    raise ValueError(f"LDDF: rd={self.rd} must be even")
                if addr & 0x7:
                    raise ValueError(f"LDDF: address {addr:#x} not 8-byte aligned")
                high_bytes = cpu_state.memory.read(addr, 4)
                low_bytes = cpu_state.memory.read(addr + 4, 4)
                cpu_state.fpu.write_raw(self.rd, int.from_bytes(high_bytes, "big"))
                cpu_state.fpu.write_raw(self.rd + 1, int.from_bytes(low_bytes, "big"))
            case 0b100001:  # LDFSR (load FSR)
                data = cpu_state.memory.read(addr, 4)
                cpu_state.fpu.fsr = int.from_bytes(data, "big")
            case 0b100100:  # STF (store float, single)
                val = cpu_state.fpu.read_raw(self.rd)
                cpu_state.memory.write(addr, val.to_bytes(4, "big"))
            case 0b100111:  # STDF (store double float)
                if self.rd & 1:
                    raise ValueError(f"STDF: rd={self.rd} must be even")
                if addr & 0x7:
                    raise ValueError(f"STDF: address {addr:#x} not 8-byte aligned")
                high_val = cpu_state.fpu.read_raw(self.rd)
                low_val = cpu_state.fpu.read_raw(self.rd + 1)
                cpu_state.memory.write(addr, high_val.to_bytes(4, "big"))
                cpu_state.memory.write(addr + 4, low_val.to_bytes(4, "big"))
            case 0b100101:  # STFSR (store FSR)
                cpu_state.memory.write(addr, cpu_state.fpu.fsr.to_bytes(4, "big"))
            case _:
                raise ValueError(f"unimplemented FP load/store opcode: {self.op3:#08b}")


class FPop1Instruction(Instruction):
    """Floating-point operate instructions (Format 3, op=2, op3=0b110100).

    Handles arithmetic, conversions, and utility FP operations.
    Uses opf field (bits 13-5) to distinguish operations.
    """

    def __init__(self, inst: int):
        super().__init__(inst)
        self.rd: int = (inst >> 25) & 0b11111
        self.rs1: int = (inst >> 14) & 0b11111
        self.rs2: int = inst & 0b11111
        self.opf: int = (inst >> 5) & 0x1FF

    def execute(self, cpu_state: CpuState) -> None:
        import math

        fpu = cpu_state.fpu

        match self.opf:
            # Move/Negate/Abs (single only, operate on raw bits)
            case 0x001:  # FMOVs
                fpu.write_raw(self.rd, fpu.read_raw(self.rs2))
            case 0x005:  # FNEGs
                val = fpu.read_raw(self.rs2)
                fpu.write_raw(self.rd, val ^ 0x80000000)  # flip sign bit
            case 0x009:  # FABSs
                val = fpu.read_raw(self.rs2)
                fpu.write_raw(self.rd, val & 0x7FFFFFFF)  # clear sign bit

            # Square root
            case 0x029:  # FSQRTs
                fs = fpu.read_single(self.rs2)
                fpu.write_single(self.rd, math.sqrt(fs))
            case 0x02A:  # FSQRTd
                fd = fpu.read_double(self.rs2)
                fpu.write_double(self.rd, math.sqrt(fd))

            # Add
            case 0x041:  # FADDs
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.write_single(self.rd, a + b)
            case 0x042:  # FADDd
                a = fpu.read_double(self.rs1)
                b = fpu.read_double(self.rs2)
                fpu.write_double(self.rd, a + b)

            # Subtract
            case 0x045:  # FSUBs
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.write_single(self.rd, a - b)
            case 0x046:  # FSUBd
                a = fpu.read_double(self.rs1)
                b = fpu.read_double(self.rs2)
                fpu.write_double(self.rd, a - b)

            # Multiply
            case 0x049:  # FMULs
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.write_single(self.rd, a * b)
            case 0x04A:  # FMULd
                a = fpu.read_double(self.rs1)
                b = fpu.read_double(self.rs2)
                fpu.write_double(self.rd, a * b)

            # Divide
            case 0x04D:  # FDIVs
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.write_single(self.rd, a / b)
            case 0x04E:  # FDIVd
                a = fpu.read_double(self.rs1)
                b = fpu.read_double(self.rs2)
                fpu.write_double(self.rd, a / b)

            # FsMULd - multiply singles to produce double
            case 0x069:  # FsMULd
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.write_double(self.rd, float(a) * float(b))

            # Integer to float conversions
            case 0x0C4:  # FiTOs - integer to single
                raw = fpu.read_raw(self.rs2)
                # Interpret as signed 32-bit integer
                if raw & 0x80000000:
                    ival = raw - 0x100000000
                else:
                    ival = raw
                fpu.write_single(self.rd, float(ival))
            case 0x0C8:  # FiTOd - integer to double
                raw = fpu.read_raw(self.rs2)
                if raw & 0x80000000:
                    ival = raw - 0x100000000
                else:
                    ival = raw
                fpu.write_double(self.rd, float(ival))

            # Float to integer conversions (truncate toward zero)
            case 0x0D1:  # FsTOi - single to integer
                fval_s = fpu.read_single(self.rs2)
                ival_s = int(fval_s)
                # Clamp to 32-bit signed range
                if ival_s > 0x7FFFFFFF:
                    ival_s = 0x7FFFFFFF
                elif ival_s < -0x80000000:
                    ival_s = -0x80000000
                fpu.write_raw(self.rd, ival_s & 0xFFFFFFFF)
            case 0x0D2:  # FdTOi - double to integer
                fval_d = fpu.read_double(self.rs2)
                ival_d = int(fval_d)
                if ival_d > 0x7FFFFFFF:
                    ival_d = 0x7FFFFFFF
                elif ival_d < -0x80000000:
                    ival_d = -0x80000000
                fpu.write_raw(self.rd, ival_d & 0xFFFFFFFF)

            # Single/double conversions
            case 0x0C9:  # FsTOd - single to double
                src_s = fpu.read_single(self.rs2)
                fpu.write_double(self.rd, float(src_s))
            case 0x0C6:  # FdTOs - double to single
                src_d = fpu.read_double(self.rs2)
                fpu.write_single(self.rd, src_d)

            case _:
                raise ValueError(f"unimplemented FPop1 opf: {self.opf:#05x}")


class FPop2Instruction(Instruction):
    """Floating-point compare instructions (Format 3, op=2, op3=0b110101).

    Handles: FCMPs, FCMPd, FCMPEs, FCMPEd
    """

    def __init__(self, inst: int):
        super().__init__(inst)
        self.rs1: int = (inst >> 14) & 0b11111
        self.rs2: int = inst & 0b11111
        self.opf: int = (inst >> 5) & 0x1FF

    def execute(self, cpu_state: CpuState) -> None:
        fpu = cpu_state.fpu

        match self.opf:
            case 0x051 | 0x055:  # FCMPs, FCMPEs
                a = fpu.read_single(self.rs1)
                b = fpu.read_single(self.rs2)
                fpu.compare(a, b)
            case 0x052 | 0x056:  # FCMPd, FCMPEd
                a = fpu.read_double(self.rs1)
                b = fpu.read_double(self.rs2)
                fpu.compare(a, b)
            case _:
                raise ValueError(f"unimplemented FPop2 opf: {self.opf:#05x}")


class FBfccInstruction(Instruction):
    """Floating-point branch on condition codes (Format 2, op=0, op2=0b110).

    Branches based on FCC (floating-point condition codes) in the FSR.
    """

    def __init__(self, inst: int):
        super().__init__(inst)
        self.cond: int = (inst >> 25) & 0b1111
        self.a: int = (inst >> 29) & 0b1  # annul bit
        disp22: int = inst & 0x3FFFFF
        # Sign extend disp22
        if disp22 & 0x200000:
            disp22 |= 0xFFC00000
            self.disp22: int = disp22 - 0x100000000
        else:
            self.disp22 = disp22

    def execute(self, cpu_state: CpuState) -> None:
        from sun4m.cpu import FCC_E, FCC_L, FCC_G, FCC_U

        fcc = cpu_state.fpu.fcc
        take_branch: bool = False

        # FCC values: E=0, L=1, G=2, U=3
        match self.cond:
            case 0b0000:  # FBN (never)
                take_branch = False
            case 0b1000:  # FBA (always)
                take_branch = True
            case 0b0111:  # FBU (unordered)
                take_branch = fcc == FCC_U
            case 0b0110:  # FBG (greater)
                take_branch = fcc == FCC_G
            case 0b0101:  # FBUG (unordered or greater)
                take_branch = fcc in (FCC_U, FCC_G)
            case 0b0100:  # FBL (less)
                take_branch = fcc == FCC_L
            case 0b0011:  # FBUL (unordered or less)
                take_branch = fcc in (FCC_U, FCC_L)
            case 0b0010:  # FBLG (less or greater)
                take_branch = fcc in (FCC_L, FCC_G)
            case 0b0001:  # FBNE (not equal)
                take_branch = fcc != FCC_E
            case 0b1001:  # FBE (equal)
                take_branch = fcc == FCC_E
            case 0b1010:  # FBUE (unordered or equal)
                take_branch = fcc in (FCC_U, FCC_E)
            case 0b1011:  # FBGE (greater or equal)
                take_branch = fcc in (FCC_G, FCC_E)
            case 0b1100:  # FBUGE (unordered, greater or equal)
                take_branch = fcc in (FCC_U, FCC_G, FCC_E)
            case 0b1101:  # FBLE (less or equal)
                take_branch = fcc in (FCC_L, FCC_E)
            case 0b1110:  # FBULE (unordered, less or equal)
                take_branch = fcc in (FCC_U, FCC_L, FCC_E)
            case 0b1111:  # FBO (ordered)
                take_branch = fcc != FCC_U
            case _:
                raise ValueError(f"unknown FBfcc condition: {self.cond:#06b}")

        # Check if this is an unconditional branch (FBA or FBN)
        is_unconditional = self.cond in (0b1000, 0b0000)

        if take_branch:
            cpu_state.npc = (cpu_state.pc + (self.disp22 << 2)) & 0xFFFFFFFF
            if self.a and is_unconditional:
                cpu_state.annul_next = True
        elif self.a:
            cpu_state.annul_next = True
