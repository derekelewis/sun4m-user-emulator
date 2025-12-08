from functools import lru_cache
from .instruction import (
    Instruction,
    CallInstruction,
    Format2Instruction,
    Format3Instruction,
    TrapInstruction,
    FPLoadStoreInstruction,
    FPop1Instruction,
    FPop2Instruction,
    FBfccInstruction,
)

# FP load/store op3 codes (op=3)
FP_LOAD_STORE_OP3 = {
    0b100000,  # LDF
    0b100001,  # LDFSR
    0b100011,  # LDDF
    0b100100,  # STF
    0b100101,  # STFSR
    0b100111,  # STDF
}


@lru_cache
def decode(inst: int) -> Instruction:
    op = (inst >> 30) & 0b11

    if op == 1:
        return CallInstruction(inst)

    elif op == 0:
        op2 = (inst >> 22) & 0b111
        if op2 == 0b110:  # FBfcc (floating-point branch)
            return FBfccInstruction(inst)
        return Format2Instruction(inst)

    elif op == 2:
        op3 = (inst >> 19) & 0b111111
        if op3 == 0b111010:  # Trap
            return TrapInstruction(inst)
        elif op3 == 0b110100:  # FPop1
            return FPop1Instruction(inst)
        elif op3 == 0b110101:  # FPop2
            return FPop2Instruction(inst)
        return Format3Instruction(inst)

    elif op == 3:
        op3 = (inst >> 19) & 0b111111
        if op3 in FP_LOAD_STORE_OP3:
            return FPLoadStoreInstruction(inst)
        return Format3Instruction(inst)

    else:
        raise ValueError("unknown instruction format")
