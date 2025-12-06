from functools import lru_cache
from .instruction import (
    Instruction,
    CallInstruction,
    Format2Instruction,
    Format3Instruction,
    TrapInstruction,
)


@lru_cache
def decode(inst: int) -> Instruction:
    op = (inst >> 30) & 0b11
    if op == 1:
        return CallInstruction(inst)
    elif op == 0:
        return Format2Instruction(inst)
    elif op in (2, 3):
        if ((inst >> 19) & 0b111111) == 0b111010:
            return TrapInstruction(inst)
        else:
            return Format3Instruction(inst)

    else:
        raise ValueError("unknown instruction format")
