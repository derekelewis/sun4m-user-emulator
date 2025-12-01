from .instruction import (
    Instruction,
    CallInstruction,
    Format2Instruction,
    Format3Instruction,
)


def decode(inst: int) -> Instruction:
    op = (inst >> 30) & 0b11
    if op == 1:
        return CallInstruction(inst)
    elif op == 0:
        return Format2Instruction(inst)
    elif op in (2, 3):
        return Format3Instruction(inst)
    else:
        raise ValueError("unknown op")
