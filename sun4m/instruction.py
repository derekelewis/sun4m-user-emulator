from enum import StrEnum


class Instruction:

    def __init__(self, inst: int):
        self.inst = int


class CallInstruction(Instruction):

    def __init__(self, inst: int):
        super()

    def decode(self): ...


class Format2Instruction(Instruction):

    def __init__(self, inst: int):
        super()

    def decode(self): ...


class Format3Instruction(Instruction):

    def __init__(self, inst: int):
        super()

    def decode(self): ...


class InstructionClass(StrEnum):
    branch = "BRANCH"
    call = "CALL"
    arithmetic = "ARITHMETIC"
    load_store = "LOAD_STORE"
    trap = "TRAP"
    unknown = "UNKNOWN"


class DecodedInstruction: ...
