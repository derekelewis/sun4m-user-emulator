from enum import StrEnum


class Instruction:

    def __init__(self, inst: int):
        self.inst = int


class CallInstruction:

    def __init__(self, inst: int):
        super()

    def decode(): ...


class Format2Instruction:

    def __init__(self, inst: int):
        super()

    def decode(): ...


class Format3Instruction:

    def __init__(self, inst: int):
        super()

    def decode(): ...


class InstructionClass(StrEnum):
    branch: str = "BRANCH"
    call: str = "CALL"
    arithmetic: str = "ARITHMETIC"
    load_store: str = "LOAD_STORE"
    trap: str = "TRAP"
    unknown: str = "UNKNOWN"


class DecodedInstruction: ...
