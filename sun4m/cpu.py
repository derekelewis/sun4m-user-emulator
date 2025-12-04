from sun4m.register import RegisterFile
from sun4m.memory import SystemMemory


class CpuState:

    def __init__(self):
        self.pc: int = 0
        self.npc: int = 0
        self.psr: int = 0
        self.registers: RegisterFile = RegisterFile()
        self.memory: SystemMemory = SystemMemory()
