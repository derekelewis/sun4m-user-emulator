from sun4m.cpu import CpuState
from sun4m.instruction import Format3Instruction

cpu_state = CpuState()
x_inst = Format3Instruction(0x9DE3BFA0)
x_inst.execute(cpu_state)
