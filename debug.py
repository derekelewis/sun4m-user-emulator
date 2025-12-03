from sun4m.cpu import CpuState
from sun4m.instruction import Format2Instruction

cpu_state = CpuState()
x_inst = Format2Instruction(0x01000000)
print(x_inst)
x_inst.execute(cpu_state)
