from sun4m.cpu import CpuState
from sun4m.instruction import Format3Instruction
from sun4m.decoder import decode

cpu_state = CpuState()
x_inst = decode(0x91D02010)
print(x_inst)
x_inst.execute(cpu_state)
breakpoint()
