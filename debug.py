from sun4m.cpu import CpuState
from sun4m.instruction import Format3Instruction
from sun4m.decoder import decode

cpu_state = CpuState()
x_inst = decode(0x91D02010)
cpu_state.registers.write_register(1, 4)
cpu_state.registers.write_register(8, 1)
cpu_state.registers.write_register(9, 0x100)
cpu_state.registers.write_register(10, 12)
cpu_state.memory.add_segment(0x100, 0x100)
cpu_state.memory.write(0x100, "hello, world".encode())
x_inst.execute(cpu_state)
