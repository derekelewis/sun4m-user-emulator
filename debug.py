from sun4m.cpu import CpuState
from sun4m.instruction import Format3Instruction

cpu_state = CpuState()
cpu_state.memory.add_segment(0, 0x100)
cpu_state.registers.write_register(24, int.from_bytes("TEST".encode(), "big"))
x_inst = Format3Instruction(0xF027A044)
print(x_inst)
x_inst.execute(cpu_state)
print(cpu_state.memory.read(0x44, 4))
