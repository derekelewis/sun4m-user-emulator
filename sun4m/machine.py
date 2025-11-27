from .memory import SystemMemory


class Machine:

    def __init__(self):
        self.memory: SystemMemory = SystemMemory()

    def load_file(self, file: str) -> None:
        with open(file, "rb") as f:
            elf_bytes = f.read()
            s1 = self.memory.add_segment(0x10000, 0x1000)
            offset = 0
            if s1:
                s1.buffer[offset : offset + len(elf_bytes)] = elf_bytes
            else:
                raise MemoryError("segment allocation failure")
