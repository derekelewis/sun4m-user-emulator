from .memory import SystemMemory


class Machine:
    memory: SystemMemory

    def __init__(self):
        self.memory = SystemMemory()

    def load_file(self, file: str) -> None:
        with open(file, "rb") as f:
            elf_bytes = f.read()
            self.memory._segments[0x1000].buffer[: len(elf_bytes)] = elf_bytes
            print(self.memory._segments[0x1000].buffer)
