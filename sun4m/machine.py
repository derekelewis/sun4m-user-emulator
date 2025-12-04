from .memory import SystemMemory
from .elf import load_elf


class Machine:

    def __init__(self):
        self.memory: SystemMemory = SystemMemory()
        self.entrypoint: int | None = None

    def load_file(self, file: str) -> int:
        with open(file, "rb") as f:
            elf_bytes = f.read()
            self.entrypoint = load_elf(self.memory, elf_bytes)
            return self.entrypoint
