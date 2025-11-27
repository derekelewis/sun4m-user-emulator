from .machine import Machine


def main() -> None:
    machine: Machine = Machine(1024 * 1024)  # 1MB of memory
    machine.memory.add_segment(0x1000, 0x1000)
    machine.load_file("./bin/hello_world")


if __name__ == "__main__":
    main()
