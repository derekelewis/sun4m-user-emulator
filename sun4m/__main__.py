from .machine import Machine


def main() -> None:
    machine: Machine = Machine()
    machine.load_file("./bin/hello_world")


if __name__ == "__main__":
    main()
