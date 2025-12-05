from .machine import Machine
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--trace", action='store_true', help="enable tracing")
args = parser.parse_args()


def main() -> None:
    machine: Machine = Machine(trace=args.trace)
    machine.load_file("./bin/hello_world")
    # Run a bounded number of steps; the sample exits via syscall.
    machine.cpu.run(max_steps=10_000)


if __name__ == "__main__":
    main()
