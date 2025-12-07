from .machine import Machine
import argparse

parser = argparse.ArgumentParser(description="SPARC V8 user-mode emulator")
parser.add_argument(
    "file",
    nargs="?",
    default="./bin/hello_world",
    help="ELF binary to execute (default: ./bin/hello_world)",
)
parser.add_argument(
    "--steps", type=int, default=10000, help="number of cycles/steps to execute"
)
parser.add_argument("--trace", action="store_true", help="enable tracing")
args = parser.parse_args()


def main() -> None:
    machine: Machine = Machine(trace=args.trace)
    machine.load_file(args.file)
    # Run a bounded number of steps; the sample exits via syscall.
    machine.cpu.run(max_steps=args.steps)


if __name__ == "__main__":
    main()
