import argparse

from .machine import Machine

parser = argparse.ArgumentParser(description="SPARC V8 user-mode emulator")
parser.add_argument(
    "--steps", type=int, default=10000, help="number of cycles/steps to execute"
)
parser.add_argument("--trace", action="store_true", help="enable tracing")
parser.add_argument("file", help="ELF binary to execute")
parser.add_argument(
    "program_args",
    nargs=argparse.REMAINDER,
    help="arguments passed to the emulated program",
)
args = parser.parse_args()


def main() -> None:
    machine: Machine = Machine(trace=args.trace)
    argv = [args.file] + args.program_args
    machine.load_file(args.file, argv=argv)
    # Run a bounded number of steps; the sample exits via syscall.
    machine.cpu.run(max_steps=args.steps)


if __name__ == "__main__":
    main()
