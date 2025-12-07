import argparse
import sys

from .machine import Machine

parser = argparse.ArgumentParser(description="SPARC V8 user-mode emulator")
parser.add_argument(
    "--steps", type=int, default=None, help="maximum number of cycles/steps to execute"
)
parser.add_argument("--trace", action="store_true", help="enable tracing")
parser.add_argument(
    "--sysroot",
    type=str,
    default="",
    help="path prefix for guest filesystem (e.g., buildroot output/target)",
)
parser.add_argument(
    "--passthrough",
    type=str,
    action="append",
    default=[],
    metavar="PATH",
    help="host path to access directly, bypassing sysroot (can be used multiple times)",
)
parser.add_argument("file", help="ELF binary to execute")
parser.add_argument(
    "program_args",
    nargs=argparse.REMAINDER,
    help="arguments passed to the emulated program",
)
args = parser.parse_args()


def main() -> None:
    machine: Machine = Machine(
        trace=args.trace, sysroot=args.sysroot, passthrough=args.passthrough
    )
    argv = [args.file] + args.program_args
    machine.load_file(args.file, argv=argv)
    # Run until program exits or step limit reached
    exit_code = machine.cpu.run(max_steps=args.steps)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
