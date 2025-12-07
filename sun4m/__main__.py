import argparse
import atexit
import cProfile
import os
import sys
import termios

from .machine import Machine

# Save original terminal attributes for restoration on exit
_original_termios: list | None = None


def _save_terminal_state() -> None:
    """Save the current terminal state if stdin is a tty."""
    global _original_termios
    if os.isatty(0):
        try:
            _original_termios = termios.tcgetattr(0)
        except termios.error:
            pass


def _restore_terminal_state() -> None:
    """Restore the original terminal state if it was saved."""
    if _original_termios is not None:
        try:
            termios.tcsetattr(0, termios.TCSANOW, _original_termios)
        except termios.error:
            pass

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
parser.add_argument(
    "--profile",
    type=str,
    nargs="?",
    const="profile.stats",
    default=None,
    metavar="FILE",
    help="enable cProfile and write stats to FILE (default: profile.stats)",
)
parser.add_argument("file", help="ELF binary to execute")
parser.add_argument(
    "program_args",
    nargs=argparse.REMAINDER,
    help="arguments passed to the emulated program",
)
args = parser.parse_args()


def main() -> None:
    # Save terminal state before running guest program
    _save_terminal_state()
    atexit.register(_restore_terminal_state)

    machine: Machine = Machine(
        trace=args.trace, sysroot=args.sysroot, passthrough=args.passthrough
    )
    argv = [args.file] + args.program_args
    machine.load_file(args.file, argv=argv)
    # Run until program exits or step limit reached
    exit_code = machine.cpu.run(max_steps=args.steps)
    sys.exit(exit_code)


if __name__ == "__main__":
    if args.profile:
        profiler = cProfile.Profile()
        profiler.enable()
        try:
            main()
        except KeyboardInterrupt:
            pass
        finally:
            profiler.disable()
            profiler.dump_stats(args.profile)
            print(f"\nProfile stats written to {args.profile}", file=sys.stderr)
    else:
        main()
