# Repository Guidelines

## Project Structure & Module Organization
- `sun4m/`: emulator core. `cpu.py` holds CPU state and register windows; `decoder.py` routes opcodes to instruction subclasses in `instruction.py`; `memory.py` provides `SystemMemory`; `machine.py` handles binary loading; `syscall.py` contains trap handlers.
- `bin/`: sample SPARC program (`hello_world`, `start.S`, `hello_world.c`) and `Makefile` to rebuild it.
- `tests/`: unit suites per component (`test_memory.py`, `test_register.py`, `test_decoder.py`, `test_instruction.py`).
- `debug.py`: small harness showing decode/execute against a preloaded memory segment.
- `TODO.md`: backlog of emulator work items.

## Build, Test, and Development Commands
- `python -m sun4m` — loads `bin/hello_world` into a `Machine` and exercises the loader; ensure `bin/hello_world` exists (rebuild with `make -C bin all` if you edit the sample or toolchain).
- `python -m unittest` — run the full suite; narrow with `python -m unittest tests.test_memory`.
- `make -C bin clean all` — rebuilds the SPARC sample; requires `sparc-linux-gcc -m32 -mcpu=v8` on your `PATH` or adjust the compiler path inside `bin/Makefile`.
- On macOS, use Homebrew binutils (`$(brew prefix binutils)/bin/objdump`, `readelf`, `addr2line`, etc.) so the GNU versions are picked up instead of the system BSD variants.

## Coding Style & Naming Conventions
- Follow PEP 8 with 4-space indents and keep type hints (existing modules annotate extensively).
- Classes use CamelCase (`Machine`, `SystemMemory`); constants uppercase; register/opcode fields follow SPARC naming (`rs1`, `rs2`, `rd`).
- Keep instruction implementations small and push state changes through existing memory/register helpers.
- Target Python 3.14; prefer modern typing syntax (PEP 604/PEP 695, `list[int]`, `|` unions, `typing.Self`, `type`/`TypedDict`/`Protocol`) and avoid deprecated aliases like `typing.Optional[T]` when `T | None` is available.
- Run `mypy sun4m tests` before PRs; keep the tree type-clean.

## Testing Guidelines
- Add `unittest.TestCase` suites under `tests/test_*.py` that mirror the component name.
- Prefer behavior-driven test names (`test_memory_write_cross_segment`) and cover error paths (invalid addresses, window underflow).
- When adding instructions, include both decode and execute assertions using `Machine()` and the relevant `Instruction` subclass.

## Commit & Pull Request Guidelines
- Use short, imperative commit messages (history examples: “implement LD instruction”, “fix typo”).
- For PRs, include: brief summary of behavior change, tests run (`python -m unittest`, `make -C bin all` if touched), and any TODO follow-ups. Link issues when applicable; screenshots are unnecessary unless documenting CLI output.
- Keep changes focused; split emulator core updates from sample binary or docs edits.

## Architecture Overview
- `Machine` owns `SystemMemory` segments and feeds instructions decoded via `decoder.decode` into classes from `instruction.py`.
- `register.py` models register windows; `syscall.py` implements trap-based syscalls (write, exit).
- New instructions usually require decoder wiring plus an `execute` method that reads/writes through `CpuState` and `SystemMemory`.
