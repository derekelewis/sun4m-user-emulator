# Repository Guidelines

## Project Structure & Module Organization
- `sun4m/`: emulator core. `cpu.py` holds CPU state/register windows and stepping helpers; `decoder.py` routes opcodes to instruction subclasses in `instruction.py`; `memory.py` provides `SystemMemory`; `machine.py` handles binary loading; `syscall.py` contains trap handlers.
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
- Use `black` for code formatting.
- Follow PEP 8 with 4-space indents and keep type hints (existing modules annotate extensively).
- Classes use CamelCase (`Machine`, `SystemMemory`); constants uppercase; register/opcode fields follow SPARC naming (`rs1`, `rs2`, `rd`).
- Keep instruction implementations small and push state changes through existing memory/register helpers.
- Target Python 3.14; prefer modern typing syntax (PEP 604/PEP 695, `list[int]`, `|` unions, `typing.Self`, `type`/`TypedDict`/`Protocol`) and avoid deprecated aliases like `typing.Optional[T]` when `T | None` is available.
- Run `mypy sun4m tests` before PRs; keep the tree type-clean. `mypy` is installed as a system binary.

## Testing Guidelines
- Use `unittest` as the testing framework.
- Add `unittest.TestCase` suites under `tests/test_*.py` that mirror the component name.
- Prefer behavior-driven test names (`test_memory_write_cross_segment`) and cover error paths (invalid addresses, window underflow).
- When adding instructions, include both decode and execute assertions using `Machine()` and the relevant `Instruction` subclass.

## Commit & Pull Request Guidelines
- Use short, imperative commit messages (history examples: “implement LD instruction”, “fix typo”).
- For PRs, include: brief summary of behavior change, tests run (`python -m unittest`, `make -C bin all` if touched), and any TODO follow-ups. Link issues when applicable; screenshots are unnecessary unless documenting CLI output.
- Keep changes focused; split emulator core updates from sample binary or docs edits.

## Dynamic Library Support
- The emulator supports dynamically linked SPARC binaries using uClibc's dynamic linker (`ld-uClibc.so.0`).
- Use `--sysroot` to specify the path to a buildroot `output/target` directory containing uClibc libraries:
  ```bash
  python -m sun4m --sysroot ~/work/repos/third-party/buildroot/output/target ./bin/gzip_dynamic --help
  ```
- `bin/gzip_dynamic` is a dynamically linked SPARC binary built against uClibc.
- Dependencies: `libc.so.0` and `/lib/ld-uClibc.so.0` (the uClibc dynamic linker).
- Use QEMU as a reference implementation for comparing behavior:
  ```bash
  QEMU_LD_PREFIX=~/work/repos/third-party/buildroot/output/target qemu-sparc ./bin/gzip_dynamic --help
  ```

## Host Filesystem Passthrough
- Use `--passthrough` to access host filesystem paths directly, bypassing sysroot translation.
- This is useful when you want the emulated program to read/write files on the host system.
- Can be specified multiple times for different path prefixes:
  ```bash
  python -m sun4m --sysroot ~/work/repos/third-party/buildroot/output/target \
    --passthrough /home --passthrough /tmp \
    ~/work/repos/third-party/buildroot/output/target/bin/tar cvf /tmp/out.tar /home/user/files
  ```
- Path matching is prefix-based: `--passthrough /tmp` allows access to `/tmp`, `/tmp/foo`, `/tmp/foo/bar`, etc.
- Paths not matching any passthrough prefix are translated through the sysroot as usual.

## Busybox Support
- Busybox utilities (tar, gzip, etc.) from buildroot work with the emulator.
- Directory traversal is supported via `getdents64` syscall for recursive operations.
- Example running tar:
  ```bash
  # Show help
  python -m sun4m --sysroot ~/work/repos/third-party/buildroot/output/target \
    ~/work/repos/third-party/buildroot/output/target/bin/tar --help

  # Create archive from host directory
  python -m sun4m --sysroot ~/work/repos/third-party/buildroot/output/target \
    --passthrough /home --passthrough /tmp \
    ~/work/repos/third-party/buildroot/output/target/bin/tar cvf /tmp/out.tar /home/user/files

  # Extract archive to host directory
  python -m sun4m --sysroot ~/work/repos/third-party/buildroot/output/target \
    --passthrough /tmp \
    ~/work/repos/third-party/buildroot/output/target/bin/tar xvf /tmp/out.tar -C /tmp/output
  ```

## Architecture Overview
- `Machine` owns `SystemMemory` segments and a `cpu` (`CpuState`) that shares that memory; run code with `machine.cpu.step()`/`run()`.
- `CpuState` includes `halted` and `exit_code` attributes for clean termination; `run()` returns the exit code when the program terminates.
- `register.py` models register windows; `syscall.py` implements trap-based syscalls (write, exit).
- Register window overlap: Each `Window` stores only `i` (ins) and `l` (locals)—there is no separate outs array. The SPARC overlap (caller's outs = callee's ins) is achieved by resolving outs at CWP via `windows[cwp - 1].i`. When SAVE decrements CWP, the same physical storage that was "outs" becomes "ins" in the new window. This is correct per SPARC V8 Figure 4-1.
- New instructions usually require decoder wiring plus an `execute` method that reads/writes through `CpuState` and `SystemMemory`.
- SPARC CALL semantics: store the call-site PC (not PC+4) into `%o7`; `retl` adds 8 to resume after the delay slot.
- `elf.py` provides a loader for 32-bit big-endian SPARC ELFs supporting both static and dynamic executables. It maps PT_LOAD segments, parses PT_INTERP for the dynamic linker path, processes R_SPARC_RELATIVE relocations for PIE/shared objects, and returns `ElfInfo` with entry point, program header addresses, and interpreter path.
- For dynamic executables, `machine.py` loads the interpreter at a separate base address (0x40000000), sets up the auxiliary vector (auxv) with AT_PHDR, AT_ENTRY, AT_RANDOM, etc., and transfers control to the dynamic linker.
