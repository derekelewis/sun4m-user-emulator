# sun4m-user-emulator

A personal project to build and optimize a SPARCv8 userland emulator, similar to `qemu-sparc`, for educational purposes. Currently implemented in Python with plans to explore other languages.

## Project Structure

```
sun4m/      Emulator core
  cpu.py        CPU state and register windows
  decoder.py    Opcode routing to instruction handlers
  instruction.py  Instruction implementations
  memory.py     SystemMemory abstraction
  machine.py    Binary loading and machine setup
  syscall.py    Trap-based syscall handlers
  elf.py        Minimal 32-bit big-endian SPARC ELF loader

bin/        Sample SPARC programs (hello_world) and Makefile
tests/      Unit test suites
```

## Requirements

- Python 3.12+ (3.11 may also work, but Python development target is Python 3.14)
- SPARC cross-compiler (`sparc-linux-gcc -m32 -mcpu=v8`) to rebuild sample binaries
- On macOS: Homebrew binutils for GNU `objdump`, `readelf`, etc.

## Usage

```bash
# Run the emulator with the sample binary
python -m sun4m

# Run tests
python -m unittest

# Rebuild sample SPARC binary
make -C bin clean all
```

## Architecture

- `Machine` owns `SystemMemory` segments and a `CpuState`; execute with `machine.cpu.step()` or `run()`
- Register windows follow SPARC V8 semantics—each window stores ins and locals; outs resolve via CWP overlap
- ELF loader maps PT_LOAD segments to memory at their virtual addresses
- Syscalls (write, exit) are handled via trap instructions

## License

Personal/educational project.
