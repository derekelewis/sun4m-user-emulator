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
# Run the emulator with a static binary
python -m sun4m ./bin/gzip --help

# Run a dynamically linked binary (requires sysroot with uClibc)
python -m sun4m --sysroot /path/to/buildroot/output/target ./bin/gzip_dynamic --help

# Run busybox utilities (tar, vi, etc.)
python -m sun4m --sysroot /path/to/buildroot/output/target \
  /path/to/buildroot/output/target/bin/tar --help

# Run interactive vi editor
python -m sun4m --sysroot /path/to/buildroot/output/target \
  --passthrough /tmp \
  /path/to/buildroot/output/target/bin/vi /tmp/myfile.txt

# Access host filesystem paths directly with --passthrough
# (bypasses sysroot translation for specified paths)
python -m sun4m --sysroot /path/to/buildroot/output/target \
  --passthrough /home --passthrough /tmp \
  /path/to/buildroot/output/target/bin/tar cvf /tmp/archive.tar /home/user/files

# Run tests
python -m unittest

# Rebuild sample SPARC binary
make -C bin clean all
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--sysroot PATH` | Path prefix for guest filesystem (e.g., buildroot output/target) |
| `--passthrough PATH` | Host path to access directly, bypassing sysroot (repeatable) |
| `--steps N` | Maximum number of instructions to execute (optional; runs until program exits if omitted) |
| `--trace` | Enable instruction tracing |
| `--profile [FILE]` | Enable cProfile and write stats to FILE (default: profile.stats) |

## Architecture

- `Machine` owns `SystemMemory` segments and a `CpuState`; execute with `machine.cpu.step()` or `run()`
- Register windows follow SPARC V8 semantics—each window stores ins and locals; outs resolve via CWP overlap
- ELF loader supports both static and dynamically linked executables, including PT_INTERP parsing and R_SPARC_RELATIVE relocations
- Dynamic linking works by loading the uClibc interpreter and setting up the auxiliary vector (auxv)
- Syscalls include file I/O (open, read, write, close, lseek, stat, lstat, access, poll, mkdir, getdents64), memory mapping (mmap2, munmap, mprotect), process info (getpid, getuid, umask, etc.), and terminal ioctls (termios, window size)

## License

Personal/educational project.
