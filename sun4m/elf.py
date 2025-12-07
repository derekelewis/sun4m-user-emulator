"""Minimal ELF loader for 32-bit big-endian SPARC binaries.

The loader only handles the pieces we need for the sample programs in
``bin/``: 32-bit, big-endian (ELFDATA2MSB) executables with PT_LOAD
program headers. Section headers are ignored. Program segments are copied
directly into ``SystemMemory`` using their virtual addresses, and BSS space
is zero-initialised by virtue of the freshly allocated buffers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Tuple

from .memory import MemorySegment, SystemMemory


ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2MSB = 2
ELF_VERSION_CURRENT = 1
EM_SPARC = 2

# ELF types
ET_EXEC = 2  # Executable file
ET_DYN = 3  # Shared object file

# Program header types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6

# Program header size for 32-bit ELF
PHDR_SIZE = 32


ProgramHeader = Tuple[int, int, int, int, int, int, int, int]


@dataclass
class ElfInfo:
    """Information extracted from an ELF file after loading."""

    entry_point: int  # Entry point address (adjusted for base)
    phdr_addr: int  # Address where program headers are loaded
    phdr_count: int  # Number of program headers
    phdr_size: int  # Size of each program header entry
    interpreter_path: str | None  # Path to dynamic linker (from PT_INTERP)
    base_address: int  # Base address where ELF was loaded
    elf_type: int  # ET_EXEC or ET_DYN
    program_headers: bytes  # Raw program header bytes for auxv


class ElfFormatError(ValueError):
    """Raised when an ELF file is malformed or unsupported."""


def _require(condition: bool, message: str) -> None:
    """Raise ``ElfFormatError`` when *condition* is false."""

    if not condition:
        raise ElfFormatError(message)


def _parse_elf_header(elf_bytes: bytes) -> tuple[int, int, int, int, int, int]:
    """Return entry point, program header offset, entry size, and count.

    Raises ``ElfFormatError`` when the binary is not a 32-bit, big-endian
    SPARC executable.
    """

    _require(len(elf_bytes) >= 52, "ELF header too small")
    ident = elf_bytes[:16]
    _require(ident[:4] == ELF_MAGIC, "not an ELF file")
    _require(ident[4] == ELFCLASS32, "unsupported ELF class (need 32-bit)")
    _require(ident[5] == ELFDATA2MSB, "unsupported endianness (need MSB)")
    _require(ident[6] == ELF_VERSION_CURRENT, "unknown ELF version")

    # 32-bit big-endian ELF header
    header_struct = struct.Struct(">HHIIIIIHHHHHH")
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = header_struct.unpack_from(elf_bytes, 16)

    _require(e_machine == EM_SPARC, "unsupported machine (need EM_SPARC)")
    _require(e_version == ELF_VERSION_CURRENT, "unexpected ELF version")
    _require(e_phoff != 0 and e_phnum > 0, "ELF has no program headers")
    _require(e_phentsize >= 32, "program header size too small")
    _require(e_phoff + e_phentsize * e_phnum <= len(elf_bytes), "truncated program headers")

    return e_entry, e_phoff, e_phentsize, e_phnum, e_flags, e_type


def _iter_program_headers(
    elf_bytes: bytes, phoff: int, phentsize: int, phnum: int
) -> Iterable[ProgramHeader]:
    """Yield parsed program headers as tuples."""

    ph_struct = struct.Struct(">IIIIIIII")
    for idx in range(phnum):
        offset = phoff + idx * phentsize
        try:
            yield ph_struct.unpack_from(elf_bytes, offset)
        except struct.error as exc:  # pragma: no cover - guarded above
            raise ElfFormatError("truncated program header") from exc


def load_elf(memory: SystemMemory, elf_bytes: bytes, base_addr: int = 0) -> int:
    """Load an ELF image into ``memory`` and return its entry point.

    Only PT_LOAD segments are honoured. Each segment is mapped to its
    virtual address with a buffer sized to ``p_memsz``. The file-backed
    portion (``p_filesz``) is copied verbatim; the remainder stays zeroed.

    This is a backward-compatible wrapper around load_elf_info.
    """
    info = load_elf_info(memory, elf_bytes, base_addr)
    return info.entry_point


def load_elf_info(
    memory: SystemMemory, elf_bytes: bytes, base_addr: int = 0
) -> ElfInfo:
    """Load an ELF image into ``memory`` and return detailed ElfInfo.

    Args:
        memory: The SystemMemory to load segments into
        elf_bytes: The raw ELF file contents
        base_addr: Base address to add to all virtual addresses (for PIE/shared libs)

    Returns:
        ElfInfo with entry point, program header info, interpreter path, etc.
    """
    entry, phoff, phentsize, phnum, _, e_type = _parse_elf_header(elf_bytes)

    # Extract raw program headers for auxv
    program_headers = elf_bytes[phoff : phoff + phentsize * phnum]

    # Parse program headers to find interpreter and load segments
    interpreter_path: str | None = None
    phdr_vaddr: int = 0  # Address of PT_PHDR or first PT_LOAD containing headers

    # First pass: find PT_INTERP and PT_PHDR
    for (
        p_type,
        p_offset,
        p_vaddr,
        p_addr,
        p_filesz,
        p_memsz,
        p_flags,
        p_align,
    ) in _iter_program_headers(elf_bytes, phoff, phentsize, phnum):
        if p_type == PT_INTERP:
            # Extract interpreter path (null-terminated string)
            interp_bytes = elf_bytes[p_offset : p_offset + p_filesz]
            interpreter_path = interp_bytes.rstrip(b"\x00").decode("utf-8")
        elif p_type == PT_PHDR:
            phdr_vaddr = p_vaddr

    # Second pass: load PT_LOAD segments
    first_load_vaddr: int | None = None
    for (
        p_type,
        p_offset,
        p_vaddr,
        p_addr,
        p_filesz,
        p_memsz,
        p_flags,
        p_align,
    ) in _iter_program_headers(elf_bytes, phoff, phentsize, phnum):
        if p_type != PT_LOAD:
            continue
        if p_memsz == 0:
            continue

        _require(p_filesz <= p_memsz, "p_filesz larger than p_memsz")
        _require(p_offset + p_filesz <= len(elf_bytes), "segment exceeds file size")

        # Track first loadable segment (used for phdr_addr if no PT_PHDR)
        if first_load_vaddr is None:
            first_load_vaddr = p_vaddr

        # Apply base address offset
        load_addr = base_addr + p_vaddr

        segment: MemorySegment | None = memory.add_segment(load_addr, p_memsz)
        if segment is None:
            raise MemoryError(f"segment overlap while loading ELF at {load_addr:#x}")

        file_slice = elf_bytes[p_offset : p_offset + p_filesz]
        segment.buffer[: len(file_slice)] = file_slice
        # Remaining space already zero-initialised.

    # Calculate phdr_addr: use PT_PHDR vaddr, or fall back to calculating it
    if phdr_vaddr:
        phdr_addr = base_addr + phdr_vaddr
    elif first_load_vaddr is not None:
        # Program headers are typically at the start of the first loadable segment
        # Offset into the segment = phoff - (first segment's file offset)
        # For simplicity, assume headers are at base_addr + phoff (common case)
        phdr_addr = base_addr + phoff
    else:
        phdr_addr = 0

    return ElfInfo(
        entry_point=base_addr + entry,
        phdr_addr=phdr_addr,
        phdr_count=phnum,
        phdr_size=phentsize,
        interpreter_path=interpreter_path,
        base_address=base_addr,
        elf_type=e_type,
        program_headers=program_headers,
    )
