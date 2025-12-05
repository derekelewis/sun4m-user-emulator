"""Minimal ELF loader for 32-bit big-endian SPARC binaries.

The loader only handles the pieces we need for the sample programs in
``bin/``: 32-bit, big-endian (ELFDATA2MSB) executables with PT_LOAD
program headers. Section headers are ignored. Program segments are copied
directly into ``SystemMemory`` using their virtual addresses, and BSS space
is zero-initialised by virtue of the freshly allocated buffers.
"""

import struct
from typing import Iterable, Tuple

from .memory import MemorySegment, SystemMemory


ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2MSB = 2
ELF_VERSION_CURRENT = 1
EM_SPARC = 2

PT_LOAD = 1


ProgramHeader = Tuple[int, int, int, int, int, int, int, int]


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


def load_elf(memory: SystemMemory, elf_bytes: bytes) -> int:
    """Load an ELF image into ``memory`` and return its entry point.

    Only PT_LOAD segments are honoured. Each segment is mapped to its
    virtual address with a buffer sized to ``p_memsz``. The file-backed
    portion (``p_filesz``) is copied verbatim; the remainder stays zeroed.
    """

    entry, phoff, phentsize, phnum, _, _ = _parse_elf_header(elf_bytes)

    for (
        p_type,
        p_offset,
        p_vaddr,
        p_addr, # physical address that we ignore today
        p_filesz,
        p_memsz,
        p_flags, # per-segment permissions - ignored today
        p_align, # used for alignment - ignored today
    ) in _iter_program_headers(elf_bytes, phoff, phentsize, phnum):
        if p_type != PT_LOAD:
            continue
        if p_memsz == 0:
            continue

        _require(p_filesz <= p_memsz, "p_filesz larger than p_memsz")
        _require(p_offset + p_filesz <= len(elf_bytes), "segment exceeds file size")

        segment: MemorySegment | None = memory.add_segment(p_vaddr, p_memsz)
        if segment is None:
            raise MemoryError("segment overlap while loading ELF")

        file_slice = elf_bytes[p_offset : p_offset + p_filesz]
        segment.buffer[: len(file_slice)] = file_slice
        # Remaining space already zero-initialised.

    return entry
