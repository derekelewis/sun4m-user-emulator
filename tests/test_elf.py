import struct
import unittest
from pathlib import Path

from sun4m.elf import (
    ElfFormatError,
    ElfInfo,
    load_elf,
    load_elf_info,
    ET_EXEC,
    ET_DYN,
    PT_LOAD,
    PT_INTERP,
    PT_DYNAMIC,
    PT_PHDR,
    PHDR_SIZE,
    R_SPARC_RELATIVE,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_NULL,
)
from sun4m.memory import SystemMemory


class TestElfLoader(unittest.TestCase):

    def test_loads_sample_binary(self):
        memory = SystemMemory()
        elf_bytes = Path("bin/hello_world").read_bytes()

        entry = load_elf(memory, elf_bytes)

        self.assertEqual(entry, 0x10074)
        segment = memory.segment_for_addr(0x10000)
        self.assertIsNotNone(segment)
        if segment:
            self.assertEqual(len(segment.buffer), 0xFF)
            self.assertEqual(segment.buffer[:0xFF], elf_bytes[:0xFF])

    def test_bss_zero_filled(self):
        # Build a tiny ELF with filesz < memsz so the tail should be zeroed.
        ident = b"\x7fELF" + bytes([1, 2, 1]) + b"\x00" * 9  # class, data, version, padding

        e_entry = 0x2000
        e_phoff = 52
        e_phentsize = 32
        e_phnum = 1

        elf_header = struct.pack(
            ">HHIIIIIHHHHHH",
            2,  # ET_EXEC
            2,  # EM_SPARC
            1,  # EV_CURRENT
            e_entry,
            e_phoff,
            0,
            0,
            52,
            e_phentsize,
            e_phnum,
            0,
            0,
            0,
        )

        p_offset = 0x80
        p_vaddr = 0x2000
        data_bytes = b"\xDE\xAD\xBE\xEF"
        p_filesz = len(data_bytes)
        p_memsz = 8

        program_header = struct.pack(
            ">IIIIIIII",
            1,  # PT_LOAD
            p_offset,
            p_vaddr,
            p_vaddr,
            p_filesz,
            p_memsz,
            5,  # PF_R | PF_X
            4,
        )

        padding = b"\x00" * (p_offset - (e_phoff + e_phentsize))
        elf_bytes = ident + elf_header + program_header + padding + data_bytes

        memory = SystemMemory()
        entry = load_elf(memory, elf_bytes)

        segment = memory.segment_for_addr(p_vaddr)
        self.assertIsNotNone(segment)
        self.assertEqual(entry, e_entry)
        if segment:
            self.assertEqual(len(segment.buffer), p_memsz)
            self.assertEqual(segment.buffer[:p_filesz], data_bytes)
            self.assertEqual(segment.buffer[p_filesz:], b"\x00" * (p_memsz - p_filesz))

    def test_invalid_magic_raises(self):
        with self.assertRaises(ElfFormatError):
            load_elf(SystemMemory(), b"not an elf")


def build_minimal_elf(
    e_type: int = ET_EXEC,
    e_entry: int = 0x2000,
    segments: list[dict] | None = None,
    data: bytes = b"\xDE\xAD\xBE\xEF",
) -> bytes:
    """Build a minimal 32-bit big-endian SPARC ELF file for testing."""
    if segments is None:
        segments = [
            {
                "type": PT_LOAD,
                "vaddr": 0x2000,
                "filesz": len(data),
                "memsz": len(data),
                "data": data,
            }
        ]

    # ELF ident (16 bytes)
    ident = b"\x7fELF" + bytes([1, 2, 1]) + b"\x00" * 9

    e_phoff = 52
    e_phentsize = 32
    e_phnum = len(segments)

    # ELF header
    elf_header = struct.pack(
        ">HHIIIIIHHHHHH",
        e_type,  # e_type
        2,  # e_machine (EM_SPARC)
        1,  # e_version
        e_entry,  # e_entry
        e_phoff,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        52,  # e_ehsize
        e_phentsize,  # e_phentsize
        e_phnum,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )

    # Program headers
    program_headers = b""
    data_offset = e_phoff + e_phentsize * e_phnum
    data_sections: list[bytes] = []

    for seg in segments:
        seg_type = seg.get("type", PT_LOAD)
        seg_data = seg.get("data", b"")
        seg_vaddr = seg.get("vaddr", 0)
        seg_filesz = seg.get("filesz", len(seg_data))
        seg_memsz = seg.get("memsz", seg_filesz)
        seg_flags = seg.get("flags", 5)  # PF_R | PF_X
        seg_offset = data_offset + len(b"".join(data_sections))

        program_headers += struct.pack(
            ">IIIIIIII",
            seg_type,
            seg_offset,
            seg_vaddr,
            seg_vaddr,  # p_paddr
            seg_filesz,
            seg_memsz,
            seg_flags,
            4,  # p_align
        )
        data_sections.append(seg_data)

    return ident + elf_header + program_headers + b"".join(data_sections)


class TestElfInfo(unittest.TestCase):
    """Tests for load_elf_info and ElfInfo dataclass."""

    def test_load_elf_info_returns_elfinfo(self):
        """Test that load_elf_info returns an ElfInfo object."""
        elf_bytes = build_minimal_elf()
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertIsInstance(info, ElfInfo)
        self.assertEqual(info.entry_point, 0x2000)
        self.assertEqual(info.elf_type, ET_EXEC)
        self.assertEqual(info.base_address, 0)
        self.assertIsNone(info.interpreter_path)

    def test_load_elf_info_with_base_address(self):
        """Test loading an ELF with a base address offset (for PIE/shared libs)."""
        elf_bytes = build_minimal_elf(e_type=ET_DYN, e_entry=0x1000)
        memory = SystemMemory()
        base_addr = 0x40000000

        info = load_elf_info(memory, elf_bytes, base_addr=base_addr)

        self.assertEqual(info.entry_point, base_addr + 0x1000)
        self.assertEqual(info.base_address, base_addr)
        self.assertEqual(info.elf_type, ET_DYN)

        # Verify segment loaded at base + vaddr
        segment = memory.segment_for_addr(base_addr + 0x2000)
        self.assertIsNotNone(segment)

    def test_load_elf_info_program_headers(self):
        """Test that program headers are captured in ElfInfo."""
        elf_bytes = build_minimal_elf()
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.phdr_count, 1)
        self.assertEqual(info.phdr_size, 32)
        self.assertEqual(len(info.program_headers), 32)  # 1 phdr * 32 bytes

    def test_load_elf_info_with_sample_binary(self):
        """Test load_elf_info with actual hello_world binary."""
        memory = SystemMemory()
        elf_bytes = Path("bin/hello_world").read_bytes()

        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.entry_point, 0x10074)
        self.assertEqual(info.elf_type, ET_EXEC)
        self.assertIsNone(info.interpreter_path)  # Static binary


class TestElfInterpreter(unittest.TestCase):
    """Tests for PT_INTERP parsing."""

    def test_parses_interpreter_path(self):
        """Test that PT_INTERP is correctly parsed."""
        interp_path = b"/lib/ld-uClibc.so.0\x00"

        segments = [
            {
                "type": PT_INTERP,
                "vaddr": 0x1000,
                "filesz": len(interp_path),
                "memsz": len(interp_path),
                "data": interp_path,
            },
            {
                "type": PT_LOAD,
                "vaddr": 0x2000,
                "filesz": 4,
                "memsz": 4,
                "data": b"\xDE\xAD\xBE\xEF",
            },
        ]

        elf_bytes = build_minimal_elf(segments=segments)
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.interpreter_path, "/lib/ld-uClibc.so.0")

    def test_no_interpreter_for_static(self):
        """Test that static binaries have no interpreter path."""
        elf_bytes = build_minimal_elf()
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertIsNone(info.interpreter_path)


class TestElfPhdr(unittest.TestCase):
    """Tests for PT_PHDR and program header address calculation."""

    def test_phdr_addr_from_pt_phdr(self):
        """Test that phdr_addr is correctly set from PT_PHDR."""
        phdr_vaddr = 0x34  # Typical location

        segments = [
            {
                "type": PT_PHDR,
                "vaddr": phdr_vaddr,
                "filesz": 64,
                "memsz": 64,
                "data": b"",  # Content doesn't matter for this test
            },
            {
                "type": PT_LOAD,
                "vaddr": 0x2000,
                "filesz": 4,
                "memsz": 4,
                "data": b"\xDE\xAD\xBE\xEF",
            },
        ]

        elf_bytes = build_minimal_elf(segments=segments)
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.phdr_addr, phdr_vaddr)

    def test_phdr_addr_with_base_address(self):
        """Test that phdr_addr is correctly offset by base address."""
        phdr_vaddr = 0x34
        base_addr = 0x40000000

        segments = [
            {
                "type": PT_PHDR,
                "vaddr": phdr_vaddr,
                "filesz": 64,
                "memsz": 64,
                "data": b"",
            },
            {
                "type": PT_LOAD,
                "vaddr": 0x2000,
                "filesz": 4,
                "memsz": 4,
                "data": b"\xDE\xAD\xBE\xEF",
            },
        ]

        elf_bytes = build_minimal_elf(e_type=ET_DYN, segments=segments)
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes, base_addr=base_addr)

        self.assertEqual(info.phdr_addr, base_addr + phdr_vaddr)


class TestElfRelocations(unittest.TestCase):
    """Tests for R_SPARC_RELATIVE relocation processing."""

    def _build_elf_with_relocations(
        self, r_offset: int, r_addend: int
    ) -> bytes:
        """Build a shared object ELF with a single R_SPARC_RELATIVE relocation.

        Manually constructs an ELF with proper file offsets for PT_DYNAMIC.
        """
        # ELF ident (16 bytes)
        ident = b"\x7fELF" + bytes([1, 2, 1]) + b"\x00" * 9

        # Layout:
        # - ELF header: 52 bytes
        # - Program headers: 3 * 32 = 96 bytes (starts at offset 52)
        # - Data section: 256 bytes at vaddr 0x1000 (file offset 148)
        # - Dynamic + Rela: at vaddr 0x2000 (file offset 404)

        e_phoff = 52
        e_phentsize = 32
        e_phnum = 3

        data_vaddr = 0x1000
        data_size = 0x100
        data_file_offset = e_phoff + e_phentsize * e_phnum  # 148

        # Dynamic section (32 bytes) followed by Rela (12 bytes) = 44 bytes
        dyn_vaddr = 0x2000
        rela_vaddr = 0x2020  # After dynamic section in memory
        dyn_file_offset = data_file_offset + data_size  # 404

        # Build rela entry: r_offset, r_info, r_addend (12 bytes)
        r_info = R_SPARC_RELATIVE
        rela_entry = struct.pack(">IIi", r_offset, r_info, r_addend)

        # Build dynamic section (points to rela within same segment)
        dyn_entries = struct.pack(
            ">IIIIIIII",
            DT_RELA,
            rela_vaddr,  # Virtual address of rela
            DT_RELASZ,
            12,
            DT_RELAENT,
            12,
            DT_NULL,
            0,
        )
        dyn_and_rela = dyn_entries + rela_entry  # 44 bytes total

        # ELF header
        elf_header = struct.pack(
            ">HHIIIIIHHHHHH",
            ET_DYN,  # e_type (shared object)
            2,  # e_machine (EM_SPARC)
            1,  # e_version
            0x1000,  # e_entry
            e_phoff,
            0,  # e_shoff
            0,  # e_flags
            52,  # e_ehsize
            e_phentsize,
            e_phnum,
            0,  # e_shentsize
            0,  # e_shnum
            0,  # e_shstrndx
        )

        # Program headers
        # 1. PT_LOAD for data segment (contains relocation targets)
        phdr_data = struct.pack(
            ">IIIIIIII",
            PT_LOAD,
            data_file_offset,
            data_vaddr,
            data_vaddr,
            data_size,
            data_size,
            6,  # PF_R | PF_W
            0x1000,
        )
        # 2. PT_LOAD for dynamic+rela segment
        phdr_dyn_load = struct.pack(
            ">IIIIIIII",
            PT_LOAD,
            dyn_file_offset,
            dyn_vaddr,
            dyn_vaddr,
            len(dyn_and_rela),
            len(dyn_and_rela),
            6,  # PF_R | PF_W
            0x1000,
        )
        # 3. PT_DYNAMIC (same file offset as PT_LOAD for dynamic)
        phdr_dynamic = struct.pack(
            ">IIIIIIII",
            PT_DYNAMIC,
            dyn_file_offset,  # Points to same file location
            dyn_vaddr,
            dyn_vaddr,
            len(dyn_entries),  # Only the dynamic section, not rela
            len(dyn_entries),
            6,
            4,
        )

        program_headers = phdr_data + phdr_dyn_load + phdr_dynamic
        data_section = b"\x00" * data_size

        return ident + elf_header + program_headers + data_section + dyn_and_rela

    def test_relative_relocation_applied(self):
        """Test that R_SPARC_RELATIVE relocations are applied correctly."""
        base_addr = 0x40000000
        r_offset = 0x1010  # Target address relative to base (within data segment)
        r_addend = 0x1000  # Value to add to base

        elf_bytes = self._build_elf_with_relocations(r_offset, r_addend)

        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes, base_addr=base_addr)

        # Read the relocated value
        target_addr = base_addr + r_offset
        relocated_value = struct.unpack(">I", memory.read(target_addr, 4))[0]

        # R_SPARC_RELATIVE: word32 = B + A (base + addend)
        expected_value = base_addr + r_addend
        self.assertEqual(relocated_value, expected_value)

    def test_no_relocation_without_base_addr(self):
        """Test that relocations are only processed with non-zero base address."""
        r_offset = 0x1010
        r_addend = 0x1000

        elf_bytes = self._build_elf_with_relocations(r_offset, r_addend)

        memory = SystemMemory()
        # Load at base 0 - no relocations should be processed for ET_DYN
        # (but ET_DYN with base 0 still won't process relocations per the code)
        info = load_elf_info(memory, elf_bytes, base_addr=0)

        # Value should remain 0 (from zero-initialized data)
        target_addr = r_offset
        value = struct.unpack(">I", memory.read(target_addr, 4))[0]
        self.assertEqual(value, 0)


class TestElfTypes(unittest.TestCase):
    """Tests for different ELF types (ET_EXEC vs ET_DYN)."""

    def test_executable_type(self):
        """Test loading an ET_EXEC binary."""
        elf_bytes = build_minimal_elf(e_type=ET_EXEC)
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.elf_type, ET_EXEC)

    def test_shared_object_type(self):
        """Test loading an ET_DYN (shared object/PIE) binary."""
        elf_bytes = build_minimal_elf(e_type=ET_DYN)
        memory = SystemMemory()
        info = load_elf_info(memory, elf_bytes)

        self.assertEqual(info.elf_type, ET_DYN)


class TestElfValidation(unittest.TestCase):
    """Tests for ELF validation error cases."""

    def test_truncated_header(self):
        """Test that truncated ELF header raises error."""
        with self.assertRaises(ElfFormatError):
            load_elf_info(SystemMemory(), b"\x7fELF" + b"\x00" * 10)

    def test_wrong_class(self):
        """Test that 64-bit ELF raises error."""
        ident = b"\x7fELF" + bytes([2, 2, 1]) + b"\x00" * 9  # Class 2 = 64-bit
        with self.assertRaises(ElfFormatError):
            load_elf_info(SystemMemory(), ident + b"\x00" * 40)

    def test_wrong_endianness(self):
        """Test that little-endian ELF raises error."""
        ident = b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9  # Data 1 = little-endian
        with self.assertRaises(ElfFormatError):
            load_elf_info(SystemMemory(), ident + b"\x00" * 40)


if __name__ == "__main__":
    unittest.main()
