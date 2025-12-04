import struct
import unittest
from pathlib import Path

from sun4m.elf import ElfFormatError, load_elf
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


if __name__ == "__main__":
    unittest.main()
