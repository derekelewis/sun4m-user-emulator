import unittest
from sun4m.machine import Machine


class TestMemory(unittest.TestCase):

    test_bytes: bytes = "hello, world".encode()

    def test_memory_segment_for_addr_found(self):
        machine: Machine = Machine()
        s1 = machine.memory.add_segment(0x100, 0x100)
        s2 = machine.memory.add_segment(0x200, 0x100)
        self.assertNotEqual(machine.memory.segment_for_addr(0x111), None)
        self.assertNotEqual(machine.memory.segment_for_addr(0x111), s2)

    def test_memory_segment_for_addr_not_found(self):
        machine: Machine = Machine()
        _ = machine.memory.add_segment(0x100, 0x100)
        self.assertEqual(machine.memory.segment_for_addr(0x200), None)

    def test_memory_add_segment_duplicate(self):
        machine: Machine = Machine()
        s1 = machine.memory.add_segment(0x100, 0x100)
        self.assertEqual(machine.memory.add_segment(0x100, 0x100), None)

    def test_memory_write_read(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.write(0x100, self.test_bytes)
        self.assertEqual(
            machine.memory.read(0x100, len(self.test_bytes)),
            self.test_bytes,
        )

    def test_memory_read_cross_segment(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.add_segment(0x200, 0x100)
        with self.assertRaises(MemoryError) as e:
            _ = machine.memory.read(0x200 - 0x1, 0x10)

    def test_memory_read_invalid_address(self):
        machine: Machine = Machine()
        with self.assertRaises(MemoryError) as e:
            machine.memory.read(0x100, 0x10)

    def test_memory_write_cross_segment(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.add_segment(0x200, 0x100)
        with self.assertRaises(MemoryError) as e:
            machine.memory.write(0x200 - 0x1, self.test_bytes)

    def test_memory_write_invalid_address(self):
        machine: Machine = Machine()
        with self.assertRaises(MemoryError) as e:
            machine.memory.write(0x100, self.test_bytes)

    def test_memory_write_and_read_last_bytes(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.write(0x200 - len(self.test_bytes), self.test_bytes)
        bytes_read = machine.memory.read(
            0x200 - len(self.test_bytes), len(self.test_bytes)
        )
        self.assertEqual(self.test_bytes, bytes_read)


if __name__ == "__main__":
    unittest.main()
