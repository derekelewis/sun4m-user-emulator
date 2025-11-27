import unittest
from sun4m.machine import Machine
from sun4m.memory import SystemMemory


class MemoryTestCase(unittest.TestCase):

    test_bytes: bytes = "hello, world".encode()

    def testMemorySegmentForAddrFound(self):
        machine: Machine = Machine()
        s1 = machine.memory.add_segment(0x100, 0x100)
        s2 = machine.memory.add_segment(0x200, 0x100)
        self.assertNotEqual(machine.memory.segment_for_addr(0x111), None)
        self.assertNotEqual(machine.memory.segment_for_addr(0x111), s2)

    def testMemorySegmentForAddrNotFound(self):
        machine: Machine = Machine()
        _ = machine.memory.add_segment(0x100, 0x100)
        self.assertEqual(machine.memory.segment_for_addr(0x200), None)

    def testMemoryAddSegmentDuplicate(self):
        machine: Machine = Machine()
        s1 = machine.memory.add_segment(0x100, 0x100)
        self.assertEqual(machine.memory.add_segment(0x100, 0x100), None)

    def testMemoryWriteRead(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.write(0x100, self.test_bytes)
        self.assertEqual(
            machine.memory.read(0x100, len(self.test_bytes)),
            self.test_bytes,
        )

    def testMemoryReadCrossSegment(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.add_segment(0x200, 0x100)
        with self.assertRaises(MemoryError) as e:
            _ = machine.memory.read(0x200 - 0x1, 0x10)

    def testMemoryReadInvalidAddress(self):
        machine: Machine = Machine()
        with self.assertRaises(MemoryError) as e:
            machine.memory.read(0x100, 0x10)

    def testMemoryWriteCrossSegment(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.add_segment(0x200, 0x100)
        with self.assertRaises(MemoryError) as e:
            machine.memory.write(0x200 - 0x1, self.test_bytes)

    def testMemoryWriteInvalidAddress(self):
        machine: Machine = Machine()
        with self.assertRaises(MemoryError) as e:
            machine.memory.write(0x100, self.test_bytes)


if __name__ == "__main__":
    unittest.main()
