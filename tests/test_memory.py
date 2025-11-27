import unittest
from sun4m.machine import Machine
from sun4m.memory import SystemMemory


class MemoryTestCase(unittest.TestCase):

    test_bytes: bytes = "hello, world".encode()

    def testMemoryWriteRead(self):
        machine: Machine = Machine()
        machine.memory.add_segment(0x100, 0x100)
        machine.memory.write(0x100, self.test_bytes)
        self.assertEqual(
            machine.memory.read(0x100, len(self.test_bytes)),
            self.test_bytes,
        )

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
