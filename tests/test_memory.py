import unittest
from sun4m.machine import Machine
from sun4m.memory import SystemMemory, PROT_READ, PROT_WRITE, PROT_EXEC


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


class TestMemoryAllocateAt(unittest.TestCase):
    """Tests for allocate_at with MAP_FIXED support."""

    def setUp(self):
        self.memory = SystemMemory()

    def test_allocate_at_finds_free_region(self):
        """Test allocate_at with addr=0 finds free region."""
        segment = self.memory.allocate_at(0, 0x1000, PROT_READ | PROT_WRITE)
        self.assertIsNotNone(segment)
        self.assertEqual(segment.start, 0x40000000)  # MMAP_BASE
        self.assertEqual(len(segment.buffer), 0x1000)

    def test_allocate_at_specific_address(self):
        """Test allocate_at at specific address."""
        segment = self.memory.allocate_at(0x50000000, 0x2000, PROT_READ)
        self.assertIsNotNone(segment)
        self.assertEqual(segment.start, 0x50000000)
        self.assertEqual(segment.permissions, PROT_READ)

    def test_allocate_at_fails_on_overlap(self):
        """Test allocate_at fails when overlapping without fixed flag."""
        self.memory.allocate_at(0x50000000, 0x2000)
        segment = self.memory.allocate_at(0x50001000, 0x1000)  # Overlaps
        self.assertIsNone(segment)

    def test_allocate_at_fixed_replaces_segment(self):
        """Test allocate_at with fixed=True replaces existing segment."""
        # Create initial segment with data
        seg1 = self.memory.allocate_at(0x50000000, 0x3000)
        seg1.buffer[0:5] = b"hello"

        # Allocate with fixed=True over part of it
        seg2 = self.memory.allocate_at(0x50001000, 0x1000, fixed=True)
        self.assertIsNotNone(seg2)
        self.assertEqual(seg2.start, 0x50001000)

        # Original segment should be split - left part should still have data
        left_seg = self.memory.segment_for_addr(0x50000000)
        self.assertIsNotNone(left_seg)
        self.assertEqual(left_seg.buffer[0:5], b"hello")

    def test_allocate_at_fixed_complete_replacement(self):
        """Test allocate_at with fixed=True completely replaces smaller segment."""
        self.memory.allocate_at(0x50001000, 0x1000)

        # Allocate larger region that completely contains original
        seg = self.memory.allocate_at(0x50000000, 0x4000, fixed=True)
        self.assertIsNotNone(seg)

        # Original segment should be gone
        self.assertEqual(self.memory.segment_for_addr(0x50001500), seg)

    def test_allocate_at_page_alignment(self):
        """Test allocate_at aligns size to page boundary."""
        segment = self.memory.allocate_at(0x50000000, 0x100)  # Less than page
        self.assertIsNotNone(segment)
        self.assertEqual(len(segment.buffer), 0x1000)  # Rounded up to page

    def test_find_free_region(self):
        """Test find_free_region returns a valid free region."""
        self.memory.allocate_at(0x40000000, 0x1000)
        self.memory.allocate_at(0x40002000, 0x1000)

        # Should find some free region (search starts from _mmap_next)
        addr = self.memory.find_free_region(0x1000)
        self.assertIsNotNone(addr)
        # Verify the returned address doesn't overlap with existing segments
        self.assertTrue(self.memory._region_is_free(addr, 0x1000))

    def test_find_free_region_with_hint(self):
        """Test find_free_region with hint finds the specified gap."""
        self.memory.allocate_at(0x40000000, 0x1000)
        self.memory.allocate_at(0x40002000, 0x1000)

        # With hint, should find the specific gap at 0x40001000
        addr = self.memory.find_free_region(0x1000, hint=0x40001000)
        self.assertIsNotNone(addr)
        self.assertEqual(addr, 0x40001000)


class TestMemoryRemoveOverlapping(unittest.TestCase):
    """Tests for _remove_overlapping used by MAP_FIXED."""

    def setUp(self):
        self.memory = SystemMemory()

    def test_remove_overlapping_splits_segment(self):
        """Test that overlapping removal splits a segment correctly."""
        # Create a large segment
        seg = self.memory.add_segment(0x50000000, 0x10000)
        seg.buffer[0:4] = b"left"
        seg.buffer[0xF000:0xF005] = b"right"

        # Remove middle portion
        self.memory._remove_overlapping(0x50004000, 0x8000)

        # Check left fragment
        left = self.memory.segment_for_addr(0x50000000)
        self.assertIsNotNone(left)
        self.assertEqual(left.end, 0x50004000)
        self.assertEqual(left.buffer[0:4], b"left")

        # Check right fragment
        right = self.memory.segment_for_addr(0x5000C000)
        self.assertIsNotNone(right)
        self.assertEqual(right.start, 0x5000C000)
        self.assertEqual(right.buffer[0x3000:0x3005], b"right")

        # Middle should be empty
        self.assertIsNone(self.memory.segment_for_addr(0x50008000))


if __name__ == "__main__":
    unittest.main()
