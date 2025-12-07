from functools import lru_cache


class MemorySegment:
    """Represents a virtual address space segment of contiguous memory"""

    def __init__(self, start, size):
        self.start = start
        self.end = start + size
        self.buffer = bytearray(size)


class SystemMemory:
    """Represents address space"""

    def __init__(self):
        self._segments: dict[int, MemorySegment] = dict()

    def add_segment(self, start, size) -> MemorySegment | None:
        """add segment given a start address and size"""
        # only add segment if start doesn't overlap with existing segments
        if not self.segment_for_addr(start):
            segment: MemorySegment = MemorySegment(start, size)
            self._segments[start] = segment
            # Invalidate cache since address mappings changed
            self.segment_for_addr.cache_clear()
            return segment
        else:
            return None

    @lru_cache
    def segment_for_addr(self, addr: int) -> MemorySegment | None:
        """Retrieve segment given an address"""
        # TODO: replace linear search with something better
        for segment in self._segments.values():
            if segment.start <= addr < segment.end:
                return segment
        return None

    def read(self, addr: int, size: int) -> bytes:
        """Read bytes from memory"""

        segment = self.segment_for_addr(addr)
        # guard against reads that span segments
        if segment and segment.start <= (addr + size) <= segment.end:
            offset = addr - segment.start
            return segment.buffer[offset : offset + size]
        else:
            raise MemoryError("invalid or cross-segment read")

    def write(self, addr: int, input: bytes) -> None:
        """Write bytes to memory"""

        segment = self.segment_for_addr(addr)
        # guard against writes that span segments
        if segment and segment.start <= (addr + len(input)) <= segment.end:
            offset = addr - segment.start
            segment.buffer[offset : offset + len(input)] = input
        else:
            raise MemoryError("invalid or cross-segment write")
