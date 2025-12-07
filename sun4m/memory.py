from functools import lru_cache

# Memory protection flags (matching Linux)
PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

# Page size
PAGE_SIZE = 4096

# Default mmap region (where dynamic allocations go)
MMAP_BASE = 0x40000000
MMAP_END = 0x80000000


class MemorySegment:
    """Represents a virtual address space segment of contiguous memory"""

    def __init__(
        self,
        start: int,
        size: int,
        permissions: int = PROT_READ | PROT_WRITE,
        name: str = "",
    ):
        self.start = start
        self.end = start + size
        self.buffer = bytearray(size)
        self.permissions = permissions
        self.name = name  # For debugging (e.g., "libc.so.0")


class SystemMemory:
    """Represents address space"""

    def __init__(self):
        self._segments: dict[int, MemorySegment] = dict()
        # Track next free address in mmap region for anonymous mappings
        self._mmap_next: int = MMAP_BASE

    def add_segment(
        self,
        start: int,
        size: int,
        permissions: int = PROT_READ | PROT_WRITE,
        name: str = "",
    ) -> MemorySegment | None:
        """Add segment given a start address and size."""
        # Only add segment if start doesn't overlap with existing segments
        if not self.segment_for_addr(start):
            segment = MemorySegment(start, size, permissions, name)
            self._segments[start] = segment
            # Invalidate cache since address mappings changed
            self.segment_for_addr.cache_clear()
            return segment
        else:
            return None

    def _align_up(self, addr: int, alignment: int = PAGE_SIZE) -> int:
        """Align address up to the given alignment."""
        return (addr + alignment - 1) & ~(alignment - 1)

    def _align_down(self, addr: int, alignment: int = PAGE_SIZE) -> int:
        """Align address down to the given alignment."""
        return addr & ~(alignment - 1)

    def find_free_region(self, size: int, hint: int = 0) -> int | None:
        """Find a free region of the given size in the mmap area.

        Args:
            size: Required size (will be page-aligned up)
            hint: Preferred address (0 = let kernel choose)

        Returns:
            Start address of free region, or None if no space available
        """
        size = self._align_up(size)

        # If hint is provided and valid, try to use it
        if hint != 0:
            hint = self._align_down(hint)
            if self._region_is_free(hint, size):
                return hint

        # Search for free space starting from _mmap_next
        addr = self._align_up(self._mmap_next)
        while addr + size <= MMAP_END:
            if self._region_is_free(addr, size):
                return addr
            # Skip to end of any overlapping segment
            seg = self.segment_for_addr(addr)
            if seg:
                addr = self._align_up(seg.end)
            else:
                addr += PAGE_SIZE

        # Wrap around and try from MMAP_BASE
        addr = MMAP_BASE
        while addr < self._mmap_next and addr + size <= MMAP_END:
            if self._region_is_free(addr, size):
                return addr
            seg = self.segment_for_addr(addr)
            if seg:
                addr = self._align_up(seg.end)
            else:
                addr += PAGE_SIZE

        return None

    def _region_is_free(self, start: int, size: int) -> bool:
        """Check if a region is free (no overlapping segments)."""
        end = start + size
        for seg in self._segments.values():
            # Check for overlap
            if start < seg.end and end > seg.start:
                return False
        return True

    def allocate_at(
        self,
        addr: int,
        size: int,
        permissions: int = PROT_READ | PROT_WRITE,
        name: str = "",
    ) -> MemorySegment | None:
        """Allocate memory at a specific address.

        Args:
            addr: Virtual address (0 = find free region)
            size: Size in bytes (will be page-aligned)
            permissions: Memory protection flags
            name: Optional name for debugging

        Returns:
            The allocated segment, or None if allocation failed
        """
        size = self._align_up(size)

        if addr == 0:
            # Find free region
            found_addr = self.find_free_region(size)
            if found_addr is None:
                return None
            addr = found_addr
        else:
            addr = self._align_down(addr)
            if not self._region_is_free(addr, size):
                return None

        segment = self.add_segment(addr, size, permissions, name)
        if segment and addr >= MMAP_BASE and addr < MMAP_END:
            # Update _mmap_next to after this allocation
            self._mmap_next = max(self._mmap_next, addr + size)
        return segment

    def remove_segment_range(self, addr: int, size: int) -> bool:
        """Remove/unmap a memory region.

        For simplicity, this only handles exact segment matches.
        A full implementation would handle partial unmapping.
        """
        addr = self._align_down(addr)
        size = self._align_up(size)

        # Find segments that are completely within the range
        to_remove = []
        for start, seg in self._segments.items():
            if seg.start >= addr and seg.end <= addr + size:
                to_remove.append(start)

        for start in to_remove:
            del self._segments[start]

        if to_remove:
            self.segment_for_addr.cache_clear()
            return True
        return False

    def set_permissions(self, addr: int, size: int, permissions: int) -> bool:
        """Change memory permissions for a region.

        For simplicity, only handles regions within a single segment.
        """
        seg = self.segment_for_addr(addr)
        if seg and seg.start <= addr and seg.end >= addr + size:
            seg.permissions = permissions
            return True
        return False

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
            raise MemoryError(f"invalid or cross-segment read at {addr:#010x}")

    def write(self, addr: int, input: bytes) -> None:
        """Write bytes to memory"""

        segment = self.segment_for_addr(addr)
        # guard against writes that span segments
        if segment and segment.start <= (addr + len(input)) <= segment.end:
            offset = addr - segment.start
            segment.buffer[offset : offset + len(input)] = input
        else:
            raise MemoryError(f"invalid or cross-segment write at {addr:#010x}")
