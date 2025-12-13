#pragma once

#include "constants.hpp"

#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sun4m {

/// Represents a virtual address space segment of contiguous memory
class MemorySegment {
public:
    uint32_t start;
    uint32_t end;
    std::vector<uint8_t> buffer;
    Prot permissions;
    std::string name;  // For debugging (e.g., "libc.so.0")

    MemorySegment(uint32_t start, uint32_t size,
                  Prot perms = Prot::Read | Prot::Write,
                  std::string_view name = "");

    [[nodiscard]] uint32_t size() const { return end - start; }
};

/// Error types for memory operations
enum class MemoryError {
    InvalidAddress,
    CrossSegmentAccess,
    AllocationFailed,
    OverlappingSegment
};

/// Represents the system address space with segment management
class SystemMemory {
public:
    SystemMemory();

    /// Add segment given a start address and size.
    /// Returns nullptr on overlap.
    MemorySegment* add_segment(
        uint32_t start,
        uint32_t size,
        Prot permissions = Prot::Read | Prot::Write,
        std::string_view name = ""
    );

    /// Allocate memory at a specific address.
    /// @param addr Virtual address (0 = find free region)
    /// @param size Size in bytes (will be page-aligned)
    /// @param permissions Memory protection flags
    /// @param name Optional name for debugging
    /// @param fixed If true, unmap any overlapping segments first (like MAP_FIXED)
    /// @return The allocated segment, or nullptr if allocation failed
    MemorySegment* allocate_at(
        uint32_t addr,
        uint32_t size,
        Prot permissions = Prot::Read | Prot::Write,
        std::string_view name = "",
        bool fixed = false
    );

    /// Find a free region of the given size in the mmap area.
    /// @param size Required size (will be page-aligned up)
    /// @param hint Preferred address (0 = let kernel choose)
    /// @return Start address of free region, or nullopt if no space available
    [[nodiscard]] std::optional<uint32_t> find_free_region(uint32_t size, uint32_t hint = 0);

    /// Remove/unmap a memory region.
    bool remove_segment_range(uint32_t addr, uint32_t size);

    /// Change memory permissions for a region.
    bool set_permissions(uint32_t addr, uint32_t size, Prot permissions);

    /// Retrieve segment containing the given address
    [[nodiscard]] MemorySegment* segment_for_addr(uint32_t addr);
    [[nodiscard]] const MemorySegment* segment_for_addr(uint32_t addr) const;

    /// Read bytes from memory
    [[nodiscard]] std::expected<std::vector<uint8_t>, MemoryError>
    read(uint32_t addr, uint32_t size) const;

    /// Write bytes to memory
    [[nodiscard]] std::expected<void, MemoryError>
    write(uint32_t addr, std::span<const uint8_t> data);

    /// Direct access to segments (for iteration)
    [[nodiscard]] const std::map<uint32_t, std::unique_ptr<MemorySegment>>& segments() const {
        return segments_;
    }

private:
    std::map<uint32_t, std::unique_ptr<MemorySegment>> segments_;
    uint32_t mmap_next_ = MMAP_BASE;

    // Simple cache for segment lookups (most recent)
    mutable uint32_t cached_addr_ = 0;
    mutable MemorySegment* cached_segment_ = nullptr;

    [[nodiscard]] uint32_t align_up(uint32_t addr, uint32_t alignment = PAGE_SIZE) const;
    [[nodiscard]] uint32_t align_down(uint32_t addr, uint32_t alignment = PAGE_SIZE) const;
    [[nodiscard]] bool region_is_free(uint32_t start, uint32_t size) const;
    void remove_overlapping(uint32_t addr, uint32_t size);
    void invalidate_cache();
};

} // namespace sun4m
