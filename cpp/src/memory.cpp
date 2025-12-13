#include "sun4m/memory.hpp"

#include <algorithm>

namespace sun4m {

MemorySegment::MemorySegment(uint32_t start, uint32_t size, Prot perms, std::string_view name)
    : start(start)
    , end(start + size)
    , buffer(size, 0)
    , permissions(perms)
    , name(name)
{
}

SystemMemory::SystemMemory() = default;

uint32_t SystemMemory::align_up(uint32_t addr, uint32_t alignment) const {
    return (addr + alignment - 1) & ~(alignment - 1);
}

uint32_t SystemMemory::align_down(uint32_t addr, uint32_t alignment) const {
    return addr & ~(alignment - 1);
}

void SystemMemory::invalidate_cache() {
    cached_addr_ = 0;
    cached_segment_ = nullptr;
}

MemorySegment* SystemMemory::add_segment(
    uint32_t start,
    uint32_t size,
    Prot permissions,
    std::string_view name
) {
    // Only add segment if start doesn't overlap with existing segments
    if (segment_for_addr(start) != nullptr) {
        return nullptr;
    }

    auto segment = std::make_unique<MemorySegment>(start, size, permissions, name);
    auto* ptr = segment.get();
    segments_[start] = std::move(segment);
    invalidate_cache();
    return ptr;
}

bool SystemMemory::region_is_free(uint32_t start, uint32_t size) const {
    uint32_t end = start + size;
    for (const auto& [seg_start, seg] : segments_) {
        // Check for overlap
        if (start < seg->end && end > seg->start) {
            return false;
        }
    }
    return true;
}

std::optional<uint32_t> SystemMemory::find_free_region(uint32_t size, uint32_t hint) {
    size = align_up(size);

    // If hint is provided and valid, try to use it
    if (hint != 0) {
        hint = align_down(hint);
        if (region_is_free(hint, size)) {
            return hint;
        }
    }

    // Search for free space starting from mmap_next_
    uint32_t addr = align_up(mmap_next_);
    while (addr + size <= MMAP_END) {
        if (region_is_free(addr, size)) {
            return addr;
        }
        // Skip to end of any overlapping segment
        auto* seg = segment_for_addr(addr);
        if (seg) {
            addr = align_up(seg->end);
        } else {
            addr += PAGE_SIZE;
        }
    }

    // Wrap around and try from MMAP_BASE
    addr = MMAP_BASE;
    while (addr < mmap_next_ && addr + size <= MMAP_END) {
        if (region_is_free(addr, size)) {
            return addr;
        }
        auto* seg = segment_for_addr(addr);
        if (seg) {
            addr = align_up(seg->end);
        } else {
            addr += PAGE_SIZE;
        }
    }

    return std::nullopt;
}

void SystemMemory::remove_overlapping(uint32_t addr, uint32_t size) {
    uint32_t end = addr + size;
    std::vector<uint32_t> to_remove;
    std::vector<std::unique_ptr<MemorySegment>> to_add;

    for (auto& [seg_start, seg] : segments_) {
        // Check for overlap
        if (addr < seg->end && end > seg->start) {
            // Determine overlap type
            if (seg->start >= addr && seg->end <= end) {
                // Segment completely within range - remove it
                to_remove.push_back(seg_start);
            } else if (seg->start < addr && seg->end > end) {
                // Range is completely within segment - split it
                to_remove.push_back(seg_start);

                // Create left fragment
                uint32_t left_size = addr - seg->start;
                auto left_seg = std::make_unique<MemorySegment>(
                    seg->start, left_size, seg->permissions, seg->name
                );
                std::copy_n(seg->buffer.begin(), left_size, left_seg->buffer.begin());
                to_add.push_back(std::move(left_seg));

                // Create right fragment
                uint32_t right_start = end;
                uint32_t right_size = seg->end - end;
                auto right_seg = std::make_unique<MemorySegment>(
                    right_start, right_size, seg->permissions, seg->name
                );
                uint32_t right_offset = end - seg->start;
                std::copy_n(seg->buffer.begin() + right_offset, right_size, right_seg->buffer.begin());
                to_add.push_back(std::move(right_seg));
            } else if (seg->start < addr) {
                // Segment extends before range - truncate end
                to_remove.push_back(seg_start);
                uint32_t new_size = addr - seg->start;
                auto new_seg = std::make_unique<MemorySegment>(
                    seg->start, new_size, seg->permissions, seg->name
                );
                std::copy_n(seg->buffer.begin(), new_size, new_seg->buffer.begin());
                to_add.push_back(std::move(new_seg));
            } else {
                // Segment extends after range - truncate start
                to_remove.push_back(seg_start);
                uint32_t new_start = end;
                uint32_t new_size = seg->end - end;
                auto new_seg = std::make_unique<MemorySegment>(
                    new_start, new_size, seg->permissions, seg->name
                );
                uint32_t old_offset = end - seg->start;
                std::copy_n(seg->buffer.begin() + old_offset, new_size, new_seg->buffer.begin());
                to_add.push_back(std::move(new_seg));
            }
        }
    }

    // Apply changes
    for (uint32_t start : to_remove) {
        segments_.erase(start);
    }
    for (auto& seg : to_add) {
        segments_[seg->start] = std::move(seg);
    }

    if (!to_remove.empty() || !to_add.empty()) {
        invalidate_cache();
    }
}

MemorySegment* SystemMemory::allocate_at(
    uint32_t addr,
    uint32_t size,
    Prot permissions,
    std::string_view name,
    bool fixed
) {
    size = align_up(size);

    if (addr == 0) {
        // Find free region
        auto found_addr = find_free_region(size);
        if (!found_addr) {
            return nullptr;
        }
        addr = *found_addr;
    } else {
        addr = align_down(addr);
        if (!region_is_free(addr, size)) {
            if (fixed) {
                // MAP_FIXED: remove overlapping segments first
                remove_overlapping(addr, size);
            } else {
                return nullptr;
            }
        }
    }

    auto* segment = add_segment(addr, size, permissions, name);
    if (segment && addr >= MMAP_BASE && addr < MMAP_END) {
        // Update mmap_next_ to after this allocation
        mmap_next_ = std::max(mmap_next_, addr + size);
    }
    return segment;
}

bool SystemMemory::remove_segment_range(uint32_t addr, uint32_t size) {
    addr = align_down(addr);
    size = align_up(size);

    // Find segments that are completely within the range
    std::vector<uint32_t> to_remove;
    for (const auto& [start, seg] : segments_) {
        if (seg->start >= addr && seg->end <= addr + size) {
            to_remove.push_back(start);
        }
    }

    for (uint32_t start : to_remove) {
        segments_.erase(start);
    }

    if (!to_remove.empty()) {
        invalidate_cache();
        return true;
    }
    return false;
}

bool SystemMemory::set_permissions(uint32_t addr, uint32_t size, Prot permissions) {
    auto* seg = segment_for_addr(addr);
    if (seg && seg->start <= addr && seg->end >= addr + size) {
        seg->permissions = permissions;
        return true;
    }
    return false;
}

MemorySegment* SystemMemory::segment_for_addr(uint32_t addr) {
    // Check cache first
    if (cached_segment_ && cached_segment_->start <= addr && addr < cached_segment_->end) {
        return cached_segment_;
    }

    for (auto& [start, segment] : segments_) {
        if (segment->start <= addr && addr < segment->end) {
            cached_addr_ = addr;
            cached_segment_ = segment.get();
            return segment.get();
        }
    }
    return nullptr;
}

const MemorySegment* SystemMemory::segment_for_addr(uint32_t addr) const {
    // Check cache first
    if (cached_segment_ && cached_segment_->start <= addr && addr < cached_segment_->end) {
        return cached_segment_;
    }

    for (const auto& [start, segment] : segments_) {
        if (segment->start <= addr && addr < segment->end) {
            cached_addr_ = addr;
            cached_segment_ = segment.get();
            return segment.get();
        }
    }
    return nullptr;
}

std::expected<std::vector<uint8_t>, MemoryError>
SystemMemory::read(uint32_t addr, uint32_t size) const {
    const auto* segment = segment_for_addr(addr);
    if (segment && segment->start <= (addr + size) && (addr + size) <= segment->end) {
        uint32_t offset = addr - segment->start;
        return std::vector<uint8_t>(
            segment->buffer.begin() + offset,
            segment->buffer.begin() + offset + size
        );
    }
    return std::unexpected(MemoryError::CrossSegmentAccess);
}

std::expected<void, MemoryError>
SystemMemory::write(uint32_t addr, std::span<const uint8_t> data) {
    auto* segment = segment_for_addr(addr);
    uint32_t size = static_cast<uint32_t>(data.size());
    if (segment && segment->start <= (addr + size) && (addr + size) <= segment->end) {
        uint32_t offset = addr - segment->start;
        std::copy(data.begin(), data.end(), segment->buffer.begin() + offset);
        return {};
    }
    return std::unexpected(MemoryError::CrossSegmentAccess);
}

} // namespace sun4m
