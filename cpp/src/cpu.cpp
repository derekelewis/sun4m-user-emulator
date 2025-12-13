#include "sun4m/cpu.hpp"
#include "sun4m/endian.hpp"
#include "sun4m/decoder.hpp"

#include <bit>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

namespace sun4m {

// ============================================================================
// FileDescriptorTable implementation
// ============================================================================

FileDescriptorTable::FileDescriptorTable(std::string_view sysroot,
                                         std::vector<std::string> passthrough)
    : sysroot_(sysroot)
    , passthrough_(std::move(passthrough))
{
    // Pre-populate stdin, stdout, stderr with their actual host fds
    auto stdin_fd = std::make_unique<FileDescriptor>();
    stdin_fd->fd = 0;
    stdin_fd->path = "/dev/stdin";
    stdin_fd->host_fd = STDIN_FILENO;
    stdin_fd->is_special = true;
    table_[0] = std::move(stdin_fd);

    auto stdout_fd = std::make_unique<FileDescriptor>();
    stdout_fd->fd = 1;
    stdout_fd->path = "/dev/stdout";
    stdout_fd->host_fd = STDOUT_FILENO;
    stdout_fd->is_special = true;
    table_[1] = std::move(stdout_fd);

    auto stderr_fd = std::make_unique<FileDescriptor>();
    stderr_fd->fd = 2;
    stderr_fd->path = "/dev/stderr";
    stderr_fd->host_fd = STDERR_FILENO;
    stderr_fd->is_special = true;
    table_[2] = std::move(stderr_fd);
}

std::string FileDescriptorTable::translate_path(std::string_view guest_path) const {
    if (!sysroot_.empty() && !guest_path.empty() && guest_path[0] == '/') {
        // Check if path matches any passthrough prefix
        for (const auto& prefix : passthrough_) {
            if (guest_path == prefix ||
                (guest_path.size() > prefix.size() &&
                 guest_path.substr(0, prefix.size()) == prefix &&
                 (prefix.back() == '/' || guest_path[prefix.size()] == '/'))) {
                return std::string(guest_path);
            }
        }
        return sysroot_ + std::string(guest_path);
    }
    return std::string(guest_path);
}

int FileDescriptorTable::open(std::string_view path, int flags, int mode) {
    // SPARC O_DIRECTORY value (may differ from host)
    constexpr int SPARC_O_DIRECTORY = 0x10000;

    std::string host_path = translate_path(path);

    // Check if this is a directory open
    bool is_dir = false;
    try {
        is_dir = std::filesystem::is_directory(host_path);
    } catch (...) {
        is_dir = false;
    }

    if (is_dir || (flags & SPARC_O_DIRECTORY)) {
        // Opening a directory - use low-level open()
        int os_flags = O_RDONLY | O_DIRECTORY;
        int host_fd = ::open(host_path.c_str(), os_flags);
        if (host_fd < 0) {
            return -errno;
        }

        int fd = next_fd_++;
        auto desc = std::make_unique<FileDescriptor>();
        desc->fd = fd;
        desc->path = std::string(path);
        desc->host_fd = host_fd;
        desc->flags = flags;
        desc->is_directory = true;
        table_[fd] = std::move(desc);
        return fd;
    }

    // Regular file open - convert SPARC O_* flags to host O_* flags
    int access_mode = flags & 3;
    int os_flags = 0;

    if (access_mode == 0) {
        os_flags = O_RDONLY;
    } else if (access_mode == 1) {
        os_flags = O_WRONLY;
    } else {
        os_flags = O_RDWR;
    }

    // Map SPARC flags to host flags
    if (flags & 0x40) os_flags |= O_CREAT;
    if (flags & 0x80) os_flags |= O_EXCL;
    if (flags & 0x100) os_flags |= O_NOCTTY;
    if (flags & 0x200) os_flags |= O_TRUNC;
    if (flags & 0x400) os_flags |= O_APPEND;
    if (flags & 0x800) os_flags |= O_NONBLOCK;

    int host_fd = ::open(host_path.c_str(), os_flags, mode);
    if (host_fd < 0) {
        return -errno;
    }

    int fd = next_fd_++;
    auto desc = std::make_unique<FileDescriptor>();
    desc->fd = fd;
    desc->path = std::string(path);
    desc->host_fd = host_fd;
    desc->flags = flags;
    table_[fd] = std::move(desc);
    return fd;
}

int FileDescriptorTable::close(int fd) {
    auto it = table_.find(fd);
    if (it == table_.end()) {
        return -9;  // EBADF
    }

    auto& desc = it->second;
    if (desc->is_special) {
        // Don't actually close stdin/stdout/stderr
        return 0;
    }

    if (desc->host_fd >= 0) {
        ::close(desc->host_fd);
    }

    table_.erase(it);
    return 0;
}

FileDescriptor* FileDescriptorTable::get(int fd) {
    auto it = table_.find(fd);
    return it != table_.end() ? it->second.get() : nullptr;
}

const FileDescriptor* FileDescriptorTable::get(int fd) const {
    auto it = table_.find(fd);
    return it != table_.end() ? it->second.get() : nullptr;
}

std::expected<std::vector<uint8_t>, int> FileDescriptorTable::read(int fd, size_t count) {
    auto* desc = get(fd);
    if (!desc) {
        return std::unexpected(-9);  // EBADF
    }

    if (desc->host_fd < 0) {
        return std::unexpected(-9);  // EBADF
    }

    std::vector<uint8_t> buffer(count);
    ssize_t bytes_read = ::read(desc->host_fd, buffer.data(), count);
    if (bytes_read < 0) {
        return std::unexpected(-errno);
    }
    buffer.resize(bytes_read);
    desc->position += bytes_read;
    return buffer;
}

std::expected<size_t, int> FileDescriptorTable::write(int fd, std::span<const uint8_t> data) {
    auto* desc = get(fd);
    if (!desc) {
        return std::unexpected(-9);  // EBADF
    }

    if (desc->host_fd < 0) {
        return std::unexpected(-9);  // EBADF
    }

    ssize_t bytes_written = ::write(desc->host_fd, data.data(), data.size());
    if (bytes_written < 0) {
        return std::unexpected(-errno);
    }
    desc->position += bytes_written;
    return static_cast<size_t>(bytes_written);
}

std::expected<int64_t, int> FileDescriptorTable::lseek(int fd, int64_t offset, int whence) {
    auto* desc = get(fd);
    if (!desc) {
        return std::unexpected(-9);  // EBADF
    }

    if (desc->host_fd < 0) {
        return std::unexpected(-9);  // EBADF
    }

    if (desc->is_special) {
        return std::unexpected(-29);  // ESPIPE - can't seek on pipe/socket
    }

    off_t new_pos = ::lseek(desc->host_fd, offset, whence);
    if (new_pos < 0) {
        return std::unexpected(-errno);
    }

    desc->position = new_pos;
    return new_pos;
}

int FileDescriptorTable::dup2(int oldfd, int newfd) {
    auto* old_desc = get(oldfd);
    if (!old_desc) {
        return -9;  // EBADF
    }

    if (old_desc->host_fd < 0) {
        return -9;  // EBADF
    }

    // If newfd is already open, close it first
    if (table_.contains(newfd)) {
        close(newfd);
    }

    // Duplicate the host file descriptor
    int new_host_fd = ::dup(old_desc->host_fd);
    if (new_host_fd < 0) {
        return -errno;
    }

    // Create a new descriptor
    auto new_desc = std::make_unique<FileDescriptor>();
    new_desc->fd = newfd;
    new_desc->path = old_desc->path;
    new_desc->host_fd = new_host_fd;
    new_desc->position = old_desc->position;
    new_desc->flags = old_desc->flags;
    new_desc->is_special = old_desc->is_special;
    new_desc->is_directory = old_desc->is_directory;

    table_[newfd] = std::move(new_desc);

    // Update next_fd if necessary
    if (newfd >= next_fd_) {
        next_fd_ = newfd + 1;
    }

    return newfd;
}

// ============================================================================
// ICC implementation
// ============================================================================

void ICC::update(uint32_t result, uint32_t op1, uint32_t op2, bool is_sub) {
    // N: set if result is negative (bit 31 set)
    n = (result & 0x80000000) != 0;

    // Z: set if result is zero
    z = (result == 0);

    if (is_sub) {
        // For subtraction A - B:
        // C: set if there WAS a borrow (i.e., A < B as unsigned)
        c = op1 < op2;
        // V: overflow if signs of operands differ and sign of result
        // differs from sign of first operand
        bool op1_sign = (op1 & 0x80000000) != 0;
        bool op2_sign = (op2 & 0x80000000) != 0;
        bool result_sign = (result & 0x80000000) != 0;
        v = (op1_sign != op2_sign) && (result_sign != op1_sign);
    } else {
        // For addition A + B:
        // C: set if carry out of bit 31
        uint64_t full_result = static_cast<uint64_t>(op1) + static_cast<uint64_t>(op2);
        c = full_result > 0xFFFFFFFF;
        // V: overflow if both operands have same sign but result differs
        bool op1_sign = (op1 & 0x80000000) != 0;
        bool op2_sign = (op2 & 0x80000000) != 0;
        bool result_sign = (result & 0x80000000) != 0;
        v = (op1_sign == op2_sign) && (result_sign != op1_sign);
    }
}

// ============================================================================
// FPUState implementation
// ============================================================================

float FPUState::read_single(uint8_t reg) const {
    return std::bit_cast<float>(f[reg]);
}

void FPUState::write_single(uint8_t reg, float value) {
    f[reg] = std::bit_cast<uint32_t>(value);
}

double FPUState::read_double(uint8_t reg) const {
    if (reg & 1) {
        throw std::invalid_argument("double-precision requires even register");
    }
    // SPARC stores high word in even register, low word in odd register (big-endian)
    uint64_t combined = (static_cast<uint64_t>(f[reg]) << 32) | f[reg + 1];
    return std::bit_cast<double>(combined);
}

void FPUState::write_double(uint8_t reg, double value) {
    if (reg & 1) {
        throw std::invalid_argument("double-precision requires even register");
    }
    uint64_t raw = std::bit_cast<uint64_t>(value);
    f[reg] = static_cast<uint32_t>(raw >> 32);      // High word
    f[reg + 1] = static_cast<uint32_t>(raw & 0xFFFFFFFF);  // Low word
}

uint32_t FPUState::read_raw(uint8_t reg) const {
    return f[reg];
}

void FPUState::write_raw(uint8_t reg, uint32_t value) {
    f[reg] = value;
}

FCC FPUState::fcc() const {
    return static_cast<FCC>((fsr >> 10) & 0x3);
}

void FPUState::set_fcc(FCC value) {
    fsr = (fsr & ~0xC00) | (static_cast<uint32_t>(value) << 10);
}

void FPUState::compare(double a, double b) {
    if (std::isnan(a) || std::isnan(b)) {
        set_fcc(FCC::Unordered);
    } else if (a == b) {
        set_fcc(FCC::Equal);
    } else if (a < b) {
        set_fcc(FCC::Less);
    } else {
        set_fcc(FCC::Greater);
    }
}

// ============================================================================
// CpuState implementation
// ============================================================================

CpuState::CpuState(SystemMemory* memory, bool trace,
                   std::string_view sysroot,
                   std::vector<std::string> passthrough)
    : trace(trace)
    , memory(memory)
    , fd_table(sysroot, std::move(passthrough))
{
    // If no memory provided, create our own for standalone usage
    if (!memory) {
        owned_memory_ = std::make_unique<SystemMemory>();
        this->memory = owned_memory_.get();
    }
}

void CpuState::step() {
    // Treat an unset npc as sequential execution from the current PC
    uint32_t current_npc = npc.value_or((pc + 4) & 0xFFFFFFFF);

    // Default fallthrough for the instruction after *current_npc*
    uint32_t default_next_npc = (current_npc + 4) & 0xFFFFFFFF;
    npc = default_next_npc;

    auto inst_result = memory->read(pc, 4);
    if (!inst_result) {
        throw std::runtime_error("Memory read error at PC");
    }

    uint32_t inst_word = read_be32(*inst_result);
    if (trace) {
        std::cerr << std::format("PC={:#010x} inst: {:#x}\n", pc, inst_word);
    }

    auto instruction = decode(inst_word);
    instruction->execute(*this);

    // Advance pipeline: execute delay-slot semantics
    if (annul_next) {
        annul_next = false;
        pc = *npc & 0xFFFFFFFF;
        npc = (*npc + 4) & 0xFFFFFFFF;
    } else {
        pc = current_npc & 0xFFFFFFFF;
        npc = *npc & 0xFFFFFFFF;
    }
}

int CpuState::run(std::optional<int64_t> max_steps) {
    int64_t steps = 0;
    while (!halted) {
        if (max_steps && steps >= *max_steps) {
            break;
        }
        step();
        ++steps;
    }
    return exit_code;
}

} // namespace sun4m
