#include "sun4m/machine.hpp"
#include "sun4m/endian.hpp"

#include <fstream>
#include <random>

namespace sun4m {

Machine::Machine(bool trace, std::string_view sysroot, std::vector<std::string> passthrough)
    : cpu(&memory, trace, sysroot, std::move(passthrough))
    , trace_(trace)
    , sysroot_(sysroot)
{
}

std::string Machine::resolve_path(std::string_view guest_path) const {
    if (!sysroot_.empty() && !guest_path.empty() && guest_path[0] == '/') {
        return sysroot_ + std::string(guest_path);
    }
    return std::string(guest_path);
}

std::expected<uint32_t, std::string>
Machine::load_file(const std::filesystem::path& file, const std::vector<std::string>& argv) {
    // Read ELF file
    std::ifstream ifs(file, std::ios::binary);
    if (!ifs) {
        return std::unexpected("Failed to open file: " + file.string());
    }
    std::vector<uint8_t> elf_bytes(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>()
    );

    // Store the executable path for /proc/self/exe emulation
    cpu.exe_path = std::filesystem::absolute(file).string();

    // Load the main executable
    auto main_result = load_elf_info(memory, elf_bytes, 0);
    if (!main_result) {
        return std::unexpected(main_result.error());
    }
    auto& main_info = *main_result;
    entrypoint = main_info.entry_point;

    // Load interpreter if present (dynamic linking)
    std::optional<ElfInfo> interp_info;
    if (main_info.interpreter_path) {
        std::string interp_path = resolve_path(*main_info.interpreter_path);
        std::ifstream interp_ifs(interp_path, std::ios::binary);
        if (interp_ifs) {
            std::vector<uint8_t> interp_bytes(
                (std::istreambuf_iterator<char>(interp_ifs)),
                std::istreambuf_iterator<char>()
            );
            auto interp_result = load_elf_info(memory, interp_bytes, INTERP_BASE);
            if (interp_result) {
                interp_info = *interp_result;
                entrypoint = interp_info->entry_point;
            }
        }
    }

    // Initialize CPU to start at entry point
    cpu.pc = *entrypoint;
    cpu.npc = (*entrypoint + 4) & 0xFFFFFFFF;

    // Initialize memory segments
    // Stack: 16MB at 0xD0000000
    constexpr uint32_t stack_size = 0x1000000;
    constexpr uint32_t stack_base = 0xD0000000;
    memory.add_segment(stack_base, stack_size);
    uint32_t stack_top = stack_base + stack_size - 0x100000;  // Leave 1MB headroom

    // TLS segment at top of address space
    memory.add_segment(0xFFFF0000, 0x10000);

    // Set up stack with argc, argv, envp, auxv
    std::vector<std::string> actual_argv = argv.empty() ?
        std::vector<std::string>{file.string()} : argv;

    uint32_t sp = setup_stack(stack_top, actual_argv, main_info,
                              interp_info ? &*interp_info : nullptr);

    // Initialize %sp (register 14)
    cpu.registers.write_register(14, sp);

    // Initialize brk to after the loaded segments
    // Find the highest loaded address
    uint32_t max_addr = 0;
    for (const auto& [start, seg] : memory.segments()) {
        if (seg->end > max_addr && seg->start < MMAP_BASE) {
            max_addr = seg->end;
        }
    }
    cpu.brk = (max_addr + 0xFFF) & ~0xFFF;  // Page-align

    return *entrypoint;
}

uint32_t Machine::setup_stack(
    uint32_t stack_top,
    const std::vector<std::string>& argv,
    const ElfInfo& main_info,
    const ElfInfo* interp_info
) {
    // Empty environment for now
    std::vector<std::string> envp;

    // Reserve space at top of stack
    uint32_t data_ptr = stack_top - 256;

    // Write 16 random bytes for AT_RANDOM
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::array<uint8_t, 16> random_bytes;
    for (auto& b : random_bytes) {
        b = static_cast<uint8_t>(dis(gen));
    }
    data_ptr -= 16;
    data_ptr &= ~7;
    uint32_t at_random_addr = data_ptr;
    (void)memory.write(at_random_addr, random_bytes);

    // Write platform string "sparc"
    std::string platform = "sparc";
    data_ptr -= platform.size() + 1;
    uint32_t platform_addr = data_ptr;
    std::vector<uint8_t> platform_bytes(platform.begin(), platform.end());
    platform_bytes.push_back(0);
    (void)memory.write(platform_addr, platform_bytes);

    // Write executable filename for AT_EXECFN
    std::string execfn = argv.empty() ? "" : argv[0];
    data_ptr -= execfn.size() + 1;
    uint32_t execfn_addr = data_ptr;
    std::vector<uint8_t> execfn_bytes(execfn.begin(), execfn.end());
    execfn_bytes.push_back(0);
    (void)memory.write(execfn_addr, execfn_bytes);

    // Write argv strings
    std::vector<uint32_t> argv_string_addrs;
    for (const auto& arg : argv) {
        data_ptr -= arg.size() + 1;
        std::vector<uint8_t> arg_bytes(arg.begin(), arg.end());
        arg_bytes.push_back(0);
        (void)memory.write(data_ptr, arg_bytes);
        argv_string_addrs.push_back(data_ptr);
    }

    // Write envp strings
    std::vector<uint32_t> envp_string_addrs;
    for (const auto& env : envp) {
        data_ptr -= env.size() + 1;
        std::vector<uint8_t> env_bytes(env.begin(), env.end());
        env_bytes.push_back(0);
        (void)memory.write(data_ptr, env_bytes);
        envp_string_addrs.push_back(data_ptr);
    }

    // Align data_ptr
    data_ptr &= ~7;

    // Build auxv entries
    std::vector<std::pair<uint32_t, uint32_t>> auxv = {
        {AT_PHDR, main_info.phdr_addr},
        {AT_PHENT, main_info.phdr_size},
        {AT_PHNUM, main_info.phdr_count},
        {AT_PAGESZ, 4096},
        {AT_BASE, interp_info ? interp_info->base_address : 0},
        {AT_FLAGS, 0},
        {AT_ENTRY, main_info.entry_point},
        {AT_UID, 1000},
        {AT_EUID, 1000},
        {AT_GID, 1000},
        {AT_EGID, 1000},
        {AT_PLATFORM, platform_addr},
        {AT_HWCAP, 0},
        {AT_CLKTCK, 100},
        {AT_RANDOM, at_random_addr},
        {AT_EXECFN, execfn_addr},
        {AT_NULL, 0},
    };

    // Calculate total size needed
    size_t argc = argv.size();
    size_t envc = envp.size();
    size_t pointer_area_size = 64  // 16-word register save area
        + 4  // argc
        + 4 * argc  // argv pointers
        + 4  // NULL
        + 4 * envc  // envp pointers
        + 4  // NULL
        + 8 * auxv.size();  // auxv entries
    pointer_area_size = (pointer_area_size + 7) & ~7;

    uint32_t sp = data_ptr - static_cast<uint32_t>(pointer_area_size);
    sp &= ~7;

    // Write argc at sp + 64
    uint32_t offset = 64;
    std::array<uint8_t, 4> buf;
    write_be32(buf, static_cast<uint32_t>(argc));
    (void)memory.write(sp + offset, buf);
    offset += 4;

    // Write argv pointers
    for (uint32_t addr : argv_string_addrs) {
        write_be32(buf, addr);
        (void)memory.write(sp + offset, buf);
        offset += 4;
    }
    // NULL terminator for argv
    write_be32(buf, 0);
    (void)memory.write(sp + offset, buf);
    offset += 4;

    // Write envp pointers
    for (uint32_t addr : envp_string_addrs) {
        write_be32(buf, addr);
        (void)memory.write(sp + offset, buf);
        offset += 4;
    }
    // NULL terminator for envp
    write_be32(buf, 0);
    (void)memory.write(sp + offset, buf);
    offset += 4;

    // Write auxv entries
    for (const auto& [atype, aval] : auxv) {
        write_be32(buf, atype);
        (void)memory.write(sp + offset, buf);
        offset += 4;
        write_be32(buf, aval);
        (void)memory.write(sp + offset, buf);
        offset += 4;
    }

    return sp;
}

} // namespace sun4m
