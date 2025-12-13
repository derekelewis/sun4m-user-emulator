#include "sun4m/elf.hpp"
#include "sun4m/endian.hpp"

#include <cstring>

namespace sun4m {

namespace {

struct ElfHeader {
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ProgramHeader {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

std::expected<ElfHeader, std::string> parse_elf_header(std::span<const uint8_t> elf_bytes) {
    if (elf_bytes.size() < 52) {
        return std::unexpected("ELF header too small");
    }

    // Check magic
    static constexpr uint8_t ELF_MAGIC[] = {0x7f, 'E', 'L', 'F'};
    if (std::memcmp(elf_bytes.data(), ELF_MAGIC, 4) != 0) {
        return std::unexpected("not an ELF file");
    }

    // Check class, endianness, version
    if (elf_bytes[4] != ELFCLASS32) {
        return std::unexpected("unsupported ELF class (need 32-bit)");
    }
    if (elf_bytes[5] != ELFDATA2MSB) {
        return std::unexpected("unsupported endianness (need MSB)");
    }
    if (elf_bytes[6] != ELF_VERSION_CURRENT) {
        return std::unexpected("unknown ELF version");
    }

    // Parse header fields (big-endian)
    ElfHeader hdr;
    hdr.e_type = read_be16({elf_bytes.data() + 16, 2});
    hdr.e_machine = read_be16({elf_bytes.data() + 18, 2});
    hdr.e_version = read_be32({elf_bytes.data() + 20, 4});
    hdr.e_entry = read_be32({elf_bytes.data() + 24, 4});
    hdr.e_phoff = read_be32({elf_bytes.data() + 28, 4});
    hdr.e_shoff = read_be32({elf_bytes.data() + 32, 4});
    hdr.e_flags = read_be32({elf_bytes.data() + 36, 4});
    hdr.e_ehsize = read_be16({elf_bytes.data() + 40, 2});
    hdr.e_phentsize = read_be16({elf_bytes.data() + 42, 2});
    hdr.e_phnum = read_be16({elf_bytes.data() + 44, 2});
    hdr.e_shentsize = read_be16({elf_bytes.data() + 46, 2});
    hdr.e_shnum = read_be16({elf_bytes.data() + 48, 2});
    hdr.e_shstrndx = read_be16({elf_bytes.data() + 50, 2});

    if (hdr.e_machine != EM_SPARC) {
        return std::unexpected("unsupported machine (need EM_SPARC)");
    }
    if (hdr.e_version != ELF_VERSION_CURRENT) {
        return std::unexpected("unexpected ELF version");
    }
    if (hdr.e_phoff == 0 || hdr.e_phnum == 0) {
        return std::unexpected("ELF has no program headers");
    }
    if (hdr.e_phentsize < 32) {
        return std::unexpected("program header size too small");
    }
    if (hdr.e_phoff + hdr.e_phentsize * hdr.e_phnum > elf_bytes.size()) {
        return std::unexpected("truncated program headers");
    }

    return hdr;
}

ProgramHeader parse_program_header(std::span<const uint8_t> data) {
    ProgramHeader ph;
    ph.p_type = read_be32({data.data() + 0, 4});
    ph.p_offset = read_be32({data.data() + 4, 4});
    ph.p_vaddr = read_be32({data.data() + 8, 4});
    ph.p_paddr = read_be32({data.data() + 12, 4});
    ph.p_filesz = read_be32({data.data() + 16, 4});
    ph.p_memsz = read_be32({data.data() + 20, 4});
    ph.p_flags = read_be32({data.data() + 24, 4});
    ph.p_align = read_be32({data.data() + 28, 4});
    return ph;
}

void process_relocations(SystemMemory& memory, std::span<const uint8_t> elf_bytes,
                        uint32_t base_addr, uint32_t phoff, uint16_t phentsize, uint16_t phnum) {
    // Find PT_DYNAMIC
    uint32_t dyn_offset = 0;
    uint32_t dyn_size = 0;

    for (uint16_t i = 0; i < phnum; ++i) {
        auto ph = parse_program_header({elf_bytes.data() + phoff + i * phentsize, phentsize});
        if (ph.p_type == PT_DYNAMIC) {
            dyn_offset = ph.p_offset;
            dyn_size = ph.p_filesz;
            break;
        }
    }

    if (dyn_offset == 0) return;

    // Parse dynamic section
    uint32_t rela_addr = 0;
    uint32_t rela_size = 0;
    uint32_t rela_entsize = 12;

    for (uint32_t i = 0; i + 8 <= dyn_size; i += 8) {
        if (dyn_offset + i + 8 > elf_bytes.size()) break;
        uint32_t d_tag = read_be32({elf_bytes.data() + dyn_offset + i, 4});
        uint32_t d_val = read_be32({elf_bytes.data() + dyn_offset + i + 4, 4});
        if (d_tag == DT_NULL) break;
        else if (d_tag == DT_RELA) rela_addr = d_val;
        else if (d_tag == DT_RELASZ) rela_size = d_val;
        else if (d_tag == DT_RELAENT) rela_entsize = d_val;
    }

    if (rela_addr == 0 || rela_size == 0) return;

    // Find file offset for rela_addr
    uint32_t rela_file_offset = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        auto ph = parse_program_header({elf_bytes.data() + phoff + i * phentsize, phentsize});
        if (ph.p_type == PT_LOAD && ph.p_vaddr <= rela_addr && rela_addr < ph.p_vaddr + ph.p_filesz) {
            rela_file_offset = ph.p_offset + (rela_addr - ph.p_vaddr);
            break;
        }
    }

    if (rela_file_offset == 0) return;

    // Process relocations
    uint32_t num_relas = rela_size / rela_entsize;
    for (uint32_t i = 0; i < num_relas; ++i) {
        uint32_t offset = rela_file_offset + i * rela_entsize;
        if (offset + 12 > elf_bytes.size()) break;

        uint32_t r_offset = read_be32({elf_bytes.data() + offset, 4});
        uint32_t r_info = read_be32({elf_bytes.data() + offset + 4, 4});
        int32_t r_addend = read_be32_signed({elf_bytes.data() + offset + 8, 4});

        uint8_t r_type = r_info & 0xff;

        if (r_type == R_SPARC_RELATIVE) {
            uint32_t target_addr = base_addr + r_offset;
            uint32_t new_value = (base_addr + r_addend) & 0xFFFFFFFF;
            std::array<uint8_t, 4> buf;
            write_be32(buf, new_value);
            (void)memory.write(target_addr, buf);  // Ignore errors
        }
    }
}

}  // namespace

std::expected<ElfInfo, std::string>
load_elf_info(SystemMemory& memory, std::span<const uint8_t> elf_bytes, uint32_t base_addr) {
    auto hdr_result = parse_elf_header(elf_bytes);
    if (!hdr_result) {
        return std::unexpected(hdr_result.error());
    }
    auto& hdr = *hdr_result;

    // Extract raw program headers
    std::vector<uint8_t> program_headers(
        elf_bytes.begin() + hdr.e_phoff,
        elf_bytes.begin() + hdr.e_phoff + hdr.e_phentsize * hdr.e_phnum
    );

    std::optional<std::string> interpreter_path;
    uint32_t phdr_vaddr = 0;
    uint32_t phdr_load_addr = 0;

    // First pass: find PT_INTERP and PT_PHDR
    for (uint16_t i = 0; i < hdr.e_phnum; ++i) {
        auto ph = parse_program_header({elf_bytes.data() + hdr.e_phoff + i * hdr.e_phentsize, hdr.e_phentsize});
        if (ph.p_type == PT_INTERP) {
            std::string interp(
                reinterpret_cast<const char*>(elf_bytes.data() + ph.p_offset),
                ph.p_filesz
            );
            // Remove null terminator
            while (!interp.empty() && interp.back() == '\0') {
                interp.pop_back();
            }
            interpreter_path = interp;
        } else if (ph.p_type == PT_PHDR) {
            phdr_vaddr = ph.p_vaddr;
        }
    }

    // Second pass: load PT_LOAD segments
    for (uint16_t i = 0; i < hdr.e_phnum; ++i) {
        auto ph = parse_program_header({elf_bytes.data() + hdr.e_phoff + i * hdr.e_phentsize, hdr.e_phentsize});
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
            continue;
        }

        if (ph.p_filesz > ph.p_memsz) {
            return std::unexpected("p_filesz larger than p_memsz");
        }
        if (ph.p_offset + ph.p_filesz > elf_bytes.size()) {
            return std::unexpected("segment exceeds file size");
        }

        // Check if this segment contains program headers
        uint32_t phdr_end = hdr.e_phoff + hdr.e_phentsize * hdr.e_phnum;
        if (ph.p_offset <= hdr.e_phoff && phdr_end <= ph.p_offset + ph.p_filesz) {
            phdr_load_addr = ph.p_vaddr + (hdr.e_phoff - ph.p_offset);
        }

        uint32_t load_addr = base_addr + ph.p_vaddr;
        auto* segment = memory.add_segment(load_addr, ph.p_memsz);
        if (!segment) {
            return std::unexpected("segment overlap while loading ELF");
        }

        std::copy(
            elf_bytes.begin() + ph.p_offset,
            elf_bytes.begin() + ph.p_offset + ph.p_filesz,
            segment->buffer.begin()
        );
    }

    // Process relocations for PIE/shared objects
    if (hdr.e_type == ET_DYN && base_addr != 0) {
        process_relocations(memory, elf_bytes, base_addr, hdr.e_phoff, hdr.e_phentsize, hdr.e_phnum);
    }

    // Calculate phdr_addr
    uint32_t phdr_addr = 0;
    if (phdr_vaddr) {
        phdr_addr = base_addr + phdr_vaddr;
    } else if (phdr_load_addr) {
        phdr_addr = base_addr + phdr_load_addr;
    }

    return ElfInfo{
        .entry_point = base_addr + hdr.e_entry,
        .phdr_addr = phdr_addr,
        .phdr_count = hdr.e_phnum,
        .phdr_size = hdr.e_phentsize,
        .interpreter_path = interpreter_path,
        .base_address = base_addr,
        .elf_type = hdr.e_type,
        .program_headers = std::move(program_headers),
    };
}

std::expected<uint32_t, std::string>
load_elf(SystemMemory& memory, std::span<const uint8_t> elf_bytes, uint32_t base_addr) {
    auto result = load_elf_info(memory, elf_bytes, base_addr);
    if (!result) {
        return std::unexpected(result.error());
    }
    return result->entry_point;
}

} // namespace sun4m
