#include "sun4m/machine.hpp"

#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <optional>
#include <signal.h>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {

// Original terminal attributes for restoration
std::optional<termios> original_termios;

void save_terminal_state() {
    if (isatty(STDIN_FILENO)) {
        termios term;
        if (tcgetattr(STDIN_FILENO, &term) == 0) {
            original_termios = term;
        }
    }
}

void restore_terminal_state() {
    if (original_termios) {
        tcsetattr(STDIN_FILENO, TCSANOW, &*original_termios);
    }
}

void signal_handler(int /*sig*/) {
    restore_terminal_state();
    std::exit(130);  // Standard exit code for Ctrl-C
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [options] <file> [program_args...]\n"
              << "\n"
              << "SPARC V8 user-mode emulator\n"
              << "\n"
              << "Options:\n"
              << "  --steps N        Maximum number of cycles/steps to execute\n"
              << "  --trace          Enable instruction tracing\n"
              << "  --sysroot PATH   Path prefix for guest filesystem\n"
              << "  --passthrough P  Host path to access directly (can be repeated)\n"
              << "  -h, --help       Show this help message\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::optional<uint64_t> max_steps;
    bool trace = false;
    std::string sysroot;
    std::vector<std::string> passthrough;

    static struct option long_options[] = {
        {"steps", required_argument, nullptr, 's'},
        {"trace", no_argument, nullptr, 't'},
        {"sysroot", required_argument, nullptr, 'r'},
        {"passthrough", required_argument, nullptr, 'p'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 's':
                max_steps = std::strtoull(optarg, nullptr, 10);
                break;
            case 't':
                trace = true;
                break;
            case 'r':
                sysroot = optarg;
                break;
            case 'p':
                passthrough.emplace_back(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Check for required file argument
    if (optind >= argc) {
        std::cerr << "Error: No ELF file specified\n\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string elf_file = argv[optind];

    // Build argv for the guest program
    std::vector<std::string> guest_argv;
    for (int i = optind; i < argc; ++i) {
        guest_argv.emplace_back(argv[i]);
    }

    // Save terminal state and set up signal handlers
    save_terminal_state();
    std::atexit(restore_terminal_state);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create machine and load ELF
    sun4m::Machine machine(trace, sysroot, std::move(passthrough));
    auto load_result = machine.load_file(elf_file, guest_argv);
    if (!load_result) {
        std::cerr << "Error: " << load_result.error() << "\n";
        return 1;
    }

    // Run until halt or step limit
    int exit_code = machine.cpu.run(max_steps);

    return exit_code;
}
