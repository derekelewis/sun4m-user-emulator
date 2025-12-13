cmake_minimum_required(VERSION 3.25)
project(sun4m VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler flags
add_compile_options(-Wall -Wextra -Wpedantic)

# Library containing all emulator code
add_library(sun4m_lib STATIC
    src/memory.cpp
    src/register.cpp
    src/cpu.cpp
    src/instruction.cpp
    src/decoder.cpp
    src/syscall.cpp
    src/elf.cpp
    src/machine.cpp
)

target_include_directories(sun4m_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Main executable
add_executable(sun4m src/main.cpp)
target_link_libraries(sun4m PRIVATE sun4m_lib)

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install rules
install(TARGETS sun4m sun4m_lib
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(DIRECTORY include/ DESTINATION include)
