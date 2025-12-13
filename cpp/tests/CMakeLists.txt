include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(sun4m_tests
    test_memory.cpp
    test_register.cpp
    test_cpu.cpp
    test_instruction.cpp
    test_decoder.cpp
    test_syscall.cpp
    test_elf.cpp
    test_machine.cpp
    test_fp_instruction.cpp
)

target_link_libraries(sun4m_tests PRIVATE
    sun4m_lib
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(sun4m_tests)
