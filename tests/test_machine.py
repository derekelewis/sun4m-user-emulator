import unittest

from sun4m.machine import Machine


class TestMachineArgvSetup(unittest.TestCase):
    """Tests for argc/argv stack setup in Machine.load_file()."""

    def setUp(self):
        self.machine = Machine()

    def test_argv_single_argument(self):
        """Test argc/argv setup with just the program name."""
        self.machine.load_file("./bin/hello_world")

        sp = self.machine.cpu.registers.read_register(14)

        # argc should be at sp + 64
        argc_bytes = self.machine.cpu.memory.read(sp + 64, 4)
        argc = int.from_bytes(argc_bytes, "big")
        self.assertEqual(argc, 1)

        # argv[0] pointer should be at sp + 68
        argv0_ptr_bytes = self.machine.cpu.memory.read(sp + 68, 4)
        argv0_ptr = int.from_bytes(argv0_ptr_bytes, "big")
        self.assertNotEqual(argv0_ptr, 0)

        # Read the string at argv[0]
        argv0_str = b""
        addr = argv0_ptr
        while True:
            byte = self.machine.cpu.memory.read(addr, 1)
            if byte[0] == 0:
                break
            argv0_str += byte
            addr += 1
        self.assertEqual(argv0_str, b"./bin/hello_world")

        # argv[1] should be NULL (after the single argument)
        argv1_ptr_bytes = self.machine.cpu.memory.read(sp + 72, 4)
        argv1_ptr = int.from_bytes(argv1_ptr_bytes, "big")
        self.assertEqual(argv1_ptr, 0)

    def test_argv_multiple_arguments(self):
        """Test argc/argv setup with multiple program arguments."""
        argv = ["./bin/hello_world", "arg1", "arg2", "arg3"]
        self.machine.load_file("./bin/hello_world", argv=argv)

        sp = self.machine.cpu.registers.read_register(14)

        # argc should be 4
        argc_bytes = self.machine.cpu.memory.read(sp + 64, 4)
        argc = int.from_bytes(argc_bytes, "big")
        self.assertEqual(argc, 4)

        # Verify all argv strings
        argv_offset = 68
        for i, expected_arg in enumerate(argv):
            ptr_bytes = self.machine.cpu.memory.read(sp + argv_offset, 4)
            ptr = int.from_bytes(ptr_bytes, "big")
            self.assertNotEqual(ptr, 0, f"argv[{i}] should not be NULL")

            # Read the string
            arg_str = b""
            addr = ptr
            while True:
                byte = self.machine.cpu.memory.read(addr, 1)
                if byte[0] == 0:
                    break
                arg_str += byte
                addr += 1
            self.assertEqual(
                arg_str.decode("utf-8"), expected_arg, f"argv[{i}] mismatch"
            )
            argv_offset += 4

        # argv[argc] should be NULL
        null_ptr_bytes = self.machine.cpu.memory.read(sp + argv_offset, 4)
        null_ptr = int.from_bytes(null_ptr_bytes, "big")
        self.assertEqual(null_ptr, 0, "argv should be NULL-terminated")

        # envp[0] should also be NULL
        envp0_bytes = self.machine.cpu.memory.read(sp + argv_offset + 4, 4)
        envp0 = int.from_bytes(envp0_bytes, "big")
        self.assertEqual(envp0, 0, "envp should be NULL-terminated")

    def test_sp_alignment(self):
        """Test that %sp is 8-byte aligned per SPARC ABI."""
        self.machine.load_file("./bin/hello_world", argv=["prog", "a", "bb", "ccc"])

        sp = self.machine.cpu.registers.read_register(14)
        self.assertEqual(sp & 0x7, 0, "Stack pointer should be 8-byte aligned")


if __name__ == "__main__":
    unittest.main()
