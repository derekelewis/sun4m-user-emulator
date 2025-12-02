import unittest
from sun4m.register import RegisterFile


class TestRegister(unittest.TestCase):

    def test_g0_return_zero(self):
        window: RegisterFile = RegisterFile()
        window.write_register(0, 0xFF)
        self.assertEqual(window.read_register(0), 0)

    def test_register_window_save(self):
        window: RegisterFile = RegisterFile()
        window.cwp = 5
        window.write_register(8, 0xFF)
        window.cwp = 4  # TODO: replace with actual SAVE
        self.assertEqual(window.read_register(24), 0xFF)

    def test_register_window_restore(self):
        window: RegisterFile = RegisterFile()
        window.cwp = 5
        window.write_register(24, 0xFF)
        window.cwp = 6  # TODO: replace with actual RESTORE
        self.assertEqual(window.read_register(8), 0xFF)
