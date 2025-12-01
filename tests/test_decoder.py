import unittest
from sun4m.decoder import decode
from sun4m.instruction import CallInstruction, Format2Instruction, Format3Instruction


class TestDecoder(unittest.TestCase):

    def test_decode_call_instruction(self):
        inst = 1 << 30
        self.assertIsInstance(decode(inst), CallInstruction)

    def test_decode_format2(self):
        inst = 0 << 30
        self.assertIsInstance(decode(inst), Format2Instruction)

    def test_decode_format3(self):
        inst = 2 << 30
        self.assertIsInstance(decode(inst), Format3Instruction)
        inst = 3 << 30
        self.assertIsInstance(decode(inst), Format3Instruction)
