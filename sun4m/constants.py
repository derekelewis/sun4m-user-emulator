"""Shared constants and utility functions for the sun4m emulator."""

# FCC (Floating-point Condition Codes) values
FCC_E = 0  # Equal
FCC_L = 1  # Less than
FCC_G = 2  # Greater than
FCC_U = 3  # Unordered (NaN)


def sign_extend(value: int, bits: int) -> int:
    """Sign-extend a value from the given number of bits to a Python int.

    Args:
        value: The unsigned value to sign-extend
        bits: The number of bits in the original value

    Returns:
        The sign-extended value as a signed Python integer
    """
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)
