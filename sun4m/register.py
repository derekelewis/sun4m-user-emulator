class Window:
    def __init__(self):
        self.i = [0] * 8
        self.l = [0] * 8


class RegisterFile:
    """SPARC register file with overlapping register windows.

    The default of 64 windows is intentionally larger than real hardware
    (typically 7-32 windows) to avoid implementing window overflow/underflow
    traps. With 64 windows, deeply nested call chains won't exhaust the
    window pool, eliminating the need to spill/fill registers to/from memory.
    """

    def __init__(self, n_windows: int = 64):
        self.n_windows: int = n_windows
        self.windows: list[Window] = [Window() for _ in range(n_windows)]
        self.g: list[int] = [0] * 8
        self.cwp: int = 0

    def read_register(self, register: int) -> int:
        if register < 8:  # globals
            if register == 0:  # g[0] must always be 0
                return 0
            return self.g[register]
        elif register < 16:  # outputs
            return self.windows[self.cwp - 1].i[register - 8]
        elif register < 24:  # locals
            return self.windows[self.cwp].l[register - 16]
        elif register < 32:  # inputs
            return self.windows[self.cwp].i[register - 24]
        else:
            raise ValueError("invalid register")

    def write_register(self, register: int, value: int) -> None:
        # Mask to 32 bits to handle negative values from sign extension
        value = value & 0xFFFFFFFF
        if register < 8:  # globals
            if register == 0:  # g[0] must always be 0
                return
            self.g[register] = value
        elif register < 16:  # outputs
            self.windows[self.cwp - 1].i[register - 8] = value
        elif register < 24:  # locals
            self.windows[self.cwp].l[register - 16] = value
        elif register < 32:  # inputs
            self.windows[self.cwp].i[register - 24] = value
        else:
            raise ValueError("invalid register")
