class _Fore:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


class _Style:
    RESET_ALL = "\033[0m"


Fore = _Fore()
Style = _Style()


def init(autoreset=False):
    pass  # nothing needed — ANSI codes work natively
