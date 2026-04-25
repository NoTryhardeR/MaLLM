try:
    from colorama import Fore, Style, init

    init(autoreset=True)
except ImportError:
    # Use our stub when colorama is not installed
    from .colorama_stub import Fore, Style, init

    init()


def info(msg: str):
    """Blue [INFO] — normal pipeline progress"""
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL}  {msg}")


def success(msg: str):
    """Green [OK] — something completed successfully"""
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL}    {msg}")


def warn(msg: str):
    """Yellow [WARN] — non-fatal issue, e.g. missing disassembly file"""
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL}  {msg}")


def error(msg: str):
    """Red [ERROR] — something failed"""
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")


def section(title: str):
    """Print a visible section separator — helps read terminal output"""
    bar = "─" * 50
    print(f"\n{Fore.MAGENTA}{bar}")
    print(f"  {title}")
    print(f"{bar}{Style.RESET_ALL}")