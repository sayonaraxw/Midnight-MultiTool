import sys
import os
import platform
import colorama
import ctypes
from pystyle import Colors as PystyleColors

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

colorama.init(autoreset=True)

from ui.menus import MainMenu
from ui.colors import Colors
from ui.display import clear_screen, gradient_print


def set_console_title(title: str):
    if platform.system().lower() == 'windows':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        except:
            os.system(f'title {title}')
        else:
            sys.stdout.write(f'\033]0;{title}\007')
        sys.stdout.flush()


def set_console_font_size(size: int):
    if platform.system().lower() == 'windows':
        try:
            
            class COORD(ctypes.Structure):
                _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]
            
            class CONSOLE_FONT_INFOEX(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_ulong),
                    ("nFont", ctypes.c_ulong),
                    ("dwFontSize", COORD),
                    ("FontFamily", ctypes.c_uint),
                    ("FontWeight", ctypes.c_uint),
                    ("FaceName", ctypes.c_wchar * 32)
                ]
            
            kernel32 = ctypes.windll.kernel32
            h_out = kernel32.GetStdHandle(-11)
            
            font_info = CONSOLE_FONT_INFOEX()
            font_info.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)
            font_info.dwFontSize = COORD(0, size)
            font_info.FontFamily = 54
            font_info.FontWeight = 400
            font_info.FaceName = "Consolas"
            
            kernel32.SetCurrentConsoleFontEx(h_out, False, ctypes.byref(font_info))
        except Exception:
            pass


def initialize_console():
    set_console_font_size(9)
    
    clear_screen()
    
    set_console_title("root@midnight")


def main():
    initialize_console()
    
    try:
        MainMenu.run()
    except KeyboardInterrupt:
        gradient_print("\n[!] Operation interrupted by user. Exiting forcefully.")
        sys.exit(1)
    except Exception as e:
        gradient_print(f"\n[!!!] A CRITICAL UNEXPECTED ERROR OCCURRED: {e}")
        gradient_print("       Please report this issue if possible.")
        sys.exit(1)


if __name__ == "__main__":
    main()
