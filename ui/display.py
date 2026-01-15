import os
import platform
import re
import shutil
from pystyle import Colorate, Colors
import colorama
from config import Config

colorama.init(autoreset=True)


def get_midnight_gradient_text(text: str) -> str:
    return Colorate.Horizontal(Colors.purple_to_blue, text)


def get_text_length_without_ansi(text: str) -> int:
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return len(ansi_escape.sub('', text))


def align_gradient_text(text: str, width: int, gradient_func=None) -> str:
    if gradient_func:
        colored_text = gradient_func(text)
    else:
        colored_text = get_midnight_gradient_text(text)
    
    text_length = get_text_length_without_ansi(colored_text)
    padding = max(0, width - text_length)
    return colored_text + ' ' * padding


ASCII_ART_LOGO = """███▄ ▄███▓ ██▓▓█████▄  ███▄    █  ██▓  ▄████  ██░ ██ ▄▄▄█████▓
▓██▒▀█▀ ██▒▓██▒▒██▀ ██▌ ██ ▀█   █ ▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒
▓██    ▓██░▒██▒░██   █▌▓██  ▀█ ██▒▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░
▒██    ▒██ ░██░░▓█▄   ▌▓██▒  ▐▌██▒░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ 
▒██▒   ░██▒░██░░▒████▓ ▒██░   ▓██░░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ 
░ ▒░   ░  ░░▓   ▒▒▓  ▒ ░ ▒░   ▒ ▒ ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   
░  ░      ░ ▒ ░ ░ ▒  ▒ ░ ░░   ░ ▒░ ▒ ░  ░   ░  ▒ ░▒░ ░    ░    
░      ░    ▒ ░ ░ ░  ░    ░   ░ ░  ▒ ░░ ░   ░  ░  ░░ ░  ░      
       ░    ░     ░             ░  ░        ░  ░  ░  ░         
                ░                                              """


def get_ascii_art_with_frame():
    try:
        terminal_width = shutil.get_terminal_size().columns
    except:
        terminal_width = 80
    
    lines = [line.rstrip() for line in ASCII_ART_LOGO.strip().split('\n')]
    
    max_width = max(len(line) for line in lines) if lines else 0
    
    padding = max(0, (terminal_width - max_width) // 2)
    padding_str = ' ' * padding
    
    centered_lines = [padding_str + line for line in lines]
    
    centered_art = '\n'.join(centered_lines)
    return get_midnight_gradient_text(centered_art)


def get_author_info():
    try:
        terminal_width = shutil.get_terminal_size().columns
    except:
        terminal_width = 80
    
    labels = ["Version", "Author", "GitHub"]
    values = [Config.VERSION, Config.AUTHOR, Config.GITHUB]
    
    max_label_len = max(len(label) for label in labels)
    
    max_value_len = max(len(value) for value in values)
    
    lines = []
    for label, value in zip(labels, values):
        label_padded = label.ljust(max_label_len)
        value_padded = value.ljust(max_value_len)
        content = f"{label_padded} : {value_padded}"
        lines.append(content)
    
    max_width = max(len(line) for line in lines) if lines else 0
    
    padding = max(0, (terminal_width - max_width) // 2)
    padding_str = ' ' * padding
    
    centered_lines = [padding_str + line for line in lines]
    
    centered_text = '\n'.join(centered_lines)
    return get_midnight_gradient_text(centered_text)


def clear_screen():
    command = 'cls' if platform.system().lower() == 'windows' else 'clear'
    os.system(command)


def display_header():
    print(get_ascii_art_with_frame())
    print()
    print(get_author_info())
    print()


def pause_and_continue(message: str = None):
    if message is None:
        message_text = "\nPress Enter to continue..."
        message = get_midnight_gradient_text(message_text)
    input(message)


def gradient_print(*args, **kwargs):
    gradient_args = []
    for arg in args:
        if isinstance(arg, str):
            gradient_args.append(get_midnight_gradient_text(arg))
        else:
            gradient_args.append(get_midnight_gradient_text(str(arg)))
    
    print(*gradient_args, **kwargs)
