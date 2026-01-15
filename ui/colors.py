import sys
import os

class Colors:
    
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    CYAN = '\033[0;36m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'
    
    DARK_BLUE = '\033[0;34m'
    BRIGHT_BLUE = '\033[1;34m'
    PURPLE = '\033[0;35m'
    BRIGHT_PURPLE = '\033[1;35m'
    BRIGHT_CYAN = '\033[1;36m'
    SILVER = '\033[0;37m'
    BRIGHT_WHITE = '\033[1;37m'
    DARK_GRAY = '\033[1;30m'
    
    @classmethod
    def is_supported(cls) -> bool:
        
        if not sys.stdout.isatty():
            return False
        
        if os.getenv('NO_COLOR') or os.getenv('TERM') == 'dumb':
            return False
        
        return True
