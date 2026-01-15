"""
Error handling utilities for EVIL LOCK Multi-Tool.
"""

import functools
from typing import Callable, Any

from .logger import default_logger
from .exceptions import (
    ValidationError,
    EncryptionError,
    NetworkError,
    FileOperationError
)
from ui.colors import Colors


def handle_errors(
    show_to_user: bool = True,
    log_error: bool = True,
    reraise: bool = False
):
    """
    Decorator for centralized error handling.
    
    Args:
        show_to_user: Whether to display error message to user
        log_error: Whether to log the error
        reraise: Whether to re-raise the exception after handling
        
    Returns:
        Decorated function.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except ValidationError as e:
                if log_error:
                    default_logger.warning(f"Validation error in {func.__name__}: {e}")
                if show_to_user:
                    print(f"{Colors.RED}[!] Validation Error: {e}{Colors.NC}")
                if reraise:
                    raise
                return None
            except EncryptionError as e:
                if log_error:
                    default_logger.error(f"Encryption error in {func.__name__}: {e}", exc_info=True)
                if show_to_user:
                    print(f"{Colors.RED}[!] Encryption Error: {e}{Colors.NC}")
                if reraise:
                    raise
                return None
            except NetworkError as e:
                if log_error:
                    default_logger.error(f"Network error in {func.__name__}: {e}", exc_info=True)
                if show_to_user:
                    print(f"{Colors.RED}[!] Network Error: {e}{Colors.NC}")
                if reraise:
                    raise
                return None
            except FileOperationError as e:
                if log_error:
                    default_logger.error(f"File operation error in {func.__name__}: {e}", exc_info=True)
                if show_to_user:
                    print(f"{Colors.RED}[!] File Operation Error: {e}{Colors.NC}")
                if reraise:
                    raise
                return None
            except Exception as e:
                if log_error:
                    default_logger.error(
                        f"Unexpected error in {func.__name__}: {e}",
                        exc_info=True
                    )
                if show_to_user:
                    print(f"{Colors.RED}[!] Unexpected Error: {e}{Colors.NC}")
                if reraise:
                    raise
                return None
        return wrapper
    return decorator
