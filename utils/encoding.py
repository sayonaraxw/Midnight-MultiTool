"""
Encoding/decoding utilities for Base64 and Hex.
"""

import base64
import binascii
from typing import Optional
from ui.colors import Colors
from ui.display import gradient_print


def base64_encode(data: str) -> Optional[str]:
    """
    Encode data to Base64.
    
    Args:
        data: String data to encode
        
    Returns:
        Base64 encoded string or None on error.
    """
    try:
        if not data:
            gradient_print("Input data cannot be empty.")
            return None
        return base64.b64encode(data.encode()).decode()
    except Exception as e:
        gradient_print(f"[!] Encoding Error: {e}")
        return None


def base64_decode(data: str) -> Optional[str]:
    """
    Decode Base64 data.
    
    Args:
        data: Base64 encoded string
        
    Returns:
        Decoded string or None on error.
    """
    try:
        if not data:
            gradient_print("Input data cannot be empty.")
            return None
        return base64.b64decode(data.encode()).decode()
    except (binascii.Error, base64.binascii.Error, ValueError) as e:
        gradient_print(f"[!] Decoding Error: Invalid Base64 input data. {e}")
        return None
    except UnicodeDecodeError:
        gradient_print("[!] Decoding Error: Result is not valid text (binary data?).")
        return None
    except Exception as e:
        gradient_print(f"[!] An unexpected error occurred: {e}")
        return None


def hex_encode(data: str) -> Optional[str]:
    """
    Encode data to hexadecimal.
    
    Args:
        data: String data to encode
        
    Returns:
        Hexadecimal encoded string or None on error.
    """
    try:
        if not data:
            gradient_print("Input data cannot be empty.")
            return None
        return binascii.hexlify(data.encode()).decode()
    except Exception as e:
        gradient_print(f"[!] Encoding Error: {e}")
        return None


def hex_decode(data: str) -> Optional[str]:
    """
    Decode hexadecimal data.
    
    Args:
        data: Hexadecimal encoded string
        
    Returns:
        Decoded string or None on error.
    """
    try:
        if not data:
            gradient_print("Input data cannot be empty.")
            return None
        return binascii.unhexlify(data.encode()).decode()
    except (binascii.Error, ValueError) as e:
        gradient_print(f"[!] Decoding Error: Invalid hexadecimal input data. {e}")
        return None
    except UnicodeDecodeError:
        gradient_print("[!] Decoding Error: Result is not valid text (binary data?).")
        return None
    except Exception as e:
        gradient_print(f"[!] An unexpected error occurred: {e}")
        return None
