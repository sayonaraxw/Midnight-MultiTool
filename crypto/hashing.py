import os
import hashlib
from typing import Optional, Callable
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from config import Config
from ui.colors import Colors
from utils.validators import validate_file_path
from utils.exceptions import ValidationError, FileOperationError
from utils.logger import default_logger


def get_hash_algorithm(choice: str) -> Optional[Callable]:
    hash_algos = {
        '1': hashlib.md5,
        '2': hashlib.sha1,
        '3': hashlib.sha256,
        '4': hashlib.sha512,
    }
    return hash_algos.get(choice)


def calculate_hash_text(text: str, algorithm: str = 'sha256') -> Optional[str]:
    try:
        if not text:
            raise ValidationError("Input text cannot be empty.")
        
        algo_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }
        
        hasher = algo_map.get(algorithm.lower(), hashlib.sha256)()
        hasher.update(text.encode())
        return hasher.hexdigest()
    except ValidationError:
        raise
    except Exception as e:
        default_logger.error(f"Error during text hashing: {e}", exc_info=True)
        raise


def calculate_hash_file(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    try:
        validate_file_path(file_path, check_exists=True)
        
        algo_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }
        
        hasher = algo_map.get(algorithm.lower(), hashlib.sha256)()
        
        file_size = os.path.getsize(file_path)
        use_progress = tqdm is not None and file_size >= Config.STREAMING_THRESHOLD
        
        with open(file_path, 'rb') as f:
            if use_progress:
                with tqdm(total=file_size, desc="Hashing", unit="B", unit_scale=True) as pbar:
                    while True:
                        chunk = f.read(Config.CHUNK_SIZE)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        pbar.update(len(chunk))
            else:
                while True:
                    chunk = f.read(Config.CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
        
        return hasher.hexdigest()
    except ValidationError:
        raise
    except PermissionError as e:
        default_logger.error(f"Permission denied reading file '{file_path}'")
        raise FileOperationError(f"Permission denied reading file: {e}") from e
    except Exception as e:
        default_logger.error(f"Error during file hashing for '{file_path}': {e}", exc_info=True)
        raise FileOperationError(f"Failed to hash file: {e}") from e
