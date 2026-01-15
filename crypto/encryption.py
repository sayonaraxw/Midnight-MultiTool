import os
import base64
import gc
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from config import Config
from ui.colors import Colors
from utils.validators import validate_file_path
from utils.exceptions import ValidationError, EncryptionError, FileOperationError
from utils.logger import default_logger
from utils.audit import audit_logger


class EncryptionService:
    
    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(Config.SALT_SIZE)
    
    @staticmethod
    def derive_key(password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=Config.KEY_LENGTH,
            salt=salt,
            iterations=Config.ENCRYPTION_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    @staticmethod
    def encrypt_message(password: str, message: str) -> Optional[str]:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            if not message:
                raise ValidationError("Message cannot be empty.")
            
            salt = EncryptionService.generate_salt()
            key = EncryptionService.derive_key(password.encode(), salt)
            f = Fernet(key)
            encrypted_message = f.encrypt(message.encode())
            result = base64.urlsafe_b64encode(salt + encrypted_message).decode()
            
            audit_logger.log_encryption("encrypt", "message", True)
            
            password = None
            del password
            gc.collect()
            
            return result
        except ValidationError:
            audit_logger.log_encryption("encrypt", "message", False)
            raise
        except Exception as e:
            default_logger.error(f"Encryption error (message): {e}", exc_info=True)
            audit_logger.log_encryption("encrypt", "message", False)
            raise EncryptionError(f"Failed to encrypt message: {e}") from e
    
    @staticmethod
    def decrypt_message(password: str, encrypted_data_b64: str) -> Optional[str]:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            if not encrypted_data_b64:
                raise ValidationError("Encrypted data cannot be empty.")
            
            encrypted_data = base64.urlsafe_b64decode(encrypted_data_b64.encode())
            salt = encrypted_data[:Config.SALT_SIZE]
            token = encrypted_data[Config.SALT_SIZE:]
            key = EncryptionService.derive_key(password.encode(), salt)
            f = Fernet(key)
            decrypted_message = f.decrypt(token).decode()
            
            audit_logger.log_encryption("decrypt", "message", True)
            
            password = None
            del password
            gc.collect()
            
            return decrypted_message
        except InvalidToken:
            default_logger.error("Decryption error (message): Invalid key or corrupted data")
            audit_logger.log_encryption("decrypt", "message", False)
            raise EncryptionError("Invalid key or corrupted data") from None
        except ValidationError:
            audit_logger.log_encryption("decrypt", "message", False)
            raise
        except Exception as e:
            default_logger.error(f"Decryption error (message): {e}", exc_info=True)
            audit_logger.log_encryption("decrypt", "message", False)
            raise EncryptionError(f"Failed to decrypt message: {e}") from e
    
    @staticmethod
    def encrypt_file(password: str, input_filepath: str, output_filepath: str) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            validate_file_path(input_filepath, check_exists=True)
            validate_file_path(output_filepath, check_writable=True)
            
            file_size = os.path.getsize(input_filepath)
            use_streaming = file_size >= Config.STREAMING_THRESHOLD
            
            if use_streaming:
                return EncryptionService.encrypt_file_streaming(password, input_filepath, output_filepath)
            
            salt = EncryptionService.generate_salt()
            key = EncryptionService.derive_key(password.encode(), salt)
            f = Fernet(key)
            
            with open(input_filepath, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = f.encrypt(file_data)
            
            with open(output_filepath, 'wb') as file:
                file.write(salt)
                file.write(encrypted_data)
            
            audit_logger.log_encryption("encrypt", input_filepath, True, {"file_size": file_size})
            audit_logger.log_file_access("write", output_filepath, True)
            
            password = None
            del password
            gc.collect()
            
            return True
        except ValidationError:
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise
        except FileNotFoundError as e:
            default_logger.error(f"Encryption error (file): Input file not found: '{input_filepath}'")
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise FileOperationError(f"Input file not found: '{input_filepath}'") from e
        except PermissionError as e:
            default_logger.error(f"Encryption error (file): Permission denied for '{input_filepath}' or '{output_filepath}'")
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise FileOperationError(f"Permission denied for '{input_filepath}' or '{output_filepath}'") from e
        except Exception as e:
            default_logger.error(f"Encryption error (file): {e}", exc_info=True)
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise EncryptionError(f"Failed to encrypt file: {e}") from e
    
    @staticmethod
    def encrypt_file_streaming(password: str, input_filepath: str, output_filepath: str) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            salt = EncryptionService.generate_salt()
            key = EncryptionService.derive_key(password.encode(), salt)
            f = Fernet(key)
            
            file_size = os.path.getsize(input_filepath)
            use_progress = tqdm is not None
            
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                outfile.write(salt)
                
                if use_progress:
                    with tqdm(total=file_size, desc="Encrypting", unit="B", unit_scale=True) as pbar:
                        while True:
                            chunk = infile.read(Config.CHUNK_SIZE)
                            if not chunk:
                                break
                            encrypted_chunk = f.encrypt(chunk)
                            outfile.write(len(encrypted_chunk).to_bytes(4, byteorder='big'))
                            outfile.write(encrypted_chunk)
                            pbar.update(len(chunk))
                else:
                    while True:
                        chunk = infile.read(Config.CHUNK_SIZE)
                        if not chunk:
                            break
                        encrypted_chunk = f.encrypt(chunk)
                        outfile.write(len(encrypted_chunk).to_bytes(4, byteorder='big'))
                        outfile.write(encrypted_chunk)
            
            audit_logger.log_encryption("encrypt", input_filepath, True, {"file_size": file_size, "streaming": True})
            audit_logger.log_file_access("write", output_filepath, True)
            
            password = None
            del password
            gc.collect()
            
            return True
        except ValidationError:
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise
        except FileNotFoundError as e:
            default_logger.error(f"Encryption error (file): Input file not found: '{input_filepath}'")
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise FileOperationError(f"Input file not found: '{input_filepath}'") from e
        except PermissionError as e:
            default_logger.error(f"Encryption error (file): Permission denied for '{input_filepath}' or '{output_filepath}'")
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise FileOperationError(f"Permission denied for '{input_filepath}' or '{output_filepath}'") from e
        except Exception as e:
            default_logger.error(f"Encryption error (file): {e}", exc_info=True)
            audit_logger.log_encryption("encrypt", input_filepath, False)
            raise EncryptionError(f"Failed to encrypt file: {e}") from e
    
    @staticmethod
    def decrypt_file(password: str, input_filepath: str, output_filepath: str) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            validate_file_path(input_filepath, check_exists=True)
            validate_file_path(output_filepath, check_writable=True)
            
            file_size = os.path.getsize(input_filepath)
            use_streaming = file_size >= Config.STREAMING_THRESHOLD
            
            if use_streaming:
                return EncryptionService.decrypt_file_streaming(password, input_filepath, output_filepath)
            
            with open(input_filepath, 'rb') as file:
                salt = file.read(Config.SALT_SIZE)
                encrypted_data = file.read()
            
            key = EncryptionService.derive_key(password.encode(), salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            with open(output_filepath, 'wb') as file:
                file.write(decrypted_data)
            
            file_size = len(decrypted_data)
            audit_logger.log_encryption("decrypt", input_filepath, True, {"file_size": file_size})
            audit_logger.log_file_access("write", output_filepath, True)
            
            password = None
            del password
            gc.collect()
            
            return True
        except InvalidToken:
            default_logger.error(f"Decryption error (file): Invalid key or corrupted data in '{input_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise EncryptionError(f"Invalid key or corrupted data in '{input_filepath}'") from None
        except ValidationError:
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise
        except FileNotFoundError as e:
            default_logger.error(f"Decryption error (file): Input file not found: '{input_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise FileOperationError(f"Input file not found: '{input_filepath}'") from e
        except PermissionError as e:
            default_logger.error(f"Decryption error (file): Permission denied for '{input_filepath}' or '{output_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise FileOperationError(f"Permission denied for '{input_filepath}' or '{output_filepath}'") from e
        except Exception as e:
            default_logger.error(f"Decryption error (file): {e}", exc_info=True)
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise EncryptionError(f"Failed to decrypt file: {e}") from e
    
    @staticmethod
    def decrypt_file_streaming(password: str, input_filepath: str, output_filepath: str) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            file_size = os.path.getsize(input_filepath)
            use_progress = tqdm is not None
            
            with open(input_filepath, 'rb') as infile:
                salt = infile.read(Config.SALT_SIZE)
                if len(salt) != Config.SALT_SIZE:
                    raise EncryptionError("Invalid encrypted file: salt missing or corrupted")
                
                key = EncryptionService.derive_key(password.encode(), salt)
                f = Fernet(key)
                
                estimated_size = file_size - Config.SALT_SIZE
                
                with open(output_filepath, 'wb') as outfile:
                    total_decrypted = 0
                    if use_progress:
                        with tqdm(total=estimated_size, desc="Decrypting", unit="B", unit_scale=True) as pbar:
                            while True:
                                size_bytes = infile.read(4)
                                if not size_bytes or len(size_bytes) < 4:
                                    break
                                
                                chunk_size = int.from_bytes(size_bytes, byteorder='big')
                                encrypted_chunk = infile.read(chunk_size)
                                
                                if not encrypted_chunk or len(encrypted_chunk) < chunk_size:
                                    break
                                
                                try:
                                    decrypted_chunk = f.decrypt(encrypted_chunk)
                                    outfile.write(decrypted_chunk)
                                    total_decrypted += len(decrypted_chunk)
                                    pbar.update(len(decrypted_chunk))
                                except InvalidToken:
                                    default_logger.error(f"Decryption error: Invalid token in chunk")
                                    raise EncryptionError("Invalid key or corrupted data") from None
                    else:
                        while True:
                            size_bytes = infile.read(4)
                            if not size_bytes or len(size_bytes) < 4:
                                break
                            
                            chunk_size = int.from_bytes(size_bytes, byteorder='big')
                            encrypted_chunk = infile.read(chunk_size)
                            
                            if not encrypted_chunk or len(encrypted_chunk) < chunk_size:
                                break
                            
                            try:
                                decrypted_chunk = f.decrypt(encrypted_chunk)
                                outfile.write(decrypted_chunk)
                                total_decrypted += len(decrypted_chunk)
                            except InvalidToken:
                                default_logger.error(f"Decryption error: Invalid token in chunk")
                                raise EncryptionError("Invalid key or corrupted data") from None
            
            audit_logger.log_encryption("decrypt", input_filepath, True, {"file_size": file_size, "streaming": True, "decrypted_size": total_decrypted})
            audit_logger.log_file_access("write", output_filepath, True)
            
            password = None
            del password
            gc.collect()
            
            return True
        except InvalidToken:
            default_logger.error(f"Decryption error (file): Invalid key or corrupted data in '{input_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise EncryptionError(f"Invalid key or corrupted data in '{input_filepath}'") from None
        except ValidationError:
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise
        except FileNotFoundError as e:
            default_logger.error(f"Decryption error (file): Input file not found: '{input_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise FileOperationError(f"Input file not found: '{input_filepath}'") from e
        except PermissionError as e:
            default_logger.error(f"Decryption error (file): Permission denied for '{input_filepath}' or '{output_filepath}'")
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise FileOperationError(f"Permission denied for '{input_filepath}' or '{output_filepath}'") from e
        except Exception as e:
            default_logger.error(f"Decryption error (file): {e}", exc_info=True)
            audit_logger.log_encryption("decrypt", input_filepath, False)
            raise EncryptionError(f"Failed to decrypt file: {e}") from e
    
    @staticmethod
    def encrypt_directory(password: str, directory_path: str, output_directory: str, 
                         preserve_structure: bool = True) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            if not os.path.isdir(directory_path):
                raise ValidationError(f"Directory does not exist: '{directory_path}'")
            
            os.makedirs(output_directory, exist_ok=True)
            
            encrypted_count = 0
            failed_count = 0
            
            for root, dirs, files in os.walk(directory_path):
                rel_path = os.path.relpath(root, directory_path)
                
                if preserve_structure:
                    if rel_path == '.':
                        output_dir = output_directory
                    else:
                        output_dir = os.path.join(output_directory, rel_path)
                    os.makedirs(output_dir, exist_ok=True)
                else:
                    output_dir = output_directory
                
                for filename in files:
                    input_file = os.path.join(root, filename)
                    output_file = os.path.join(output_dir, filename + '.encrypted')
                    
                    try:
                        EncryptionService.encrypt_file(password, input_file, output_file)
                        encrypted_count += 1
                        default_logger.debug(f"Encrypted: {input_file} -> {output_file}")
                    except Exception as e:
                        failed_count += 1
                        default_logger.warning(f"Failed to encrypt {input_file}: {e}")
            
            audit_logger.log_encryption(
                "encrypt", 
                directory_path, 
                True, 
                {
                    "encrypted_count": encrypted_count,
                    "failed_count": failed_count,
                    "preserve_structure": preserve_structure
                }
            )
            
            default_logger.info(
                f"Directory encryption complete: {encrypted_count} files encrypted, "
                f"{failed_count} files failed"
            )
            
            password = None
            del password
            gc.collect()
            
            return encrypted_count > 0
            
        except ValidationError:
            audit_logger.log_encryption("encrypt", directory_path, False)
            raise
        except Exception as e:
            default_logger.error(f"Directory encryption error: {e}", exc_info=True)
            audit_logger.log_encryption("encrypt", directory_path, False)
            raise EncryptionError(f"Failed to encrypt directory: {e}") from e
    
    @staticmethod
    def decrypt_directory(password: str, directory_path: str, output_directory: str,
                         preserve_structure: bool = True) -> bool:
        try:
            if not password:
                raise ValidationError("Password cannot be empty.")
            
            if not os.path.isdir(directory_path):
                raise ValidationError(f"Directory does not exist: '{directory_path}'")
            
            os.makedirs(output_directory, exist_ok=True)
            
            decrypted_count = 0
            failed_count = 0
            
            for root, dirs, files in os.walk(directory_path):
                rel_path = os.path.relpath(root, directory_path)
                
                if preserve_structure:
                    if rel_path == '.':
                        output_dir = output_directory
                    else:
                        output_dir = os.path.join(output_directory, rel_path)
                    os.makedirs(output_dir, exist_ok=True)
                else:
                    output_dir = output_directory
                
                for filename in files:
                    if not filename.endswith('.encrypted'):
                        continue
                    
                    input_file = os.path.join(root, filename)
                    original_filename = filename[:-10]
                    output_file = os.path.join(output_dir, original_filename)
                    
                    try:
                        EncryptionService.decrypt_file(password, input_file, output_file)
                        decrypted_count += 1
                        default_logger.debug(f"Decrypted: {input_file} -> {output_file}")
                    except Exception as e:
                        failed_count += 1
                        default_logger.warning(f"Failed to decrypt {input_file}: {e}")
            
            audit_logger.log_encryption(
                "decrypt", 
                directory_path, 
                True, 
                {
                    "decrypted_count": decrypted_count,
                    "failed_count": failed_count,
                    "preserve_structure": preserve_structure
                }
            )
            
            default_logger.info(
                f"Directory decryption complete: {decrypted_count} files decrypted, "
                f"{failed_count} files failed"
            )
            
            password = None
            del password
            gc.collect()
            
            return decrypted_count > 0
            
        except ValidationError:
            audit_logger.log_encryption("decrypt", directory_path, False)
            raise
        except Exception as e:
            default_logger.error(f"Directory decryption error: {e}", exc_info=True)
            audit_logger.log_encryption("decrypt", directory_path, False)
            raise EncryptionError(f"Failed to decrypt directory: {e}") from e
