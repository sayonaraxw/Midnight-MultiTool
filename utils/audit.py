import datetime
from typing import Optional, Dict, Any

from .logger import default_logger


class AuditLogger:
    
    @staticmethod
    def log_encryption(
        operation_type: str,
        target: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        metadata_str = ""
        if metadata:
            safe_metadata = {k: v for k, v in metadata.items() 
                           if k not in ['password', 'key', 'salt']}
            if safe_metadata:
                metadata_str = f" | Metadata: {safe_metadata}"
        
        status = "SUCCESS" if success else "FAILED"
        log_message = (
            f"AUDIT | {operation_type.upper()} | Target: {target} | "
            f"Status: {status}{metadata_str}"
        )
        
        default_logger.info(log_message)
    
    @staticmethod
    def log_port_scan(
        target: str,
        ports_scanned: int,
        open_ports: int,
        duration: Optional[float] = None
    ) -> None:
        duration_str = f" | Duration: {duration:.2f}s" if duration else ""
        log_message = (
            f"AUDIT | PORT_SCAN | Target: {target} | "
            f"Ports scanned: {ports_scanned} | Open ports: {open_ports}{duration_str}"
        )
        
        default_logger.info(log_message)
    
    @staticmethod
    def log_file_access(
        operation: str,
        file_path: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        metadata_str = ""
        if metadata:
            metadata_str = f" | Metadata: {metadata}"
        
        status = "SUCCESS" if success else "FAILED"
        log_message = (
            f"AUDIT | FILE_ACCESS | Operation: {operation} | "
            f"File: {file_path} | Status: {status}{metadata_str}"
        )
        
        default_logger.info(log_message)
    
    @staticmethod
    def log_dns_query(
        query_type: str,
        domain: str,
        success: bool,
        result_count: Optional[int] = None,
        cached: Optional[bool] = None
    ) -> None:
        result_str = f" | Results: {result_count}" if result_count is not None else ""
        cache_str = f" | Cached: {cached}" if cached is not None else ""
        status = "SUCCESS" if success else "FAILED"
        log_message = (
            f"AUDIT | DNS_QUERY | Type: {query_type} | "
            f"Domain: {domain} | Status: {status}{result_str}{cache_str}"
        )
        
        default_logger.info(log_message)
    
    @staticmethod
    def log_network_operation(
        operation: str,
        target: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        metadata_str = ""
        if metadata:
            safe_metadata = {k: v for k, v in metadata.items() 
                           if k not in ['cookies', 'headers', 'auth']}
            if safe_metadata:
                metadata_str = f" | Metadata: {safe_metadata}"
        
        status = "SUCCESS" if success else "FAILED"
        log_message = (
            f"AUDIT | NETWORK | Operation: {operation} | "
            f"Target: {target} | Status: {status}{metadata_str}"
        )
        
        default_logger.info(log_message)


audit_logger = AuditLogger()
