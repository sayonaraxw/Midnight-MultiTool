"""
Input validation utilities.
"""

import os
import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse
from ui.colors import Colors
from utils.exceptions import ValidationError


def validate_file_path(file_path: str, check_exists: bool = False, check_writable: bool = False) -> None:
    """
    Validate file path.
    
    Args:
        file_path: Path to validate
        check_exists: Check if file exists
        check_writable: Check if file is writable (for output files)
        
    Raises:
        ValidationError: If validation fails.
    """
    if not file_path:
        raise ValidationError("File path cannot be empty.")
    
    if check_exists and not os.path.exists(file_path):
        raise ValidationError(f"File not found: '{file_path}'")
    
    if check_writable:
        directory = os.path.dirname(file_path) or '.'
        if not os.access(directory, os.W_OK):
            raise ValidationError(f"Permission denied: Cannot write to directory '{directory}'.")


def validate_port_range(start_port: int, end_port: int) -> None:
    """
    Validate port range.
    
    Args:
        start_port: Starting port number
        end_port: Ending port number
        
    Raises:
        ValidationError: If validation fails.
    """
    if not (0 < start_port <= 65535 and 0 < end_port <= 65535):
        raise ValidationError("Ports must be in range 1-65535.")
    
    if start_port > end_port:
        raise ValidationError("Start port must be less than or equal to end port.")


def validate_domain(domain: str) -> None:
    """
    Validate domain name format.
    
    Args:
        domain: Domain name to validate
        
    Raises:
        ValidationError: If validation fails.
    """
    if not domain:
        raise ValidationError("Domain name cannot be empty.")
    
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    if not domain_pattern.match(domain):
        raise ValidationError(f"Invalid domain format: '{domain}'.")


def validate_url(url: str) -> None:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Raises:
        ValidationError: If validation fails.
    """
    if not url:
        raise ValidationError("URL cannot be empty.")
    
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValidationError(f"Invalid URL format: '{url}'.")
    except Exception as e:
        raise ValidationError(f"Invalid URL format: '{url}'.") from e


def validate_ip_address(ip: str) -> None:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
        
    Raises:
        ValidationError: If validation fails.
    """
    if not ip:
        raise ValidationError("IP address cannot be empty.")
    
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address format: '{ip}'.") from e


def validate_password(password: str, min_length: int = 8) -> None:
    """
    Validate password basic requirements.
    
    Args:
        password: Password to validate
        min_length: Minimum length requirement
        
    Raises:
        ValidationError: If validation fails.
    """
    if not password:
        raise ValidationError("Password cannot be empty.")
    
    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters long.")
