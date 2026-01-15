"""
Dependency checking module.
Automatically checks for required packages on import.
"""

import sys
from typing import Dict, Tuple


REQUIRED_PACKAGES: Dict[str, Tuple[str, str]] = {
    'cryptography': ('cryptography', 'Core Encryption'),
    'requests': ('requests', 'Web Features (Cookies, Headers)'),
    'python-whois': ('whois', 'Whois Lookup'),
    'dnspython': ('dns.resolver', 'DNS Lookup'),
    'psutil': ('psutil', 'Process Listing & System Info'),
    'tqdm': ('tqdm', 'Progress Bars'),
}

OPTIONAL_PACKAGES: Dict[str, Tuple[str, str]] = {
    'pyyaml': ('yaml', 'YAML Configuration Files'),
}


def check_dependencies() -> bool:
    """
    Check if all required packages are installed.
    
    Returns:
        True if all dependencies are satisfied, False otherwise.
    """
    missing_packages = []
    
    for package_name, (import_name, description) in REQUIRED_PACKAGES.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append((package_name, description))
    
    if missing_packages:
        print("ERROR: Missing required packages:")
        for package_name, description in missing_packages:
            print(f"  - {package_name} ({description})")
        print("\nPlease install missing packages:")
        print(f"  pip install {' '.join([pkg[0] for pkg in missing_packages])}")
        return False
    
    return True


if not check_dependencies():
    sys.exit(1)
