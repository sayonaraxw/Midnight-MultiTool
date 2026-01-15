import re
from typing import Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json

from config import Config
from utils.exceptions import NetworkError
from utils.logger import default_logger


def compare_versions(version1: str, version2: str) -> int:
    def normalize_version(version: str) -> Tuple[int, ...]:
        parts = re.findall(r'\d+', version)
        return tuple(int(p) for p in parts) if parts else (0,)
    
    v1_parts = normalize_version(version1)
    v2_parts = normalize_version(version2)
    
    max_len = max(len(v1_parts), len(v2_parts))
    v1_parts = v1_parts + (0,) * (max_len - len(v1_parts))
    v2_parts = v2_parts + (0,) * (max_len - len(v2_parts))
    
    if v1_parts < v2_parts:
        return -1
    elif v1_parts > v2_parts:
        return 1
    else:
        return 0


def get_latest_version(github_repo: str) -> Optional[str]:
    """
    Get latest version from GitHub releases API.
    
    Args:
        github_repo: GitHub repository in format "owner/repo" (e.g., "Pyscodes-pro/EVIL-ENCRYPT")
        
    Returns:
        Latest version string, or None if not found or error occurred.
        
    Raises:
        NetworkError: If network request fails
    """
    try:
        if '/' not in github_repo:
            default_logger.warning(f"Invalid GitHub repository format: {github_repo}")
            return None
        
        owner, repo = github_repo.split('/', 1)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        
        request = Request(api_url)
        request.add_header('User-Agent', Config.USER_AGENT)
        
        with urlopen(request, timeout=Config.REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode('utf-8'))
            version = data.get('tag_name', '')
            
            if version.startswith('v'):
                version = version[1:]
            
            return version if version else None
            
    except HTTPError as e:
        default_logger.warning(f"HTTP error while checking for updates: {e.code}")
        raise NetworkError(f"Failed to check for updates: HTTP {e.code}") from e
    except URLError as e:
        default_logger.warning(f"URL error while checking for updates: {e.reason}")
        raise NetworkError(f"Failed to check for updates: {e.reason}") from e
    except json.JSONDecodeError as e:
        default_logger.warning(f"JSON decode error while checking for updates: {e}")
        return None
    except Exception as e:
        default_logger.error(f"Unexpected error while checking for updates: {e}", exc_info=True)
        raise NetworkError(f"Failed to check for updates: {e}") from e


def check_for_updates(github_repo: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if updates are available.
    
    Args:
        github_repo: GitHub repository in format "owner/repo".
                    If None, tries to extract from Config.GITHUB URL.
        
    Returns:
        Tuple of (is_update_available, current_version, latest_version).
        If error occurred, returns (False, current_version, None).
    """
    current_version = Config.VERSION
    
    if github_repo is None:
        github_url = Config.GITHUB
        if github_url:
            match = re.search(r'github\.com/([^/]+/[^/]+)', github_url)
            if match:
                github_repo = match.group(1)
            else:
                default_logger.warning(f"Could not extract repository from GitHub URL: {github_url}")
                return False, current_version, None
        else:
            default_logger.warning("GitHub repository not specified")
            return False, current_version, None
    
    try:
        latest_version = get_latest_version(github_repo)
        
        if latest_version is None:
            return False, current_version, None
        
        comparison = compare_versions(current_version, latest_version)
        is_update_available = comparison < 0
        
        return is_update_available, current_version, latest_version
        
    except NetworkError:
        return False, current_version, None
    except Exception as e:
        default_logger.error(f"Error checking for updates: {e}", exc_info=True)
        return False, current_version, None


def download_update(github_repo: str, output_path: str, asset_name: Optional[str] = None) -> bool:
    """
    Download latest release asset from GitHub (optional feature).
    
    Args:
        github_repo: GitHub repository in format "owner/repo"
        output_path: Path where to save downloaded file
        asset_name: Name of the asset to download. If None, downloads first asset.
        
    Returns:
        True if download successful, False otherwise.
        
    Raises:
        NetworkError: If network request fails
        FileOperationError: If file operations fail
    """
    try:
        if '/' not in github_repo:
            default_logger.error(f"Invalid GitHub repository format: {github_repo}")
            return False
        
        owner, repo = github_repo.split('/', 1)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        
        request = Request(api_url)
        request.add_header('User-Agent', Config.USER_AGENT)
        
        with urlopen(request, timeout=Config.REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode('utf-8'))
            assets = data.get('assets', [])
            
            if not assets:
                default_logger.error("No assets found in latest release")
                return False
            
            if asset_name:
                asset = next((a for a in assets if a['name'] == asset_name), None)
                if not asset:
                    default_logger.error(f"Asset '{asset_name}' not found in release")
                    return False
            else:
                asset = assets[0]
            
            download_url = asset['browser_download_url']
            
            download_request = Request(download_url)
            download_request.add_header('User-Agent', Config.USER_AGENT)
            
            with urlopen(download_request, timeout=Config.REQUEST_TIMEOUT) as download_response:
                with open(output_path, 'wb') as f:
                    f.write(download_response.read())
            
            default_logger.info(f"Successfully downloaded update to {output_path}")
            return True
            
    except HTTPError as e:
        default_logger.error(f"HTTP error while downloading update: {e.code}")
        raise NetworkError(f"Failed to download update: HTTP {e.code}") from e
    except URLError as e:
        default_logger.error(f"URL error while downloading update: {e.reason}")
        raise NetworkError(f"Failed to download update: {e.reason}") from e
    except Exception as e:
        default_logger.error(f"Error downloading update: {e}", exc_info=True)
        raise NetworkError(f"Failed to download update: {e}") from e
