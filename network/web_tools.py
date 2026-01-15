import requests
from requests.exceptions import RequestException
from datetime import datetime
from typing import Optional, Dict
import whois
from whois import parser

from config import Config
from ui.colors import Colors
from ui.display import gradient_print, get_midnight_gradient_text
from utils.validators import validate_url, validate_domain
from utils.exceptions import ValidationError, NetworkError
from utils.logger import default_logger
from utils.audit import audit_logger


def get_http_headers(url: str) -> Optional[Dict[str, str]]:
    try:
        if not url.startswith(('http://', 'https://')):
            gradient_print("[!] URL scheme missing, attempting with 'https://'")
            url = 'https://' + url
        
        validate_url(url)
        
        headers = {'User-Agent': Config.USER_AGENT}
        gradient_print(f"Fetching headers from '{url}'...")
        
        response = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT, allow_redirects=True)
        
        gradient_print(f"--- Response Headers from {response.url} (Status: {response.status_code}) ---")
        if response.headers:
            for key, value in response.headers.items():
                gradient_print(f"{key:<25}: {value}")
        else:
            gradient_print("No headers received in the response.")
        gradient_print("------------------------------------------------------")
        
        audit_logger.log_network_operation("http_headers", url, True, {"status_code": response.status_code})
        
        return dict(response.headers)
    except ValidationError:
        audit_logger.log_network_operation("http_headers", url, False)
        raise
    except RequestException as e:
        default_logger.error(f"Network error retrieving headers from {url}: {e}")
        audit_logger.log_network_operation("http_headers", url, False)
        raise NetworkError(f"Could not retrieve headers: {e}") from e
    except Exception as e:
        default_logger.error(f"Unexpected error retrieving headers from {url}: {e}", exc_info=True)
        audit_logger.log_network_operation("http_headers", url, False)
        raise NetworkError(f"Failed to retrieve headers: {e}") from e


def get_website_cookies(url: str) -> Optional[Dict]:
    try:
        if not url.startswith(('http://', 'https://')):
            gradient_print("[!] URL scheme missing, attempting with 'https://'")
            url = 'https://' + url
        
        validate_url(url)
        
        headers = {'User-Agent': Config.USER_AGENT}
        gradient_print(f"Attempting connection to '{url}' to check cookies...")
        
        response = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT, allow_redirects=True)
        response.raise_for_status()
        
        cookie_count = len(response.cookies)
        if response.cookies:
            gradient_print(f"[+] Cookies received from {response.url} (Status: {response.status_code}):")
            for cookie in response.cookies:
                expires_str = "Session"
                if cookie.expires:
                    try:
                        expires_str = datetime.fromtimestamp(cookie.expires).strftime('%Y-%m-%d %H:%M:%S UTC')
                    except:
                        expires_str = str(cookie.expires)
                
                gradient_print(f"  - Name : {cookie.name}")
                gradient_print(f"    Value: {cookie.value}")
                gradient_print(f"    Domain: {cookie.domain}")
                gradient_print(f"    Path  : {cookie.path}")
                gradient_print(f"    Secure: {cookie.secure}")
                gradient_print(f"    Expires: {expires_str}")
                gradient_print("-" * 20)
        else:
            gradient_print("[-] No cookies were set by the server in this response.")
        
        audit_logger.log_network_operation("cookies", url, True, {"cookie_count": cookie_count, "status_code": response.status_code})
        
        return dict(response.cookies)
    except ValidationError:
        audit_logger.log_network_operation("cookies", url, False)
        raise
    except RequestException as e:
        default_logger.error(f"Network error retrieving cookies from {url}: {e}")
        audit_logger.log_network_operation("cookies", url, False)
        raise NetworkError(f"Could not retrieve cookies: {e}") from e
    except Exception as e:
        default_logger.error(f"Unexpected error retrieving cookies from {url}: {e}", exc_info=True)
        audit_logger.log_network_operation("cookies", url, False)
        raise NetworkError(f"Failed to retrieve cookies: {e}") from e


def perform_whois_lookup(domain: str) -> Optional[Dict]:
    try:
        gradient_print("--- Whois Domain Lookup ---")
        if not domain:
            raise ValidationError("Domain name cannot be empty.")
        
        validate_domain(domain)
        
        gradient_print(f"Querying WHOIS for '{domain}'...")
        w = whois.whois(domain)
        
        if w.status is None and not w.domain_name:
            default_logger.warning(f"Could not retrieve WHOIS data for {domain}")
            audit_logger.log_network_operation("whois", domain, False)
            gradient_print("Could not retrieve WHOIS data. Domain might not exist or WHOIS server unavailable.")
            if hasattr(w, 'text'):
                gradient_print(f"Raw Response Snippet:\n{w.text[:500]}...")
            raise NetworkError("Could not retrieve WHOIS data")
        
        gradient_print("--- WHOIS Information ---")
        for key, value in w.items():
            if key != 'text' and value:
                if isinstance(value, list):
                    gradient_print(f"{key.replace('_', ' ').title():<20}: {', '.join(map(str, value))}")
                else:
                    gradient_print(f"{key.replace('_', ' ').title():<20}: {value}")
        gradient_print("-------------------------")
        
        audit_logger.log_network_operation("whois", domain, True)
        
        return dict(w)
    except ValidationError:
        audit_logger.log_network_operation("whois", domain, False)
        raise
    except parser.PywhoisError as e:
        default_logger.error(f"WHOIS error for {domain}: {e}")
        audit_logger.log_network_operation("whois", domain, False)
        raise NetworkError(f"WHOIS lookup failed: {e}") from e
    except Exception as e:
        default_logger.error(f"Unexpected error during WHOIS lookup for {domain}: {e}", exc_info=True)
        audit_logger.log_network_operation("whois", domain, False)
        raise NetworkError(f"Failed to perform WHOIS lookup: {e}") from e


def get_http_headers_interactive():
    gradient_print("--- HTTP Header Viewer ---")
    url = input(get_midnight_gradient_text("Enter full URL (e.g., https://google.com): "))
    if not url:
        gradient_print("URL cannot be empty.")
        return
    get_http_headers(url)


def get_website_cookies_interactive():
    gradient_print("--- Website Cookie Viewer ---")
    url = input(get_midnight_gradient_text("Enter full URL (e.g., https://google.com): "))
    if not url:
        gradient_print("URL cannot be empty.")
        return
    get_website_cookies(url)


def perform_whois_lookup_interactive():
    domain = input(get_midnight_gradient_text("Enter domain name (e.g., google.com): "))
    perform_whois_lookup(domain)
