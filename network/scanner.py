import socket
import re
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from config import Config
from ui.colors import Colors
from ui.display import gradient_print, get_midnight_gradient_text
from utils.validators import validate_ip_address, validate_port_range
from utils.exceptions import ValidationError, NetworkError
from utils.logger import default_logger
from utils.audit import audit_logger


class PortScanner:
    
    def __init__(self, timeout: float = None, max_workers: int = None):
        self.timeout = timeout or Config.SCANNER_TIMEOUT
        self.max_workers = max_workers or Config.SCANNER_MAX_WORKERS
        socket.setdefaulttimeout(self.timeout)
    
    def scan_port(self, target_ip: str, port: int) -> bool:
        try:
            validate_ip_address(target_ip)
            if not (0 < port <= 65535):
                raise ValidationError(f"Port must be in range 1-65535, got {port}.")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except ValidationError:
            raise
        except socket.error as e:
            default_logger.debug(f"Socket error scanning {target_ip}:{port}: {e}")
            return False
        except Exception as e:
            default_logger.error(f"Unexpected error scanning port {port} on {target_ip}: {e}", exc_info=True)
            raise NetworkError(f"Failed to scan port {port} on {target_ip}: {e}") from e
    
    def scan_range(self, target_ip: str, start_port: int, end_port: int, use_parallel: bool = True) -> List[int]:
        try:
            validate_ip_address(target_ip)
            validate_port_range(start_port, end_port)
        except ValidationError:
            raise
        
        ports = list(range(start_port, end_port + 1))
        
        if use_parallel:
            return self.scan_port_parallel(target_ip, ports)
        else:
            open_ports = []
            start_time = datetime.now()
            
            for port in ports:
                try:
                    if self.scan_port(target_ip, port):
                        gradient_print(f"[+] Port {port}: Open")
                        open_ports.append(port)
                except KeyboardInterrupt:
                    gradient_print("\nScan aborted by user.")
                    break
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            audit_logger.log_port_scan(target_ip, len(ports), len(open_ports), duration)
            
            return open_ports
    
    def scan_common_ports(self, target_ip: str) -> List[int]:
        try:
            validate_ip_address(target_ip)
        except ValidationError:
            raise
        
        return self.scan_port_parallel(target_ip, Config.COMMON_PORTS)
    
    def scan_port_parallel(self, target_ip: str, ports: List[int], show_progress: bool = True) -> List[int]:
        try:
            validate_ip_address(target_ip)
        except ValidationError:
            raise
        
        open_ports = []
        open_ports_lock = Lock()
        start_time = datetime.now()
        
        def scan_and_collect(port: int) -> Optional[int]:
            try:
                if self.scan_port(target_ip, port):
                    with open_ports_lock:
                        open_ports.append(port)
                    return port
            except KeyboardInterrupt:
                return None
            except Exception:
                return None
            return None
        
        use_progress = show_progress and tqdm is not None
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                if use_progress:
                    futures = {executor.submit(scan_and_collect, port): port for port in ports}
                    with tqdm(total=len(ports), desc="Scanning ports", unit="port") as pbar:
                        for future in as_completed(futures):
                            pbar.update(1)
                            try:
                                future.result()
                            except Exception:
                                pass
                else:
                    futures = [executor.submit(scan_and_collect, port) for port in ports]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass
        except KeyboardInterrupt:
            gradient_print("\nScan aborted by user.")
        
        for port in sorted(open_ports):
            gradient_print(f"[+] Port {port}: Open")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        audit_logger.log_port_scan(target_ip, len(ports), len(open_ports), duration)
        
        return sorted(open_ports)


def _clean_target_input(target: str) -> str:
    target = target.strip()
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]
    target = target.rstrip('/')
    return target


def perform_port_scan():
    gradient_print("--- Basic Port Scanner ---")
    gradient_print("WARNING: Unauthorized scanning is illegal and unethical.")
    gradient_print("Only scan targets you have explicit permission to test.")
    
    target = input(get_midnight_gradient_text("Enter target IP Address or Hostname: "))
    if not target:
        gradient_print("Target cannot be empty.")
        return
    
    target = _clean_target_input(target)
    
    try:
        target_ip = socket.gethostbyname(target)
        gradient_print(f"Resolved '{target}' to IP: {target_ip}")
    except socket.gaierror:
        gradient_print(f"Could not resolve hostname '{target}'. Check the name or your network connection.")
        return
    except Exception as e:
        gradient_print(f"Error resolving hostname: {e}")
        return
    
    port_range_str = input(get_midnight_gradient_text("Enter port range (e.g., 1-1024) or common ports (c): "))
    ports_to_scan = []
    
    if port_range_str.lower() == 'c':
        ports_to_scan = Config.COMMON_PORTS
        gradient_print("Scanning common ports...")
    else:
        try:
            start_port, end_port = map(int, port_range_str.split('-'))
            validate_port_range(start_port, end_port)
            ports_to_scan = list(range(start_port, end_port + 1))
            gradient_print(f"Scanning ports {start_port}-{end_port}...")
        except ValueError as e:
            gradient_print("Invalid port range format. Use start-end (e.g., 80-100).")
            default_logger.warning(f"Invalid port range format: {port_range_str}")
            return
        except ValidationError as e:
            gradient_print(str(e))
            return
    
    scanner = PortScanner()
    
    gradient_print(f"Starting parallel scan on {target_ip}...")
    gradient_print(f"Using {scanner.max_workers} worker threads")
    
    open_ports = scanner.scan_port_parallel(target_ip, ports_to_scan, show_progress=True)
    
    gradient_print("\nScan Complete.")
    if open_ports:
        gradient_print(f"Open ports found: {', '.join(map(str, sorted(open_ports)))}")
    else:
        gradient_print("No open ports found in the specified range.")


class ServiceInfo:
    def __init__(self, service_name: str, version: str = "", banner: str = ""):
        self.service_name = service_name
        self.version = version
        self.banner = banner
    
    def __str__(self) -> str:
        if self.version:
            return f"{self.service_name} ({self.version})"
        elif self.banner:
            return f"UNKNOWN (banner: \"{self.banner[:50]}\")"
        else:
            return self.service_name


class SmartPortScanner:
    
    SERVICE_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'MSRPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
    }
    
    def __init__(self, timeout: float = None, max_workers: int = None, banner_timeout: float = 2.0):
        self.timeout = timeout or Config.SCANNER_TIMEOUT
        self.banner_timeout = banner_timeout
        self.max_workers = max_workers or Config.SCANNER_MAX_WORKERS
        socket.setdefaulttimeout(self.timeout)
    
    def grab_banner(self, target_ip: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.banner_timeout)
            sock.connect((target_ip, port))
            
            banner = ""
            
            if port == 22:
                try:
                    sock.settimeout(2.0)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
            
            elif port in [80, 443, 8080, 8443]:
                try:
                    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {Config.USER_AGENT}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    sock.settimeout(2.0)
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
                    if server_match:
                        banner = server_match.group(1).strip()
                    elif response:
                        banner = response.split('\n')[0].strip()[:100]
                except Exception:
                    pass
            
            elif port == 21:
                try:
                    sock.settimeout(2.0)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
            
            elif port == 25:
                try:
                    sock.settimeout(2.0)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
            
            else:
                try:
                    sock.settimeout(1.0)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass
                except Exception:
                    pass
            
            sock.close()
            return banner[:200]  # Limit banner length
        except Exception:
            return ""
    
    def detect_service(self, target_ip: str, port: int) -> ServiceInfo:
        service_name = self.SERVICE_PORTS.get(port, "UNKNOWN")
        
        banner = self.grab_banner(target_ip, port)
        
        version = ""
        
        if banner:
            version = self._extract_version(service_name, banner)
        
        if banner and not version and service_name == "UNKNOWN":
            service_name = self._identify_from_banner(banner)
        
        return ServiceInfo(service_name, version, banner)
    
    def _extract_version(self, service_name: str, banner: str) -> str:
        version_patterns = {
            'SSH': [
                r'SSH-[\d.]+-OpenSSH[_\s]+([\d.]+[^\s]*)',
                r'SSH-[\d.]+-([^\s]+)',
                r'OpenSSH[_\s]+([\d.]+[^\s]*)',
                r'([\d.]+[^\s]*)\s*OpenSSH',
            ],
            'HTTP': [
                r'nginx/([\d.]+)',
                r'Apache/([\d.]+)',
                r'Microsoft-IIS/([\d.]+)',
                r'Server:\s*([^\r\n]+)',
            ],
            'HTTPS': [
                r'nginx/([\d.]+)',
                r'Apache/([\d.]+)',
                r'Microsoft-IIS/([\d.]+)',
                r'Server:\s*([^\r\n]+)',
            ],
            'FTP': [
                r'([\d.]+)\s+FTP',
                r'FTP\s+([\d.]+)',
                r'\(([^)]+FTP[^)]*)\)',
            ],
            'SMTP': [
                r'([\d.]+)\s+ESMTP',
                r'ESMTP\s+([\d.]+)',
                r'Postfix\s+\(([^)]+)\)',
            ],
        }
        
        patterns = version_patterns.get(service_name, [])
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                version = re.sub(r'\s+', ' ', version)
                return version
        
        return ""
    
    def _identify_from_banner(self, banner: str) -> str:
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower or 'openssh' in banner_lower:
            return 'SSH'
        elif 'http' in banner_lower or 'apache' in banner_lower or 'nginx' in banner_lower:
            return 'HTTP'
        elif 'ftp' in banner_lower:
            return 'FTP'
        elif 'smtp' in banner_lower or 'esmtp' in banner_lower:
            return 'SMTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'jboss' in banner_lower:
            return 'JBoss'
        elif 'tomcat' in banner_lower:
            return 'Tomcat'
        elif 'iis' in banner_lower:
            return 'IIS'
        
        return 'UNKNOWN'
    
    def scan_port_with_service(self, target_ip: str, port: int) -> Optional[Tuple[int, ServiceInfo]]:
        try:
            validate_ip_address(target_ip)
            if not (0 < port <= 65535):
                return None
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                service_info = self.detect_service(target_ip, port)
                return (port, service_info)
            return None
        except Exception as e:
            default_logger.debug(f"Error scanning {target_ip}:{port}: {e}")
            return None
    
    def scan_ports_smart(self, target_ip: str, ports: List[int], show_progress: bool = True) -> Dict[int, ServiceInfo]:
        try:
            validate_ip_address(target_ip)
        except ValidationError:
            raise
        
        results = {}
        results_lock = Lock()
        start_time = datetime.now()
        
        def scan_and_detect(port: int) -> Optional[Tuple[int, ServiceInfo]]:
            try:
                result = self.scan_port_with_service(target_ip, port)
                if result:
                    port_num, service_info = result
                    with results_lock:
                        results[port_num] = service_info
                    return result
            except KeyboardInterrupt:
                return None
            except Exception:
                return None
            return None
        
        use_progress = show_progress and tqdm is not None
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                if use_progress:
                    futures = {executor.submit(scan_and_detect, port): port for port in ports}
                    with tqdm(total=len(ports), desc="Scanning ports", unit="port") as pbar:
                        for future in as_completed(futures):
                            pbar.update(1)
                            try:
                                future.result()
                            except Exception:
                                pass
                else:
                    futures = [executor.submit(scan_and_detect, port) for port in ports]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass
        except KeyboardInterrupt:
            gradient_print("\nScan aborted by user.")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        audit_logger.log_port_scan(target_ip, len(ports), len(results), duration)
        
        return results
    
    def scan_range_smart(self, target_ip: str, start_port: int, end_port: int, show_progress: bool = True) -> Dict[int, ServiceInfo]:
        try:
            validate_ip_address(target_ip)
            validate_port_range(start_port, end_port)
        except ValidationError:
            raise
        
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports_smart(target_ip, ports, show_progress)


def perform_smart_port_scan():
    gradient_print("--- Smart Port Scanner ---")
    gradient_print("WARNING: Unauthorized scanning is illegal and unethical.")
    gradient_print("Only scan targets you have explicit permission to test.")
    
    target = input(get_midnight_gradient_text("Enter target IP Address or Hostname: "))
    if not target:
        gradient_print("Target cannot be empty.")
        return
    
    target = _clean_target_input(target)
    
    try:
        target_ip = socket.gethostbyname(target)
        gradient_print(f"Resolved '{target}' to IP: {target_ip}")
    except socket.gaierror:
        gradient_print(f"Could not resolve hostname '{target}'. Check the name or your network connection.")
        return
    except Exception as e:
        gradient_print(f"Error resolving hostname: {e}")
        return
    
    port_range_str = input(get_midnight_gradient_text("Enter port range (e.g., 1-1000) or common ports (c): "))
    ports_to_scan = []
    
    if port_range_str.lower() == 'c':
        ports_to_scan = Config.COMMON_PORTS
        gradient_print("Scanning common ports...")
    else:
        try:
            start_port, end_port = map(int, port_range_str.split('-'))
            validate_port_range(start_port, end_port)
            ports_to_scan = list(range(start_port, end_port + 1))
            gradient_print(f"Scanning ports {start_port}-{end_port}...")
        except ValueError:
            gradient_print("Invalid port range format. Use start-end (e.g., 1-1000).")
            return
        except ValidationError as e:
            gradient_print(str(e))
            return
    
    scanner = SmartPortScanner()
    
    gradient_print(f"Starting smart scan on {target_ip}...")
    gradient_print(f"Using {scanner.max_workers} worker threads")
    gradient_print("Detecting services and grabbing banners...\n")
    
    if port_range_str.lower() == 'c':
        results = scanner.scan_ports_smart(target_ip, ports_to_scan, show_progress=True)
    else:
        start_port, end_port = ports_to_scan[0], ports_to_scan[-1]
        results = scanner.scan_range_smart(target_ip, start_port, end_port, show_progress=True)
    
    gradient_print("\n" + "="*70)
    gradient_print("Scan Results:")
    gradient_print("="*70)
    
    if results:
        for port in sorted(results.keys()):
            service_info = results[port]
            if service_info.version:
                gradient_print(f"[+] {port}/tcp: {service_info.service_name} ({service_info.version})")
            elif service_info.banner and service_info.service_name == "UNKNOWN":
                banner_display = service_info.banner[:60] + "..." if len(service_info.banner) > 60 else service_info.banner
                gradient_print(f"[-] {port}/tcp: {service_info.service_name} (banner: \"{banner_display}\")")
            elif service_info.banner:
                banner_display = service_info.banner[:60] + "..." if len(service_info.banner) > 60 else service_info.banner
                gradient_print(f"[+] {port}/tcp: {service_info.service_name} (banner: \"{banner_display}\")")
            else:
                gradient_print(f"[+] {port}/tcp: {service_info.service_name}")
    else:
        gradient_print("[-] No open ports found in the specified range.")
    
    gradient_print("="*70)
    gradient_print(f"\nScan Complete. Found {len(results)} open port(s).")
