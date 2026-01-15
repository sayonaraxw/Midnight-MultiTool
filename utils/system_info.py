"""
System information utilities.
"""

import platform
import socket
import sys
import psutil
from typing import Dict, List, Optional
from ui.colors import Colors


def get_system_info() -> Dict[str, str]:
    """
    Get basic system information.
    
    Returns:
        Dictionary with system information.
    """
    try:
        info = {
            'os_type': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'python_version': sys.version.split()[0],
        }
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            info['local_ip'] = local_ip
        except socket.gaierror:
            info['local_ip'] = 'Could not resolve hostname to IP'
        
        return info
    except Exception as e:
        gradient_print(f"Error retrieving system info: {e}")
        return {}


def display_system_info():
    """
    Display system information in formatted output.
    """
    gradient_print("--- System Information ---")
    info = get_system_info()
    
    try:
        gradient_print(f"{'OS Type':<20}: {info.get('os_type', 'N/A')}")
        gradient_print(f"{'OS Release':<20}: {info.get('os_release', 'N/A')}")
        gradient_print(f"{'OS Version':<20}: {info.get('os_version', 'N/A')}")
        gradient_print(f"{'Architecture':<20}: {info.get('architecture', 'N/A')}")
        gradient_print(f"{'Processor':<20}: {info.get('processor', 'N/A')}")
        gradient_print(f"{'Hostname':<20}: {info.get('hostname', 'N/A')}")
        
        local_ip = info.get('local_ip', 'N/A')
        gradient_print(f"{'Local IP (Guess)':<20}: {local_ip}")
        
        gradient_print(f"{'Python Version':<20}: {info.get('python_version', 'N/A')}")
        
        gradient_print("--- Resource Info (psutil) ---")
        cpu_count = psutil.cpu_count(logical=True)
        gradient_print(f"{'CPU Cores (Logical)':<20}: {cpu_count}")
        mem = psutil.virtual_memory()
        mem_total_gb = mem.total / (1024**3)
        gradient_print(f"{'Total RAM':<20}: {mem_total_gb:.2f} GB")
    except Exception as e:
        gradient_print(f"Error displaying system info: {e}")


def get_running_processes() -> List[Dict[str, any]]:
    """
    Get list of running processes.
    
    Returns:
        List of dictionaries with process information (pid, name, username).
    """
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'] or 'N/A',
                    'username': proc.info['username'] or 'N/A',
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as inner_e:
                gradient_print(f"Error processing PID {proc.pid}: {inner_e}")
    except Exception as e:
        gradient_print(f"Error retrieving process list: {e}")
    
    return processes


def list_running_processes():
    """
    Display running processes in formatted output.
    """
    gradient_print("--- Running Processes ---")
    gradient_print(f"{'PID':<8} {'Username':<15} {'Name'}")
    gradient_print("-" * 40)
    
    processes = get_running_processes()
    count = 0
    
    for proc in processes:
        pid = proc['pid']
        name = proc['name']
        username = proc['username']
        gradient_print(f"{pid:<8} {username[:15]:<15} {name[:40]}")
        count += 1
    
    gradient_print("-" * 40)
    gradient_print(f"Total processes listed: {count}")


def get_resource_usage() -> Dict[str, any]:
    """
    Get current resource usage information.
    
    Returns:
        Dictionary with CPU and memory usage information.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        
        return {
            'cpu_percent': cpu_percent,
            'memory_total': mem.total,
            'memory_available': mem.available,
            'memory_used': mem.used,
            'memory_percent': mem.percent,
        }
    except Exception as e:
        gradient_print(f"Error retrieving resource usage: {e}")
        return {}
