import os
import json
from typing import Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class Config:
    
    VERSION = "1.0.0"
    AUTHOR = "sayonara"
    GITHUB = "https://github.com/sayonaraxw"
    DESCRIPTION = "Advanced Multi-Tool Suite for Security & Network Operations"
    
    ENCRYPTION_ITERATIONS = 480000
    SALT_SIZE = 16
    KEY_LENGTH = 32
    
    SCANNER_TIMEOUT = 0.5
    SCANNER_MAX_WORKERS = 100
    DNS_CACHE_TTL = 300
    
    CHUNK_SIZE = 64 * 1024
    STREAMING_THRESHOLD = 10 * 1024 * 1024
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    HASH_ALGORITHMS = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha256',
        '4': 'sha512',
    }
    
    DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
    
    REQUEST_TIMEOUT = 10
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    LOG_FILE = "evil_lock.log"
    LOG_LEVEL = "INFO"
    LOG_MAX_SIZE_MB = 10
    
    COLORS_ENABLED = True
    SHOW_PROGRESS = True
    PROGRESS_BAR_STYLE = "default"
    
    _loaded_config: Optional[Dict[str, Any]] = None
    
    @classmethod
    def load_config(cls, config_file: str = "config.yaml") -> bool:
        if not os.path.exists(config_file):
            return False
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.json'):
                    cls._loaded_config = json.load(f)
                elif config_file.endswith(('.yaml', '.yml')):
                    if not YAML_AVAILABLE:
                        return False
                    cls._loaded_config = yaml.safe_load(f)
                else:
                    return False
            
            cls._apply_config(cls._loaded_config)
            return True
        except Exception:
            return False
    
    @classmethod
    def _apply_config(cls, config: Dict[str, Any]) -> None:
        if not config:
            return
        
        if 'encryption' in config:
            enc = config['encryption']
            if 'iterations' in enc:
                cls.ENCRYPTION_ITERATIONS = int(enc['iterations'])
            if 'salt_size' in enc:
                cls.SALT_SIZE = int(enc['salt_size'])
            if 'key_length' in enc:
                cls.KEY_LENGTH = int(enc['key_length'])
        
        if 'network' in config:
            net = config['network']
            if 'timeout' in net:
                cls.SCANNER_TIMEOUT = float(net['timeout'])
            if 'max_workers' in net:
                cls.SCANNER_MAX_WORKERS = int(net['max_workers'])
            if 'dns_cache_ttl' in net:
                cls.DNS_CACHE_TTL = int(net['dns_cache_ttl'])
        
        if 'file_processing' in config:
            fp = config['file_processing']
            if 'chunk_size' in fp:
                cls.CHUNK_SIZE = int(fp['chunk_size'])
            if 'streaming_threshold' in fp:
                cls.STREAMING_THRESHOLD = int(fp['streaming_threshold'])
        
        if 'ui' in config:
            ui = config['ui']
            if 'colors_enabled' in ui:
                cls.COLORS_ENABLED = bool(ui['colors_enabled'])
            if 'show_progress' in ui:
                cls.SHOW_PROGRESS = bool(ui['show_progress'])
            if 'progress_bar_style' in ui:
                cls.PROGRESS_BAR_STYLE = str(ui['progress_bar_style'])
        
        if 'logging' in config:
            log = config['logging']
            if 'level' in log:
                cls.LOG_LEVEL = str(log['level'])
            if 'file' in log:
                cls.LOG_FILE = str(log['file'])
            if 'max_size_mb' in log:
                cls.LOG_MAX_SIZE_MB = int(log['max_size_mb'])
    
    @classmethod
    def get_config(cls, key_path: str, default: Any = None) -> Any:
        if not cls._loaded_config:
            return default
        
        keys = key_path.split('.')
        value = cls._loaded_config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        if not isinstance(config, dict):
            return False, "Configuration must be a dictionary"
        
        if 'encryption' in config:
            enc = config['encryption']
            if 'iterations' in enc and not isinstance(enc['iterations'], int):
                return False, "encryption.iterations must be an integer"
            if 'salt_size' in enc and not isinstance(enc['salt_size'], int):
                return False, "encryption.salt_size must be an integer"
        
        if 'network' in config:
            net = config['network']
            if 'timeout' in net and not isinstance(net['timeout'], (int, float)):
                return False, "network.timeout must be a number"
            if 'max_workers' in net and not isinstance(net['max_workers'], int):
                return False, "network.max_workers must be an integer"
        
        return True, None
    
    @classmethod
    def save_default_config(cls, config_file: str = "config.yaml") -> bool:
        default_config = {
            'encryption': {
                'iterations': cls.ENCRYPTION_ITERATIONS,
                'salt_size': cls.SALT_SIZE,
                'key_length': cls.KEY_LENGTH,
            },
            'network': {
                'timeout': cls.SCANNER_TIMEOUT,
                'max_workers': cls.SCANNER_MAX_WORKERS,
                'dns_cache_ttl': cls.DNS_CACHE_TTL,
            },
            'file_processing': {
                'chunk_size': cls.CHUNK_SIZE,
                'streaming_threshold': cls.STREAMING_THRESHOLD,
            },
            'ui': {
                'colors_enabled': cls.COLORS_ENABLED,
                'show_progress': cls.SHOW_PROGRESS,
                'progress_bar_style': cls.PROGRESS_BAR_STYLE,
            },
            'logging': {
                'level': cls.LOG_LEVEL,
                'file': cls.LOG_FILE,
                'max_size_mb': cls.LOG_MAX_SIZE_MB,
            },
        }
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                if config_file.endswith('.json'):
                    json.dump(default_config, f, indent=2, ensure_ascii=False)
                elif config_file.endswith(('.yaml', '.yml')):
                    if YAML_AVAILABLE:
                        yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
                    else:
                        json.dump(default_config, f, indent=2, ensure_ascii=False)
                else:
                    return False
            return True
        except Exception:
            return False


_config_paths = ["config.yaml", "config.yml", "config.json"]
for path in _config_paths:
    if os.path.exists(path):
        Config.load_config(path)
        break

