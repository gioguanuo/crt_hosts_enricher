#!/usr/bin/env python3
"""
CRT Hosts Enricher - Configuration Management
Handles loading configuration from files and environment variables
"""

import os
import json
import configparser
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for CRT Hosts Enricher"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file
        self.config = self._load_default_config()
        
        # Load configuration from various sources (in order of priority)
        self._load_from_file()
        self._load_from_environment()
        
        # Validate configuration
        self._validate_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration values"""
        return {
            # API Configuration
            'ipinfo_token': '',
            'user_agent': 'crt-hosts-enricher/2.1 (+https://github.com/yourusername/crt-hosts-enricher)',
            
            # Rate Limiting
            'default_sleep': 0.5,
            'http_timeout': 60.0,
            'http_retries': 3,
            'retry_backoff_base': 1.7,
            
            # Logging
            'log_level': 'INFO',
            'log_file_pattern': 'logs/crt-enricher-{date}.log',
            'colored_output': True,
            'max_log_size': 10 * 1024 * 1024,  # 10MB
            'log_backup_count': 5,
            
            # Output
            'output_dir': 'results',
            'csv_delimiter': ',',
            'csv_quote_char': '"',
            'include_header': True,
            
            # Filtering
            'only_resolvable': False,
            'public_only': False,
            'skip_patterns': [
                r'^\*\.',
                r'\*',
                r'^localhost$',
                r'^127\.',
                r'^192\.168\.',
                r'^10\.',
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
            ],
            
            # API Endpoints
            'crt_sh_url': 'https://crt.sh/',
            'crt_sh_timeout': 120.0,
            'ipinfo_url': 'https://api.ipinfo.io',
            'ipinfo_timeout': 30.0,
            'bgpview_url': 'https://api.bgpview.io',
            'bgpview_timeout': 30.0,
            
            # Advanced
            'max_hostnames': None,
            'progress_interval': 50,
            'batch_size': 10,
            'cache_enabled': True,
            'cache_dir': '.cache',
            'cache_expiration': 86400,  # 24 hours
            
            # Error Handling
            'continue_on_error': True,
            'max_consecutive_failures': 10,
            'retry_http_codes': [429, 500, 502, 503, 504]
        }
    
    def _load_from_file(self):
        """Load configuration from file"""
        config_paths = []
        
        # Use specified config file
        if self.config_file:
            config_paths.append(self.config_file)
        
        # Default config file locations
        config_paths.extend([
            'config.json',
            'config.ini',
            'crt-enricher.json',
            'crt-enricher.ini',
            os.path.expanduser('~/.crt-enricher.json'),
            os.path.expanduser('~/.crt-enricher.ini'),
            '/etc/crt-enricher.json',
            '/etc/crt-enricher.ini'
        ])
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                self._load_config_file(config_path)
                break
    
    def _load_config_file(self, config_path: str):
        """Load configuration from specific file"""
        try:
            config_path = Path(config_path)
            
            if config_path.suffix.lower() == '.json':
                self._load_json_config(config_path)
            elif config_path.suffix.lower() in ['.ini', '.cfg']:
                self._load_ini_config(config_path)
            else:
                # Try to detect format by content
                with open(config_path, 'r') as f:
                    content = f.read().strip()
                    if content.startswith('{'):
                        self._load_json_config(config_path)
                    else:
                        self._load_ini_config(config_path)
                        
            print(f"[CONFIG] Loaded configuration from: {config_path}")
            
        except Exception as e:
            print(f"[WARNING] Failed to load config from {config_path}: {e}")
    
    def _load_json_config(self, config_path: Path):
        """Load JSON configuration file"""
        with open(config_path, 'r') as f:
            file_config = json.load(f)
            self.config.update(file_config)
    
    def _load_ini_config(self, config_path: Path):
        """Load INI configuration file"""
        parser = configparser.ConfigParser()
        parser.read(config_path)
        
        # Convert INI to dict
        for section_name in parser.sections():
            section = parser[section_name]
            for key, value in section.items():
                # Convert string values to appropriate types
                self.config[key] = self._convert_value(value)
    
    def _convert_value(self, value: str) -> Any:
        """Convert string configuration value to appropriate type"""
        # Boolean values
        if value.lower() in ['true', 'yes', 'on', '1']:
            return True
        elif value.lower() in ['false', 'no', 'off', '0']:
            return False
        
        # Numeric values
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # JSON values (lists, dicts)
        if value.startswith(('[', '{')):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        
        # String value
        return value
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'CRT_IPINFO_TOKEN': 'ipinfo_token',
            'CRT_USER_AGENT': 'user_agent',
            'CRT_LOG_LEVEL': 'log_level',
            'CRT_HTTP_TIMEOUT': 'http_timeout',
            'CRT_HTTP_RETRIES': 'http_retries',
            'CRT_SLEEP': 'default_sleep',
            'CRT_OUTPUT_DIR': 'output_dir',
            'CRT_CACHE_DIR': 'cache_dir',
            'CRT_MAX_HOSTNAMES': 'max_hostnames'
        }
        
        for env_var, config_key in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                self.config[config_key] = self._convert_value(env_value)
                print(f"[CONFIG] Loaded {config_key} from environment")
    
    def _validate_config(self):
        """Validate configuration values"""
        errors = []
        
        # Required fields
        if not self.config.get('ipinfo_token'):
            errors.append("IPinfo token is required (set in config file or CRT_IPINFO_TOKEN env var)")
        
        # Numeric validations
        if self.config['default_sleep'] < 0:
            errors.append("default_sleep cannot be negative")
        
        if self.config['http_timeout'] <= 0:
            errors.append("http_timeout must be positive")
        
        if self.config['http_retries'] < 0:
            errors.append("http_retries cannot be negative")
        
        # Create directories
        for dir_key in ['output_dir', 'cache_dir']:
            dir_path = Path(self.config[dir_key])
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Log file directory
        log_file = self.config['log_file_pattern'].replace('{date}', '20240101')
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        if errors:
            print("[ERROR] Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            raise ValueError("Invalid configuration")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values"""
        return self.config.copy()
    
    def save_to_file(self, file_path: str, format: str = 'json'):
        """Save current configuration to file"""
        file_path = Path(file_path)
        
        if format.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=2, default=str)
        elif format.lower() == 'ini':
            parser = configparser.ConfigParser()
            parser['DEFAULT'] = {k: str(v) for k, v in self.config.items()}
            with open(file_path, 'w') as f:
                parser.write(f)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"[CONFIG] Configuration saved to: {file_path}")
    
    def print_config(self):
        """Print current configuration"""
        print("\n=== Current Configuration ===")
        for key, value in sorted(self.config.items()):
            # Mask sensitive values
            if 'token' in key.lower() or 'password' in key.lower():
                display_value = '*' * 8 if value else 'Not set'
            else:
                display_value = value
            print(f"  {key}: {display_value}")
        print()


def create_example_config_files():
    """Create example configuration files"""
    
    # JSON example
    json_config = {
        "ipinfo_token": "your_ipinfo_token_here",
        "user_agent": "crt-hosts-enricher/2.1 (+https://github.com/yourusername/crt-hosts-enricher)",
        "default_sleep": 0.5,
        "http_timeout": 60.0,
        "http_retries": 3,
        "log_level": "INFO",
        "output_dir": "results",
        "only_resolvable": False,
        "public_only": False,
        "colored_output": True,
        "cache_enabled": True
    }
    
    with open('config.example.json', 'w') as f:
        json.dump(json_config, f, indent=2)
    
    # INI example
    ini_content = """[DEFAULT]
# IPinfo.io API token (required)
# Get your free token at: https://ipinfo.io/signup
ipinfo_token = your_ipinfo_token_here

# User agent for HTTP requests
user_agent = crt-hosts-enricher/2.1 (+https://github.com/yourusername/crt-hosts-enricher)

# Rate limiting
default_sleep = 0.5
http_timeout = 60.0
http_retries = 3

# Logging
log_level = INFO
colored_output = true

# Output
output_dir = results
only_resolvable = false
public_only = false

# Caching
cache_enabled = true
cache_dir = .cache
"""
    
    with open('config.example.ini', 'w') as f:
        f.write(ini_content)
    
    print("Created example configuration files:")
    print("  - config.example.json")
    print("  - config.example.ini")
    print("\nCopy one to 'config.json' or 'config.ini' and edit with your settings.")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--create-examples':
        create_example_config_files()
    else:
        # Test configuration loading
        try:
            config = Config()
            config.print_config()
        except Exception as e:
            print(f"Configuration error: {e}")
            print("\nCreate a config file first:")
            print("python config.py --create-examples")