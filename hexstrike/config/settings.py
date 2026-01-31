"""
Configuration Management for HexStrike AI

Centralized configuration with:
- YAML file support
- Environment variable overrides
- Validation
- Hot reloading
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, TypeVar, Type
from pathlib import Path

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheConfig:
    """Cache configuration."""
    max_size: int = 1000
    ttl: int = 3600  # seconds
    cleanup_interval: int = 300


@dataclass
class ExecutionConfig:
    """Execution configuration."""
    command_timeout: int = 300
    max_retries: int = 3
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0
    parallel_max_threads: int = 10
    parallel_max_processes: int = 4


@dataclass
class NetworkConfig:
    """Network configuration."""
    request_timeout: int = 30
    connect_timeout: int = 10
    max_connections: int = 100
    verify_ssl: bool = True
    proxy: Optional[str] = None


@dataclass
class ToolConfig:
    """Tool-specific configuration."""
    nmap_timeout: int = 600
    sqlmap_timeout: int = 1800
    nikto_timeout: int = 1200
    gobuster_timeout: int = 600
    nuclei_timeout: int = 900
    hydra_timeout: int = 1800
    hashcat_timeout: int = 7200


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "127.0.0.1"
    port: int = 8888
    debug: bool = False
    workers: int = 4
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class Settings:
    """
    Main settings container.

    Aggregates all configuration sections.
    """
    cache: CacheConfig = field(default_factory=CacheConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    # Custom settings
    custom: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Settings":
        """Create settings from dictionary."""
        settings = cls()

        if "cache" in data:
            settings.cache = CacheConfig(**data["cache"])
        if "execution" in data:
            settings.execution = ExecutionConfig(**data["execution"])
        if "network" in data:
            settings.network = NetworkConfig(**data["network"])
        if "tools" in data:
            settings.tools = ToolConfig(**data["tools"])
        if "logging" in data:
            settings.logging = LoggingConfig(**data["logging"])
        if "server" in data:
            settings.server = ServerConfig(**data["server"])
        if "custom" in data:
            settings.custom = data["custom"]

        return settings

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return {
            "cache": {
                "max_size": self.cache.max_size,
                "ttl": self.cache.ttl,
                "cleanup_interval": self.cache.cleanup_interval,
            },
            "execution": {
                "command_timeout": self.execution.command_timeout,
                "max_retries": self.execution.max_retries,
                "retry_base_delay": self.execution.retry_base_delay,
                "retry_max_delay": self.execution.retry_max_delay,
                "parallel_max_threads": self.execution.parallel_max_threads,
                "parallel_max_processes": self.execution.parallel_max_processes,
            },
            "network": {
                "request_timeout": self.network.request_timeout,
                "connect_timeout": self.network.connect_timeout,
                "max_connections": self.network.max_connections,
                "verify_ssl": self.network.verify_ssl,
                "proxy": self.network.proxy,
            },
            "tools": {
                "nmap_timeout": self.tools.nmap_timeout,
                "sqlmap_timeout": self.tools.sqlmap_timeout,
                "nikto_timeout": self.tools.nikto_timeout,
                "gobuster_timeout": self.tools.gobuster_timeout,
                "nuclei_timeout": self.tools.nuclei_timeout,
                "hydra_timeout": self.tools.hydra_timeout,
                "hashcat_timeout": self.tools.hashcat_timeout,
            },
            "logging": {
                "level": self.logging.level,
                "format": self.logging.format,
                "file": self.logging.file,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count,
            },
            "server": {
                "host": self.server.host,
                "port": self.server.port,
                "debug": self.server.debug,
                "workers": self.server.workers,
                "cors_origins": self.server.cors_origins,
            },
            "custom": self.custom,
        }


class SettingsManager:
    """
    Settings manager with file loading and environment overrides.
    """

    ENV_PREFIX = "HEXSTRIKE_"

    # Environment variable mappings
    ENV_MAPPINGS = {
        "HOST": ("server", "host"),
        "PORT": ("server", "port"),
        "DEBUG": ("server", "debug"),
        "CACHE_SIZE": ("cache", "max_size"),
        "CACHE_TTL": ("cache", "ttl"),
        "COMMAND_TIMEOUT": ("execution", "command_timeout"),
        "MAX_RETRIES": ("execution", "max_retries"),
        "REQUEST_TIMEOUT": ("network", "request_timeout"),
        "LOG_LEVEL": ("logging", "level"),
        "LOG_FILE": ("logging", "file"),
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize settings manager.

        Args:
            config_path: Path to configuration file
        """
        self._settings: Optional[Settings] = None
        self._config_path = config_path
        self._loaded_from: Optional[str] = None

    def load(self, config_path: Optional[str] = None) -> Settings:
        """
        Load settings from file and environment.

        Args:
            config_path: Path to configuration file

        Returns:
            Loaded Settings object
        """
        path = config_path or self._config_path

        # Start with defaults
        settings_dict: Dict[str, Any] = {}

        # Load from file if provided
        if path:
            file_settings = self._load_from_file(path)
            if file_settings:
                settings_dict = file_settings
                self._loaded_from = path

        # Apply environment overrides
        self._apply_env_overrides(settings_dict)

        # Create settings object
        self._settings = Settings.from_dict(settings_dict)

        return self._settings

    def _load_from_file(self, path: str) -> Optional[Dict[str, Any]]:
        """Load settings from YAML or JSON file."""
        path_obj = Path(path)

        if not path_obj.exists():
            logger.warning(f"Config file not found: {path}")
            return None

        try:
            content = path_obj.read_text()

            if path_obj.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    return yaml.safe_load(content)
                except ImportError:
                    logger.warning("PyYAML not installed, trying JSON parser")
                    import json
                    return json.loads(content)

            elif path_obj.suffix == ".json":
                import json
                return json.loads(content)

            else:
                logger.warning(f"Unknown config format: {path_obj.suffix}")
                return None

        except Exception as e:
            logger.error(f"Failed to load config from {path}: {e}")
            return None

    def _apply_env_overrides(self, settings_dict: Dict[str, Any]) -> None:
        """Apply environment variable overrides."""
        for env_suffix, (section, key) in self.ENV_MAPPINGS.items():
            env_var = f"{self.ENV_PREFIX}{env_suffix}"
            value = os.environ.get(env_var)

            if value is not None:
                # Ensure section exists
                if section not in settings_dict:
                    settings_dict[section] = {}

                # Convert value to appropriate type
                converted = self._convert_env_value(value, section, key)
                settings_dict[section][key] = converted

                logger.debug(f"Applied env override: {env_var}={converted}")

    def _convert_env_value(self, value: str, section: str, key: str) -> Any:
        """Convert environment variable string to appropriate type."""
        # Boolean conversion
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        # Integer conversion for known int fields
        int_fields = {
            ("server", "port"),
            ("cache", "max_size"),
            ("cache", "ttl"),
            ("execution", "command_timeout"),
            ("execution", "max_retries"),
            ("network", "request_timeout"),
        }

        if (section, key) in int_fields:
            try:
                return int(value)
            except ValueError:
                pass

        # Float conversion for known float fields
        float_fields = {
            ("execution", "retry_base_delay"),
            ("execution", "retry_max_delay"),
        }

        if (section, key) in float_fields:
            try:
                return float(value)
            except ValueError:
                pass

        return value

    @property
    def settings(self) -> Settings:
        """Get current settings, loading if necessary."""
        if self._settings is None:
            self._settings = self.load()
        return self._settings

    def reload(self) -> Settings:
        """Reload settings from source."""
        return self.load(self._config_path)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value by dot-notation key.

        Args:
            key: Setting key (e.g., "cache.max_size")
            default: Default value if not found

        Returns:
            Setting value
        """
        parts = key.split(".")
        obj: Any = self.settings

        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return default

        return obj

    def set(self, key: str, value: Any) -> None:
        """
        Set a setting value by dot-notation key.

        Args:
            key: Setting key (e.g., "cache.max_size")
            value: Value to set
        """
        parts = key.split(".")
        obj: Any = self.settings

        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                raise KeyError(f"Invalid setting path: {key}")

        final_key = parts[-1]
        if hasattr(obj, final_key):
            setattr(obj, final_key, value)
        elif isinstance(obj, dict):
            obj[final_key] = value
        else:
            raise KeyError(f"Invalid setting path: {key}")


# Global settings instance
_settings_manager: Optional[SettingsManager] = None


def get_settings_manager() -> SettingsManager:
    """Get the global settings manager."""
    global _settings_manager
    if _settings_manager is None:
        _settings_manager = SettingsManager()
    return _settings_manager


def get_settings() -> Settings:
    """Get the current settings."""
    return get_settings_manager().settings


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Load settings from a configuration file."""
    global _settings_manager
    _settings_manager = SettingsManager(config_path)
    return _settings_manager.load()


def get_config(key: str, default: Any = None) -> Any:
    """Get a configuration value by key."""
    return get_settings_manager().get(key, default)
