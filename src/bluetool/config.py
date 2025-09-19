"""Configuration management for Blue Team Toolkit."""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class CaptureConfig:
    """Packet capture configuration."""

    bpf: str = "tcp or udp or icmp"
    snaplen: int = 65535
    promisc: bool = True
    offline: bool = False


@dataclass
class PortscanConfig:
    """Port scan detection configuration."""

    window_sec: int = 5
    unique_ports_threshold: int = 20


@dataclass
class BruteforceConfig:
    """Brute force detection configuration."""

    services: list[str] = None
    window_sec: int = 60
    fail_threshold: int = 10

    def __post_init__(self):
        if self.services is None:
            self.services = ["ssh", "http", "https"]


@dataclass
class DosConfig:
    """DoS detection configuration."""

    window_sec: int = 5
    packet_threshold: int = 500


@dataclass
class DetectionConfig:
    """Detection rules configuration."""

    portscan: PortscanConfig = None
    bruteforce: BruteforceConfig = None
    dos: DosConfig = None

    def __post_init__(self):
        if self.portscan is None:
            self.portscan = PortscanConfig()
        if self.bruteforce is None:
            self.bruteforce = BruteforceConfig()
        if self.dos is None:
            self.dos = DosConfig()


@dataclass
class TelegramConfig:
    """Telegram alert configuration."""

    bot_token: str = ""
    chat_id: str = ""


@dataclass
class AlertsConfig:
    """Alerting configuration."""

    slack_webhook: str = ""
    telegram: TelegramConfig = None

    def __post_init__(self):
        if self.telegram is None:
            self.telegram = TelegramConfig()


@dataclass
class PersistenceConfig:
    """Data persistence configuration."""

    db_path: str = "bluetool.db"


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "info"
    console: bool = True


@dataclass
class Config:
    """Main configuration class."""

    version: int = 1
    interface: str = "auto"
    capture: CaptureConfig = None
    detection: DetectionConfig = None
    alerts: AlertsConfig = None
    persistence: PersistenceConfig = None
    logging: LoggingConfig = None

    def __post_init__(self):
        if self.capture is None:
            self.capture = CaptureConfig()
        if self.detection is None:
            self.detection = DetectionConfig()
        if self.alerts is None:
            self.alerts = AlertsConfig()
        if self.persistence is None:
            self.persistence = PersistenceConfig()
        if self.logging is None:
            self.logging = LoggingConfig()


def create_default_config() -> dict[str, Any]:
    """Create default configuration dictionary."""
    return {
        "version": 1,
        "interface": "auto",
        "capture": {
            "bpf": "tcp or udp or icmp",
            "snaplen": 65535,
            "promisc": True,
            "offline": False,
        },
        "detection": {
            "portscan": {
                "window_sec": 5,
                "unique_ports_threshold": 20,
            },
            "bruteforce": {
                "services": ["ssh", "http", "https"],
                "window_sec": 60,
                "fail_threshold": 10,
            },
            "dos": {
                "window_sec": 5,
                "packet_threshold": 500,
            },
        },
        "alerts": {
            "slack_webhook": "",
            "telegram": {
                "bot_token": "",
                "chat_id": "",
            },
        },
        "persistence": {
            "db_path": "bluetool.db",
        },
        "logging": {
            "level": "info",
            "console": True,
        },
    }


def _dict_to_dataclass(cls, data: dict[str, Any]) -> Any:
    """Convert dictionary to dataclass instance recursively."""
    if not hasattr(cls, "__dataclass_fields__"):
        return data

    kwargs = {}
    for field_name, field_def in cls.__dataclass_fields__.items():
        if field_name in data:
            field_type = field_def.type
            field_value = data[field_name]

            # Handle Optional types
            if hasattr(field_type, "__origin__") and field_type.__origin__ is type(
                None
            ):
                field_type = field_type.__args__[0]

            # Handle nested dataclasses
            if hasattr(field_type, "__dataclass_fields__"):
                kwargs[field_name] = _dict_to_dataclass(field_type, field_value)
            else:
                kwargs[field_name] = field_value

    return cls(**kwargs)


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from YAML file.

    Args:
        config_path: Path to configuration file. If None, uses default config.

    Returns:
        Config: Loaded configuration object.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If config file is invalid YAML.
        ValueError: If config validation fails.
    """
    if config_path is None:
        return Config()

    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Invalid YAML in config file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Configuration must be a YAML dictionary")

    # Validate version
    version = data.get("version", 1)
    if version != 1:
        raise ValueError(f"Unsupported configuration version: {version}")

    try:
        return _dict_to_dataclass(Config, data)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Invalid configuration: {e}") from e


def save_config(config: Config, config_path: str) -> None:
    """Save configuration to YAML file.

    Args:
        config: Configuration object to save.
        config_path: Path to save configuration file.
    """
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)

    # Convert dataclass to dict
    def dataclass_to_dict(obj):
        if hasattr(obj, "__dataclass_fields__"):
            return {
                field_name: dataclass_to_dict(getattr(obj, field_name))
                for field_name in obj.__dataclass_fields__
            }
        return obj

    data = dataclass_to_dict(config)

    with open(config_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, indent=2)


def validate_config(config: Config) -> list[str]:
    """Validate configuration and return list of errors.

    Args:
        config: Configuration to validate.

    Returns:
        List of validation error messages.
    """
    errors = []

    # Validate version
    if config.version != 1:
        errors.append(f"Unsupported version: {config.version}")

    # Validate interface
    if not config.interface:
        errors.append("Interface cannot be empty")

    # Validate detection thresholds
    if config.detection.portscan.unique_ports_threshold <= 0:
        errors.append("Port scan threshold must be positive")

    if config.detection.bruteforce.fail_threshold <= 0:
        errors.append("Brute force threshold must be positive")

    if config.detection.dos.packet_threshold <= 0:
        errors.append("DoS packet threshold must be positive")

    # Validate time windows
    if config.detection.portscan.window_sec <= 0:
        errors.append("Port scan window must be positive")

    if config.detection.bruteforce.window_sec <= 0:
        errors.append("Brute force window must be positive")

    if config.detection.dos.window_sec <= 0:
        errors.append("DoS window must be positive")

    # Validate services
    valid_services = {"ssh", "http", "https", "ftp", "telnet", "smtp", "pop3", "imap"}
    for service in config.detection.bruteforce.services:
        if service not in valid_services:
            errors.append(f"Unknown service: {service}")

    # Validate logging level
    valid_levels = {"debug", "info", "warning", "error", "critical"}
    if config.logging.level.lower() not in valid_levels:
        errors.append(f"Invalid logging level: {config.logging.level}")

    return errors


def setup_logging(config: LoggingConfig) -> None:
    """Setup logging based on configuration.

    Args:
        config: Logging configuration.
    """
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    level = level_map.get(config.level.lower(), logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Suppress noisy third-party loggers
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
